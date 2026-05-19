/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.debug;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCConfiguration;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCConfigurationExtractor;
import org.wso2.carbon.identity.application.common.model.AccountLookupAttributeMappingConfig;
import org.wso2.carbon.identity.debug.framework.store.DebugSessionStore;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.OAuth2TokenClient;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.TokenResponse;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.util.DebugDiagnosticsUtil;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugProcessor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OIDC-specific implementation of IdpDebugProcessor.
 * Handles the OIDC authorization code callback: validates the callback parameters, exchanges the code for tokens,
 * extracts and maps claims, evaluates account linking, and persists the debug result.
 */
public class OIDCDebugProcessor extends IdpDebugProcessor {

    private static final Log LOG = LogFactory.getLog(OIDCDebugProcessor.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * Validates OIDC callback parameters: checks for authorization code or error response and validates the
     * state parameter against the debug session to prevent CSRF.
     *
     * @param request            HttpServletRequest containing callback parameters.
     * @param context            DebugContext for the current debug session.
     * @param response           HttpServletResponse.
     * @param state              OAuth state parameter from the callback.
     * @param resourceIdentifier IdP resource ID.
     * @return true if callback is valid, false otherwise.
     * @throws IOException If response cannot be sent.
     */
    @Override
    protected boolean validateCallback(HttpServletRequest request, DebugContext context,
            HttpServletResponse response, String state, String resourceIdentifier) throws IOException {

        String code = request.getParameter(OIDCDebugConstants.OIDC_CODE_PARAM);
        String error = request.getParameter(OIDCDebugConstants.OIDC_ERROR_PARAM);
        String errorDescription = request.getParameter(OIDCDebugConstants.OIDC_ERROR_DESCRIPTION_PARAM);

        // Store IdP ID in context for fallback resolution during token exchange.
        if (StringUtils.isNotEmpty(resourceIdentifier)) {
            context.setProperty(OIDCDebugConstants.DEBUG_IDP_NAME, resourceIdentifier);
        }

        if (error != null) {
            LOG.error("OIDC error from IdP: " + error + " - " + errorDescription);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, error + ": " + errorDescription);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse(error, errorDescription, state, context);
            return false;
        }

        if (code == null || code.trim().isEmpty()) {
            LOG.error("Authorization code missing in OIDC callback");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Authorization code not received");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("NO_CODE",
                    "Authorization code not received from IdP", state, context);
            return false;
        }

        if (state == null || state.trim().isEmpty()) {
            LOG.error("State parameter missing in OIDC callback");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR,
                    "State parameter missing - possible CSRF attack");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("NO_STATE",
                    "State parameter missing - possible CSRF attack", state, context);
            return false;
        }

        // Validate callback state against the debug session ID to prevent CSRF.
        String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);
        if (debugId == null || !state.trim().equals(debugId)) {
            LOG.error("State parameter mismatch - CSRF attack detected");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR,
                    "State validation failed - possible CSRF attack");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("STATE_MISMATCH",
                    "State validation failed - possible CSRF attack", state, context);
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("OIDC callback validation passed for state: " + state);
        }

        return true;
    }

    /**
     * Exchanges the OIDC authorization code for tokens (access token + ID token).
     * Resolves IdP configuration, performs the token exchange via {@link OAuth2TokenClient},
     * and stores tokens in context. Errors are recorded as diagnostics and cached as debug results.
     *
     * @param request            HttpServletRequest.
     * @param context            DebugContext.
     * @param response           HttpServletResponse.
     * @param state              State parameter.
     * @param resourceIdentifier IdP resource ID.
     * @return true if token exchange succeeds, false otherwise.
     * @throws IOException If response cannot be sent.
     */
    @Override
    protected boolean processAuthentication(HttpServletRequest request, DebugContext context,
            HttpServletResponse response, String state, String resourceIdentifier) throws IOException {

        String code = request.getParameter(OIDCDebugConstants.OIDC_CODE_PARAM);
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_STARTED, "Starting OIDC token exchange.");

        try {
            if (!validateAndExtractPrerequisites(code, state, context)) {
                LOG.error("Token exchange failed: Prerequisites validation failed");
                context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
                return false;
            }

            OIDCConfiguration config = extractOIDCConfiguration(context, request);

            if (!config.isValid()) {
                LOG.error("Token exchange failed: OIDC configuration is invalid");
                handleConfigurationError(config, state, context);
                return false;
            }

            return performTokenExchange(code, config, state, context);

        } catch (Exception e) {
            LOG.error("Exception during OIDC token exchange: " + e.getMessage(), e);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_FAILED, "OIDC token exchange failed with an exception.",
                    buildErrorDetails("TOKEN_EXCHANGE_ERROR", e.getMessage()));
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Token exchange error: " + e.getMessage());
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("TOKEN_EXCHANGE_ERROR",
                    "Token exchange error: " + e.getMessage(), state, context);
            return false;
        }
    }

    private boolean validateAndExtractPrerequisites(String code, String state, DebugContext context) {

        IdentityProvider idp = resolveIdentityProvider(context, state);

        if (idp == null) {
            LOG.error("IdP configuration not found in context");
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_FAILED, "Identity Provider configuration was not found.");
            buildAndCacheTokenExchangeErrorResponse("IDP_CONFIG_MISSING",
                    "Identity Provider configuration not found", state, context);
            return false;
        }

        if (code == null || code.trim().isEmpty()) {
            LOG.error("Authorization code missing in OIDC callback");
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_FAILED, "Authorization code is missing for token exchange.");
            buildAndCacheTokenExchangeErrorResponse("NO_CODE",
                    "Authorization code not received from IdP", state, context);
            return false;
        }

        context.setProperty(OIDCDebugConstants.DEBUG_IDP_NAME, idp.getIdentityProviderName());
        context.setProperty(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID, idp.getResourceId());
        context.setProperty(OIDCDebugConstants.IDP_CONFIG, idp);
        return true;
    }

    /**
     * Resolves the IdP from cached context properties when IDP_CONFIG is not directly available.
     * Tries resource ID first, then falls back to name lookup — both may be stored from the initial request.
     */
    private IdentityProvider resolveIdpFromContext(DebugContext context, String state) {

        try {
            String tenantDomain = IdentityTenantUtil.resolveTenantDomain();

            String resourceId = (String) context.getProperty(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID);
            String idpName = (String) context.getProperty(OIDCDebugConstants.DEBUG_IDP_NAME);
            if (StringUtils.isEmpty(resourceId) && StringUtils.isEmpty(idpName)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("IdP identifier not found in context for state: " + state);
                }
                return null;
            }

            IdentityProviderManager idpManager = IdentityProviderManager.getInstance();
            IdentityProvider idp = null;
            if (StringUtils.isNotEmpty(resourceId)) {
                idp = idpManager.getIdPByResourceId(resourceId, tenantDomain, true);
            }
            if (idp == null && StringUtils.isNotEmpty(idpName)) {
                idp = idpManager.getIdPByName(idpName, tenantDomain, true);
            }

            if (idp != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Resolved IdP from context cache for state: " + state + ", IdP: "
                            + idp.getIdentityProviderName());
                }
                return idp;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not resolve IdP by name: " + idpName);
            }
            return null;

        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error resolving IdP from context: " + e.getMessage(), e);
            }
            return null;
        }
    }

    /**
     * Resolves the IdP for this debug session using a three-step strategy:
     * 1. Direct IDP_CONFIG in context (fastest path, set by validateAndExtractPrerequisites).
     * 2. Restore context from session store using state, then re-check IDP_CONFIG.
     * 3. Re-resolve from stored resource ID or name via IdentityProviderManager.
     */
    private IdentityProvider resolveIdentityProvider(DebugContext context, String state) {

        Object cachedIdp = context.getProperty(OIDCDebugConstants.IDP_CONFIG);
        if (cachedIdp instanceof IdentityProvider) {
            return (IdentityProvider) cachedIdp;
        }

        if (state != null) {
            restoreContextFromSessionCache(state, context);
            cachedIdp = context.getProperty(OIDCDebugConstants.IDP_CONFIG);
            if (cachedIdp instanceof IdentityProvider) {
                return (IdentityProvider) cachedIdp;
            }
        }

        IdentityProvider resolvedIdp = resolveIdpFromContext(context, state);
        if (resolvedIdp != null) {
            context.setProperty(OIDCDebugConstants.IDP_CONFIG, resolvedIdp);
            context.setProperty(OIDCDebugConstants.DEBUG_IDP_NAME, resolvedIdp.getIdentityProviderName());
            context.setProperty(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID, resolvedIdp.getResourceId());
        }
        return resolvedIdp;
    }

    /**
     * Extracts OIDC configuration from context first (set by OIDCContextProvider), falling back to the IdP
     * authenticator config via OIDCConfigurationExtractor if any required value is missing.
     */
    private OIDCConfiguration extractOIDCConfiguration(DebugContext context, HttpServletRequest request) {

        OIDCConfiguration config = new OIDCConfiguration();
        IdentityProvider idp = resolveIdentityProvider(context, null);
        config.setIdpName(idp != null ? idp.getIdentityProviderName() : "Unknown");
        config.setCodeVerifier((String) context.getProperty(OIDCDebugConstants.DEBUG_CODE_VERIFIER));
        config.setTokenEndpoint((String) context.getProperty(OIDCDebugConstants.TOKEN_ENDPOINT));
        config.setClientId((String) context.getProperty(OIDCDebugConstants.CLIENT_ID));
        config.setClientSecret((String) context.getProperty(OIDCDebugConstants.CLIENT_SECRET));

        if (LOG.isDebugEnabled()) {
            LOG.debug("Token exchange - from context: tokenEndpoint=" +
                    (config.getTokenEndpoint() != null ? OIDCDebugConstants.STATUS_FOUND : "null") +
                    ", clientId=" + (config.getClientId() != null ? OIDCDebugConstants.STATUS_FOUND : "null") +
                    ", clientSecret="
                    + (config.getClientSecret() != null ? OIDCDebugConstants.STATUS_FOUND : "null"));
        }

        // Fall back to IdP authenticator config if any required value is still missing from context.
        if ((!config.hasRequiredEndpoints() || StringUtils.isBlank(config.getClientSecret()))
                && idp != null && idp.getFederatedAuthenticatorConfigs() != null) {
            extractFromIdPConfig(idp, config);
        }

        String callbackUrl = (String) context.getProperty(OIDCDebugConstants.REDIRECT_URI);
        if (StringUtils.isEmpty(callbackUrl)) {
            callbackUrl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        }
        config.setCallbackUrl(callbackUrl);

        return config;
    }

    /**
     * Populates OIDCConfiguration from IdP authenticator properties using OIDCConfigurationExtractor.
     * Stops iterating authenticator configs as soon as required endpoints are found.
     */
    private void extractFromIdPConfig(IdentityProvider idp, OIDCConfiguration config) {

        for (FederatedAuthenticatorConfig authConfig : idp.getFederatedAuthenticatorConfigs()) {
            if (authConfig == null) {
                continue;
            }
            Map<String, String> extracted = OIDCConfigurationExtractor.extractConfiguration(authConfig);
            if (extracted.isEmpty()) {
                continue;
            }
            if (StringUtils.isNotEmpty(extracted.get(OIDCDebugConstants.TOKEN_ENDPOINT))) {
                config.setTokenEndpoint(extracted.get(OIDCDebugConstants.TOKEN_ENDPOINT));
            }
            if (StringUtils.isNotEmpty(extracted.get(OIDCDebugConstants.CLIENT_ID))) {
                config.setClientId(extracted.get(OIDCDebugConstants.CLIENT_ID));
            }
            if (StringUtils.isNotEmpty(extracted.get(OIDCDebugConstants.CLIENT_SECRET))) {
                config.setClientSecret(extracted.get(OIDCDebugConstants.CLIENT_SECRET));
            }
            if (config.hasRequiredEndpoints()) {
                break;
            }
        }
    }

    private void handleConfigurationError(OIDCConfiguration config, String state, DebugContext context) {

        boolean missingEndpoint = config.getTokenEndpoint() == null || config.getTokenEndpoint().trim().isEmpty();
        boolean missingClientId = config.getClientId() == null || config.getClientId().trim().isEmpty();

        String errorCode;
        String errorDescription;

        if (missingEndpoint && missingClientId) {
            LOG.error("Token endpoint and client ID not found in context or IdP configuration");
            errorCode = "CONFIG_MISSING";
            errorDescription = "Token endpoint and client ID are not configured for the IdP.";
        } else if (missingEndpoint) {
            LOG.error("Token endpoint not found in context or IdP configuration");
            errorCode = "TOKEN_ENDPOINT_MISSING";
            errorDescription = "Token endpoint is not configured for the IdP.";
        } else {
            LOG.error("Client ID not found in context or IdP configuration");
            errorCode = "CLIENT_ID_MISSING";
            errorDescription = "Client ID is not configured for the IdP.";
        }

        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_FAILED, errorDescription);
        buildAndCacheTokenExchangeErrorResponse(errorCode, errorDescription, state, context);
    }

    private boolean performTokenExchange(String code, OIDCConfiguration config, String state,
            DebugContext context) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Starting token exchange with IdP: " + config.getIdpName() +
                    ", Token Endpoint: " + config.getTokenEndpoint());
        }
        TokenResponse tokenResponse = executeTokenExchange(code, config);

        if (tokenResponse.hasError()) {
            return handleTokenExchangeError(tokenResponse, config, state, context);
        }

        return handleTokenExchangeSuccess(tokenResponse, config, context);
    }

    private TokenResponse executeTokenExchange(String code, OIDCConfiguration config) {

        OAuth2TokenClient tokenClient = new OAuth2TokenClient();
        return tokenClient.exchangeCodeForTokens(
                code, config.getTokenEndpoint(), config.getClientId(), config.getClientSecret(),
                config.getCallbackUrl(), config.getCodeVerifier(), config.getIdpName());
    }

    private boolean handleTokenExchangeError(TokenResponse tokenResponse, OIDCConfiguration config,
            String state, DebugContext context) {

        String errorCode = tokenResponse.getErrorCode();
        String errorDesc = tokenResponse.getErrorDescription();

        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_FAILED, "Failed to obtain tokens",
                buildErrorDetails(errorCode, errorDesc));

        context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, errorDesc);
        context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
        buildAndCacheTokenExchangeErrorResponse(errorCode, errorDesc, state, context);

        return false;
    }

    private boolean handleTokenExchangeSuccess(TokenResponse tokenResponse, OIDCConfiguration config,
            DebugContext context) {

        storeTokensInContext(tokenResponse, config, context);
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_SUCCESS, "Token received successfully.");
        return true;
    }

    private void storeTokensInContext(TokenResponse tokenResponse, OIDCConfiguration config,
            DebugContext context) {

        context.setProperty(OIDCDebugConstants.ACCESS_TOKEN, tokenResponse.getAccessToken());
        String idToken = tokenResponse.getIdToken();
        if (idToken != null && !idToken.trim().isEmpty()) {
            context.setProperty(OIDCDebugConstants.ID_TOKEN, idToken);
        }
        String tokenType = tokenResponse.getTokenType();
        if (tokenType != null && !tokenType.trim().isEmpty()) {
            context.setProperty(OIDCDebugConstants.TOKEN_TYPE, tokenType);
        }
    }

    /**
     * Extracts user claims from the OIDC ID token.
     * Parses the JWT payload and validates the nonce claim against the value generated in the authorization request.
     *
     * @param context DebugContext containing the ID token and nonce.
     * @return Map of extracted claims, or empty map if extraction fails.
     */
    @Override
    protected Map<String, Object> extractDebugData(DebugContext context) {

        try {
            String idToken = (String) context.getProperty(OIDCDebugConstants.ID_TOKEN);
            if (idToken == null || idToken.trim().isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No ID token available for claim extraction");
                }
                DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                        OIDCDebugConstants.STATUS_FAILED, "ID token is not available for claim extraction.");
                return new HashMap<>();
            }

            Map<String, Object> claims = parseIdTokenClaims(idToken);

            if (!isValidNonceClaim(context, claims)) {
                DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                        OIDCDebugConstants.STATUS_FAILED,
                        "ID token nonce claim validation failed.",
                        buildErrorDetails("NONCE_VALIDATION_FAILED",
                                "ID token nonce claim is missing or does not match the original request nonce."));
                return new HashMap<>();
            }

            return returnExtractedClaims(claims, context);

        } catch (Exception e) {
            LOG.error("Error extracting user claims from OIDC tokens: " + e.getMessage(), e);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                    OIDCDebugConstants.STATUS_FAILED, "Error extracting claims from OIDC tokens.",
                    buildErrorDetails("CLAIM_EXTRACTION_ERROR", e.getMessage()));
            return new HashMap<>();
        }
    }

    private Map<String, Object> returnExtractedClaims(Map<String, Object> claims, DebugContext context) {

        if (!claims.isEmpty()) {
            context.setProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS, claims);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                    OIDCDebugConstants.STATUS_SUCCESS, "Claims extracted successfully from tokens.");
            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully extracted " + claims.size() + " claims from tokens: " + claims.keySet());
            }
            return claims;
        }

        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                OIDCDebugConstants.STATUS_FAILED, "No claims could be extracted from the OIDC tokens.");
        if (LOG.isDebugEnabled()) {
            LOG.debug("No claims extracted from ID token or UserInfo endpoint");
        }
        return new HashMap<>();
    }

    /**
     * Parses JWT ID token claims from the base64url-encoded payload (the middle part of the three-part JWT).
     *
     * @param idToken The JWT ID token string.
     * @return Map of claims from the token payload, or empty map if parsing fails.
     */
    private Map<String, Object> parseIdTokenClaims(String idToken) {

        if (StringUtils.isEmpty(idToken)) {
            return new HashMap<>();
        }
        try {
            String[] parts = idToken.split("\\.");
            if (parts.length != 3) {
                LOG.error("Invalid ID token format - expected 3 parts, got " + parts.length);
                return new HashMap<>();
            }

            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]),
                    java.nio.charset.StandardCharsets.UTF_8);
            return parseJsonToClaims(payload);

        } catch (Exception e) {
            LOG.error("Error parsing ID token claims: " + e.getMessage(), e);
            return new HashMap<>();
        }
    }

    /**
     * Validates the nonce claim in the ID token against the nonce stored in the debug context.
     * If no nonce was generated for this session (e.g. non-OIDC IdP), validation is skipped.
     */
    private boolean isValidNonceClaim(DebugContext context, Map<String, Object> claims) {

        String expectedNonce = (String) context.getProperty(OIDCDebugConstants.DEBUG_NONCE);
        if (StringUtils.isBlank(expectedNonce)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Expected nonce is not available in debug context. Skipping nonce validation.");
            }
            return true;
        }

        if (claims == null || claims.isEmpty()) {
            LOG.error("ID token claims are empty. Cannot validate nonce claim.");
            return false;
        }

        Object tokenNonceObj = claims.get(OIDCDebugConstants.CLAIM_NONCE);
        String tokenNonce = tokenNonceObj != null ? String.valueOf(tokenNonceObj) : null;
        if (StringUtils.isBlank(tokenNonce)) {
            LOG.error("ID token nonce claim is missing while request nonce is present.");
            return false;
        }

        if (!StringUtils.equals(expectedNonce, tokenNonce)) {
            LOG.error("Nonce mismatch detected between request context and ID token claims.");
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("ID token nonce claim validation succeeded.");
        }
        return true;
    }

    private Map<String, Object> parseJsonToClaims(String json) {

        if (StringUtils.isEmpty(json)) {
            return new HashMap<>();
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = OBJECT_MAPPER.readValue(json, Map.class);
            return claims != null ? claims : new HashMap<>();
        } catch (Exception e) {
            LOG.error("Error parsing JSON to claims: " + e.getMessage(), e);
            return new HashMap<>();
        }
    }

    /**
     * Validates that at least one user identifier claim (sub, user_id, userId, email) is present.
     *
     * @param claims             Extracted claims map.
     * @param context            DebugContext.
     * @param response           HttpServletResponse.
     * @param state              State parameter.
     * @param resourceIdentifier IdP resource ID.
     * @return true if a user identifier is present, false otherwise.
     * @throws IOException If response cannot be sent.
     */
    @Override
    protected boolean validateDebugData(Map<String, Object> claims, DebugContext context,
            HttpServletResponse response, String state, String resourceIdentifier) throws IOException {

        if (claims == null || claims.isEmpty()) {
            LOG.error("No claims extracted from OIDC tokens");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "No user claims extracted from IdP");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("NO_CLAIMS",
                    "No user claims available from IdP", state, context);
            return false;
        }

        boolean hasUserIdentifier = claims.containsKey(OIDCDebugConstants.CLAIM_SUB)
                || claims.containsKey(OIDCDebugConstants.CLAIM_USER_ID)
                || claims.containsKey(OIDCDebugConstants.CLAIM_USER_ID_ALT)
                || claims.containsKey(OIDCDebugConstants.CLAIM_EMAIL);
        if (!hasUserIdentifier) {
            LOG.error("Required user identifier claim not found in extracted claims");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "User identifier claim missing");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("NO_USER_IDENTIFIER",
                    "User identifier (sub/user_id/email) not found in claims", state, context);
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Claims extraction validation passed. Claims found: " + claims.keySet());
        }
        return true;
    }

    /**
     * Builds and caches the final debug result after successful authentication.
     * Includes claim mapping, account linking evaluation, step statuses, and diagnostics.
     * Persists to DebugSessionStore for API retrieval.
     *
     * @param context DebugContext containing all debug information.
     * @param state   State parameter for session identification.
     */
    @Override
    protected void buildAndCacheDebugResult(DebugContext context, String state) {

        try {
            Map<String, Object> debugResult = new HashMap<>();
            @SuppressWarnings("unchecked")
            Map<String, Object> rawClaims = (Map<String, Object>) context
                    .getProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS);
            Map<String, Object> normalizedClaims = normalizeIncomingClaimsForDebug(
                    rawClaims != null ? rawClaims : new HashMap<>());
            processClaimMappings(context, normalizedClaims, debugResult);
            evaluateAccountLinking(context, normalizedClaims);
            buildResultMetadata(debugResult, context);
            persistDebugResultToCache(state, context, debugResult);

        } catch (Exception e) {
            LOG.error("Error building and caching debug result: " + e.getMessage(), e);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Error caching debug result: " + e.getMessage());
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
        }
    }

    private void processClaimMappings(DebugContext context,
            Map<String, Object> incomingClaims, Map<String, Object> debugResult) {

        IdentityProvider idp = resolveIdentityProvider(context, null);
        Map<String, Map<String, String>> idpClaimMappings = extractIdPClaimMappings(idp);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Building mapped claims array from " + idpClaimMappings.size() +
                    " configured mappings. Incoming claims: " +
                    (incomingClaims.isEmpty() ? "none" : incomingClaims.keySet()));
        }

        List<Map<String, Object>> mappedClaimsArray = buildMappedClaimsArray(idpClaimMappings, incomingClaims);
        debugResult.put(OIDCDebugConstants.RESULT_MAPPED_CLAIMS, mappedClaimsArray);

        // SUCCESS if all mappings resolved, PARTIAL if any remain unmapped.
        String claimMappingStatus = determineClaimMappingStatus(mappedClaimsArray, idpClaimMappings);
        Map<String, Object> claimMappingDetails = buildClaimMappingDiagnosticDetails(claimMappingStatus,
                mappedClaimsArray);
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_MAPPING, claimMappingStatus,
                resolveClaimMappingStatusMessage(claimMappingStatus), claimMappingDetails);
    }

    private String resolveClaimMappingStatusMessage(String claimMappingStatus) {

        if (OIDCDebugConstants.STATUS_PARTIAL.equals(claimMappingStatus)) {
            return "Claim mappings are partially successful.";
        }
        return "Claim mapping processing successful.";
    }

    private Map<String, Object> buildClaimMappingDiagnosticDetails(String claimMappingStatus,
            List<Map<String, Object>> mappedClaimsArray) {

        Map<String, Object> details = new LinkedHashMap<>();
        if (!OIDCDebugConstants.STATUS_PARTIAL.equals(claimMappingStatus)) {
            return details;
        }

        Map<String, String> unmappedClaimPair = extractFirstUnmappedClaimPair(mappedClaimsArray);
        String unmappedIdpClaim = unmappedClaimPair.get("idpClaim");
        String unmappedLocalClaim = unmappedClaimPair.get("localClaim");
        if (StringUtils.isNotBlank(unmappedIdpClaim) || StringUtils.isNotBlank(unmappedLocalClaim)) {
            details.put(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION, buildUnmappedClaimErrorDescription(unmappedIdpClaim, unmappedLocalClaim));
        } else {
            details.put(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION,
                    "Couldn't map one or more IdP claims to local claims. Please review claim mappings.");
        }
        return details;
    }

    private Map<String, String> extractFirstUnmappedClaimPair(List<Map<String, Object>> mappedClaimsArray) {

        for (Map<String, Object> claim : mappedClaimsArray) {
            String status = (String) claim.get(OIDCDebugConstants.CLAIM_MAPPING_STATUS);
            if (!OIDCDebugConstants.CLAIM_STATUS_NOT_MAPPED.equals(status)) {
                continue;
            }

            Object idpClaim = claim.get(OIDCDebugConstants.CLAIM_MAPPING_IDP_CLAIM);
            Object localClaim = claim.get(OIDCDebugConstants.CLAIM_MAPPING_LOCAL_CLAIM);
            String idpClaimValue = idpClaim != null ? idpClaim.toString() : null;
            String localClaimValue = localClaim != null ? localClaim.toString() : null;

            Map<String, String> claimPair = new LinkedHashMap<>();
            claimPair.put("idpClaim", StringUtils.defaultString(idpClaimValue));
            claimPair.put("localClaim", StringUtils.defaultString(localClaimValue));
            return claimPair;
        }

        Map<String, String> emptyPair = new LinkedHashMap<>();
        emptyPair.put("idpClaim", "");
        emptyPair.put("localClaim", "");
        return emptyPair;
    }

    private String buildUnmappedClaimErrorDescription(String unmappedIdpClaim, String unmappedLocalClaim) {

        if (StringUtils.isNotBlank(unmappedIdpClaim) && StringUtils.isNotBlank(unmappedLocalClaim)) {
            return "The IdP claim '" + unmappedIdpClaim + "' is not mapped to the IS local claim '" +
                    unmappedLocalClaim + "'.";
        }
        if (StringUtils.isNotBlank(unmappedIdpClaim)) {
            return "The IdP claim '" + unmappedIdpClaim + "' is not mapped to an IS local claim.";
        }
        if (StringUtils.isNotBlank(unmappedLocalClaim)) {
            return "The IS local claim '" + unmappedLocalClaim + "' does not have a mapped IdP claim.";
        }
        return "Couldn't map one or more IdP claims to local claims. Please review claim mappings.";
    }

    /**
     * Determines claim mapping status: SUCCESS if all configured mappings resolved, PARTIAL if any are missing.
     * Returns SUCCESS immediately when there are no configured mappings (no mapping = nothing to fail).
     */
    private String determineClaimMappingStatus(List<Map<String, Object>> mappedClaimsArray,
            Map<String, Map<String, String>> idpClaimMappings) {

        if (idpClaimMappings.isEmpty()) {
            return OIDCDebugConstants.STATUS_SUCCESS;
        }

        int mappedCount = 0;
        int unmappedCount = 0;
        for (Map<String, Object> claim : mappedClaimsArray) {
            String status = (String) claim.get(OIDCDebugConstants.CLAIM_MAPPING_STATUS);
            if (OIDCDebugConstants.CLAIM_STATUS_SUCCESSFUL.equals(status)) {
                mappedCount++;
            } else if (OIDCDebugConstants.CLAIM_STATUS_NOT_MAPPED.equals(status)) {
                unmappedCount++;
            }
        }

        if (mappedCount > 0 && unmappedCount > 0) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Claim mapping status set to PARTIAL due to mixed mapped/unmapped claims.");
            }
            return OIDCDebugConstants.STATUS_PARTIAL;
        }

        if (mappedCount > 0) {
            return OIDCDebugConstants.STATUS_SUCCESS;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Claim mapping status set to PARTIAL because configured claims were not mapped.");
        }
        return OIDCDebugConstants.STATUS_PARTIAL;
    }

    /**
     * Builds the mapped claims array by cross-referencing configured IdP claim mappings against incoming claims.
     */
    private List<Map<String, Object>> buildMappedClaimsArray(
            Map<String, Map<String, String>> idpClaimMappings, Map<String, Object> incomingClaims) {

        List<Map<String, Object>> mappedClaimsArray = new ArrayList<>();
        for (Map.Entry<String, Map<String, String>> mapping : idpClaimMappings.entrySet()) {
            String remoteClaimUri = mapping.getValue().get(OIDCDebugConstants.CLAIM_MAPPING_REMOTE);
            String localClaimUri = mapping.getValue().get(OIDCDebugConstants.CLAIM_MAPPING_LOCAL);
            mappedClaimsArray.add(processConfiguredMapping(remoteClaimUri, localClaimUri, incomingClaims));
        }
        return mappedClaimsArray;
    }

    private Map<String, Object> processConfiguredMapping(String remoteClaimUri, String localClaimUri,
            Map<String, Object> incomingClaims) {

        Map<String, Object> claimEntry = new HashMap<>();
        claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_IDP_CLAIM, remoteClaimUri != null ? remoteClaimUri : "");
        claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_LOCAL_CLAIM, localClaimUri != null ? localClaimUri : "");

        Object claimValue = null;
        String claimStatus = OIDCDebugConstants.CLAIM_STATUS_NOT_MAPPED;

        if (remoteClaimUri != null && incomingClaims.containsKey(remoteClaimUri)) {
            claimValue = incomingClaims.get(remoteClaimUri);
            claimStatus = OIDCDebugConstants.CLAIM_STATUS_SUCCESSFUL;
            if (LOG.isDebugEnabled()) {
                LOG.debug("Mapped claim: " + remoteClaimUri + " -> " + localClaimUri);
            }
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("Claim not found in incoming claims: " + remoteClaimUri);
        }

        claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_VALUE,
                claimValue != null ? claimValue.toString() : null);
        claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_STATUS, claimStatus);

        return claimEntry;
    }

    private void buildResultMetadata(Map<String, Object> debugResult, DebugContext context) {

        String externalRedirectUrl = (String) context.getProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
        if (StringUtils.isNotBlank(externalRedirectUrl)) {
            debugResult.put(OIDCDebugConstants.RESULT_EXTERNAL_REDIRECT_URL, externalRedirectUrl);
        }

        String idToken = (String) context.getProperty(OIDCDebugConstants.ID_TOKEN);
        if (StringUtils.isNotBlank(idToken)) {
            debugResult.put(OIDCDebugConstants.ID_TOKEN, idToken);
        }

        debugResult.put(OIDCDebugConstants.DEBUG_DIAGNOSTICS,
                transformDiagnostics(DebugDiagnosticsUtil.getDiagnostics(context)));
    }

    private void persistDebugResultToCache(String state, DebugContext context, Map<String, Object> debugResult) {

        try {
            String debugResultJson = OBJECT_MAPPER.writeValueAsString(debugResult);
            context.setProperty(OIDCDebugConstants.DEBUG_RESULT_CACHE_KEY, debugResultJson);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, true);
            String contextId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);
            persistJsonToSessionStore(state, contextId, debugResultJson);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Debug result cached and persisted for state: " + state);
            }
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            LOG.error("Failed to serialize debug result to JSON: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts claim mappings from IdP configuration, converting ClaimMapping objects to a map keyed by remote URI.
     */
    private Map<String, Map<String, String>> extractIdPClaimMappings(IdentityProvider idp) {

        Map<String, Map<String, String>> mappings = new HashMap<>();

        if (idp == null || idp.getClaimConfig() == null || idp.getClaimConfig().getClaimMappings() == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No claim configuration found in IdP");
            }
            return mappings;
        }

        try {
            for (ClaimMapping claimMapping : idp.getClaimConfig().getClaimMappings()) {
                if (claimMapping == null || claimMapping.getRemoteClaim() == null
                        || claimMapping.getLocalClaim() == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Skipping invalid claim mapping with null remote or local claim");
                    }
                    continue;
                }

                String remoteClaimUri = claimMapping.getRemoteClaim().getClaimUri();
                String localClaimUri = claimMapping.getLocalClaim().getClaimUri();
                if (StringUtils.isBlank(remoteClaimUri)) {
                    LOG.warn("Skipping claim mapping with blank remote claim URI");
                    continue;
                }

                Map<String, String> mapping = new HashMap<>();
                mapping.put(OIDCDebugConstants.CLAIM_MAPPING_REMOTE, remoteClaimUri);
                mapping.put(OIDCDebugConstants.CLAIM_MAPPING_LOCAL, localClaimUri);
                mappings.put(remoteClaimUri, mapping);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Extracted claim mapping: " + remoteClaimUri + " -> " + localClaimUri);
                }
            }
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error extracting claim mappings from IdP: " + e.getMessage());
            }
        }

        return mappings;
    }

    private void buildAndCacheTokenExchangeErrorResponse(String errorCode, String errorDescription,
            String state, DebugContext context) {

        try {
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, Boolean.FALSE);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put(OIDCDebugConstants.DEBUG_RESULT_SUCCESS, false);
            errorResponse.put(OIDCDebugConstants.RESULT_ERROR_CODE, errorCode);
            errorResponse.put(OIDCDebugConstants.OIDC_ERROR_DESCRIPTION_PARAM, resolveErrorDescription(errorDescription));

            String externalRedirectUrl = (String) context.getProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
            if (externalRedirectUrl != null && !externalRedirectUrl.isEmpty()) {
                errorResponse.put(OIDCDebugConstants.RESULT_EXTERNAL_REDIRECT_URL, externalRedirectUrl);
            }

            errorResponse.put(OIDCDebugConstants.DEBUG_DIAGNOSTICS,
                    transformDiagnostics(DebugDiagnosticsUtil.getDiagnostics(context)));

            String errorResponseJson = OBJECT_MAPPER.writeValueAsString(errorResponse);
            context.setProperty(OIDCDebugConstants.DEBUG_RESULT_CACHE_KEY, errorResponseJson);

            String contextId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);
            // Persist under both state and contextId so the result is retrievable by either key.
            persistJsonToSessionStore(state, contextId, errorResponseJson);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Error response cached and persisted for state: " + state + " with error: " + errorCode);
            }

        } catch (Exception e) {
            LOG.error("Error building and caching error response: " + e.getMessage(), e);
        }
    }

    private String resolveErrorDescription(String errorDescription) {

        if (StringUtils.isNotBlank(errorDescription)) {
            return errorDescription;
        }
        return "An error occurred during OIDC debug processing.";
    }

    private String resolveAccountLinkingStatus(DebugContext context) {

        Object accountLinkingStatus = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS);
        if (accountLinkingStatus instanceof String && StringUtils.isNotBlank((String) accountLinkingStatus)) {
            return (String) accountLinkingStatus;
        }

        return OIDCDebugConstants.STATUS_PENDING;
    }

    private String resolveAccountLinkingMessage(DebugContext context) {

        Object accountLinkingMessage = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE);
        if (accountLinkingMessage instanceof String && StringUtils.isNotBlank((String) accountLinkingMessage)) {
            return (String) accountLinkingMessage;
        }

        if (OIDCDebugConstants.STATUS_FAILED.equals(resolveAccountLinkingStatus(context))) {
            return "Account linking attribute validation failed.";
        }

        return null;
    }

    private void evaluateAccountLinking(DebugContext context, Map<String, Object> incomingClaims) {

        if (!isAccountLinkingEnabled(context) || hasResolvedAccountLinkingStatus(context)) {
            return;
        }

        IdentityProvider idp = resolveIdentityProvider(context, null);
        if (idp == null || idp.getJustInTimeProvisioningConfig() == null) {
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                    OIDCDebugConstants.STATUS_PENDING, "Account linking configuration is not available.",
                    buildAccountLinkingDetails(context));
            return;
        }

        AccountLookupAttributeMappingConfig[] accountLookupMappings =
                idp.getJustInTimeProvisioningConfig().getAccountLookupAttributeMappings();
        if (accountLookupMappings == null || accountLookupMappings.length == 0) {
            evaluateDefaultAccountLinkingAttribute(context, incomingClaims);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                    resolveAccountLinkingStatus(context), "Default account linking attribute check completed.",
                    buildAccountLinkingDetails(context));
            return;
        }

        evaluateConfiguredAccountLinkingAttributes(context, incomingClaims, accountLookupMappings);
        String configuredAccountLinkingStatus = resolveAccountLinkingStatus(context);
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                configuredAccountLinkingStatus,
                OIDCDebugConstants.STATUS_FAILED.equals(configuredAccountLinkingStatus)
                        ? "Configured account linking attribute check failed."
                        : "Configured account linking attribute check successful.",
                buildAccountLinkingDetails(context));
    }

    private Map<String, Object> buildAccountLinkingDetails(DebugContext context) {

        Map<String, Object> details = new LinkedHashMap<>();

        String accountLinkingMessage = resolveAccountLinkingMessage(context);
        if (StringUtils.isNotBlank(accountLinkingMessage)) {
            details.put(OIDCDebugConstants.ACCOUNT_LINKING_REASON, accountLinkingMessage);
            String federatedAttribute = extractFederatedAttribute(accountLinkingMessage);
            if (StringUtils.isNotBlank(federatedAttribute)) {
                details.put("federatedAttribute", federatedAttribute);
            }
        }
        return details;
    }

    private String extractFederatedAttribute(String message) {

        String marker = "Required Federated IdP attribute '";
        if (StringUtils.isBlank(message) || !message.startsWith(marker)) {
            return null;
        }

        int start = marker.length();
        int end = message.indexOf('\'', start);
        if (end <= start) {
            return null;
        }
        return message.substring(start, end);
    }

    private Map<String, Object> normalizeIncomingClaimsForDebug(Map<String, Object> incomingClaims) {

        Map<String, Object> normalizedClaims = new HashMap<>();
        if (incomingClaims == null || incomingClaims.isEmpty()) {
            return normalizedClaims;
        }

        normalizedClaims.putAll(incomingClaims);
        addAddressScopeClaims(incomingClaims, normalizedClaims);
        return normalizedClaims;
    }

    /**
     * Flattens the OIDC "address" structured claim into individual keys (e.g. "street_address", "address.street_address")
     * so they can be matched against IdP claim mappings that reference either format.
     */
    @SuppressWarnings("unchecked")
    private void addAddressScopeClaims(Map<String, Object> incomingClaims, Map<String, Object> normalizedClaims) {

        Object addressClaim = incomingClaims.get(OIDCDebugConstants.CLAIM_ADDRESS);
        if (!(addressClaim instanceof Map)) {
            return;
        }

        Map<String, Object> addressClaims = (Map<String, Object>) addressClaim;
        for (Map.Entry<String, Object> entry : addressClaims.entrySet()) {
            if (entry.getValue() == null) {
                continue;
            }
            normalizedClaims.putIfAbsent(entry.getKey(), entry.getValue());
            normalizedClaims.put("address." + entry.getKey(), entry.getValue());
        }
    }

    private void evaluateDefaultAccountLinkingAttribute(DebugContext context,
            Map<String, Object> incomingClaims) {

        String email = getStringClaim(incomingClaims, OIDCDebugConstants.CLAIM_EMAIL);
        if (StringUtils.isBlank(email)) {
            setAccountLinkingFailure(context, "\"email\" is missing.");
            return;
        }

        setAccountLinkingSuccess(context);
    }

    private void evaluateConfiguredAccountLinkingAttributes(DebugContext context,
            Map<String, Object> incomingClaims,
            AccountLookupAttributeMappingConfig[] accountLookupMappings) {

        for (AccountLookupAttributeMappingConfig mappingConfig : accountLookupMappings) {
            if (mappingConfig == null || StringUtils.isBlank(mappingConfig.getFederatedAttribute())) {
                continue;
            }

            String federatedAttribute = mappingConfig.getFederatedAttribute();
            if (StringUtils.isBlank(getStringClaim(incomingClaims, federatedAttribute))) {
                setAccountLinkingFailure(context, buildMissingAccountLinkingAttributeMessage(mappingConfig));
                return;
            }
        }

        setAccountLinkingSuccess(context);
    }

    private boolean hasResolvedAccountLinkingStatus(DebugContext context) {

        Object accountLinkingStatus = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS);
        return accountLinkingStatus instanceof String && StringUtils.isNotBlank((String) accountLinkingStatus);
    }

    private void setAccountLinkingSuccess(DebugContext context) {

        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE, null);
    }

    private void setAccountLinkingFailure(DebugContext context, String message) {

        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS, OIDCDebugConstants.STATUS_FAILED);
        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE, message);
    }

    private String buildMissingAccountLinkingAttributeMessage(AccountLookupAttributeMappingConfig mappingConfig) {

        String federatedAttribute = mappingConfig.getFederatedAttribute();
        String localAttribute = mappingConfig.getLocalAttribute();

        if (StringUtils.isNotBlank(localAttribute)) {
            return "Required Federated IdP attribute '" + federatedAttribute + "' is missing for account linking to local " +
                    "attribute '" + localAttribute + "'.";
        }

        return "Required Federated IdP attribute '" + federatedAttribute + "' is missing for account linking.";
    }

    private String getStringClaim(Map<String, Object> incomingClaims, String claimName) {

        Object claimValue = incomingClaims.get(claimName);
        return claimValue instanceof String ? (String) claimValue : null;
    }

    private boolean isAccountLinkingEnabled(DebugContext context) {

        IdentityProvider idp = resolveIdentityProvider(context, null);
        if (idp == null) {
            return false;
        }

        JustInTimeProvisioningConfig jitProvisioningConfig = idp.getJustInTimeProvisioningConfig();
        return jitProvisioningConfig != null && jitProvisioningConfig.isProvisioningEnabled()
                && jitProvisioningConfig.isAssociateLocalUserEnabled();
    }

    /**
     * Persists the JSON result under both state and contextId so it is retrievable by either key during callback.
     */
    private void persistJsonToSessionStore(String state, String contextId, String resultJson) {

        try {
            DebugSessionStore.getInstance().putResult(state, resultJson);
            if (contextId != null && !contextId.equals(state)) {
                DebugSessionStore.getInstance().putResult(contextId, resultJson);
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Debug result persisted to cache for state: " + state +
                        (contextId != null ? ", contextId: " + contextId : ""));
            }
        } catch (Exception e) {
            LOG.error("Error persisting debug result to cache: " + e.getMessage(), e);
        }
    }

    /**
     * Redirects to the debug success JSP after processing.
     * URL parameters are encoded to prevent open redirect and injection vulnerabilities.
     * Only redirects to the fixed debug success page path.
     *
     * @param response           HttpServletResponse for sending the redirect.
     * @param state              State parameter for session identification.
     * @param resourceIdentifier IdP resource ID.
     * @throws IOException If response fails.
     */
    @Override
    protected void sendDebugResponse(HttpServletResponse response, String state, String resourceIdentifier) throws IOException {

        if (!response.isCommitted()) {
            String encodedState = encodeForUrl(state);
            String encodedIdpId = encodeForUrl(resourceIdentifier);

            if (encodedState.isEmpty() && StringUtils.isNotEmpty(state)) {
                LOG.error("Failed to encode state parameter for redirect, aborting redirect.");
                return;
            }
            if (encodedIdpId.isEmpty() && StringUtils.isNotEmpty(resourceIdentifier)) {
                LOG.error("Failed to encode idpId parameter for redirect, aborting redirect.");
                return;
            }

            // IdentityUtil resolves the correct host/port for this deployment (handles proxy, port-offset, etc.).
            String successPageUrl = IdentityUtil.getServerURL(OIDCDebugConstants.DEBUG_SUCCESS_PAGE, true, true);
            String redirectUrl = successPageUrl + "?state=" + encodedState + "&idpId=" + encodedIdpId;
            response.sendRedirect(redirectUrl);
        }
    }

    /**
     * Restores context properties from DebugSessionStore using the state parameter.
     * Required because the OIDC callback arrives in a new request with no in-memory context.
     */
    private void restoreContextFromSessionCache(String state, DebugContext context) {

        try {
            Map<String, Object> cachedContext = DebugSessionStore.getInstance().get(state);
            if (cachedContext == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No cached context found for state: " + state);
                }
                return;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Restoring context from DebugSessionStore for state: " + state);
            }
            restorePropertiesToContext(cachedContext, context);

        } catch (Exception e) {
            LOG.debug("Unable to restore context from DebugSessionStore: " + e.getMessage());
        }
    }

    private void restorePropertiesToContext(Map<String, Object> cachedContext, DebugContext context) {

        // When adding new context properties that must survive the callback round-trip, add them here too.
        // CLIENT_SECRET is intentionally excluded — it is nulled out before caching in OIDCDebugExecutor.
        String[] propertiesToRestore = {
                OIDCDebugConstants.TOKEN_ENDPOINT, OIDCDebugConstants.CLIENT_ID,
                OIDCDebugConstants.DEBUG_CODE_VERIFIER,
                OIDCDebugConstants.REDIRECT_URI,
                OIDCDebugConstants.DEBUG_IDP_NAME, OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID,
                OIDCDebugConstants.AUTHORIZATION_ENDPOINT,
                OIDCDebugConstants.DEBUG_ID, OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL,
                OIDCDebugConstants.DEBUG_DIAGNOSTICS,
                OIDCDebugConstants.ACCESS_TOKEN, OIDCDebugConstants.ID_TOKEN, OIDCDebugConstants.TOKEN_TYPE,
                OIDCDebugConstants.DEBUG_NONCE,
        };

        for (String property : propertiesToRestore) {
            Object value = cachedContext.get(property);
            if (value != null) {
                context.setProperty(property, value);
            }
        }
    }

    private Map<String, Object> buildErrorDetails(String errorCode, String errorDescription) {

        Map<String, Object> details = new LinkedHashMap<>();
        if (StringUtils.isNotBlank(errorCode)) {
            details.put(OIDCDebugConstants.DIAG_ERROR_CODE, errorCode);
        }
        if (StringUtils.isNotBlank(errorDescription)) {
            details.put(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION, errorDescription);
        }
        return details;
    }

    private List<Map<String, Object>> transformDiagnostics(List<Map<String, Object>> diagnostics) {

        List<Map<String, Object>> sanitizedDiagnostics = new ArrayList<>();
        for (Map<String, Object> diagnostic : diagnostics) {
            sanitizedDiagnostics.add(transformDiagnosticEvent(diagnostic));
        }
        return sanitizedDiagnostics;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> transformDiagnosticEvent(Map<String, Object> diagnostic) {

        Map<String, Object> sanitizedEvent = new LinkedHashMap<>(diagnostic);
        Object detailsObj = sanitizedEvent.get(DebugFrameworkConstants.DIAGNOSTIC_DETAILS);
        if (!(detailsObj instanceof Map)) {
            return sanitizedEvent;
        }

        Map<String, Object> details = new LinkedHashMap<>((Map<String, Object>) detailsObj);
        Object errorCode = details.remove(OIDCDebugConstants.DIAG_ERROR_CODE);
        Object errorDescription = details.remove(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION);
        Object accountLinkingReason = details.remove(OIDCDebugConstants.ACCOUNT_LINKING_REASON);
        Object federatedAttribute = details.remove("federatedAttribute");
        details.remove("idpName");
        details.remove(OIDCDebugConstants.TOKEN_ENDPOINT);

        if (errorCode != null) {
            sanitizedEvent.put(OIDCDebugConstants.DIAG_ERROR_CODE, errorCode);
        }
        if (errorDescription == null && accountLinkingReason != null) {
            errorDescription = accountLinkingReason;
        }
        if (errorDescription != null) {
            sanitizedEvent.put(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION, errorDescription);
        }
        if (federatedAttribute != null) {
            sanitizedEvent.put("federatedAttribute", federatedAttribute);
        }

        if (details.isEmpty()) {
            sanitizedEvent.remove(DebugFrameworkConstants.DIAGNOSTIC_DETAILS);
        } else {
            sanitizedEvent.put(DebugFrameworkConstants.DIAGNOSTIC_DETAILS, details);
        }
        return sanitizedEvent;
    }

    /**
     * URL-encodes a parameter for safe use in HTTP redirects.
     * Returns empty string on encoding failure to prevent injection rather than propagating a bad value.
     */
    private String encodeForUrl(String param) {

        if (param == null || param.isEmpty()) {
            return "";
        }
        try {
            return java.net.URLEncoder.encode(param, StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            LOG.warn("Error encoding parameter for URL: " + e.getMessage());
            return "";
        }
    }
}
