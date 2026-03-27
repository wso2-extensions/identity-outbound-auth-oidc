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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCConfiguration;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCConfigurationExtractor;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.cache.DebugSessionCache;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.OAuth2TokenClient;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.TokenResponse;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.UrlConnectionHttpFetcher;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.debug.framework.core.DebugProcessor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OIDC-specific implementation of abstract DebugProcessor.
 * Implements only protocol-specific OIDC logic.
 * All generic logic is inherited from DebugProcessor base class.
 */

public class OIDCDebugProcessor extends DebugProcessor {

    private static final Log LOG = LogFactory.getLog(OIDCDebugProcessor.class);
    private static final com.fasterxml.jackson.databind.ObjectMapper OBJECT_MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();

    // Context property keys used for caching debug results.
    private static final String DEBUG_RESULT_CACHE_KEY = "DEBUG_RESULT_CACHE";

    /**
     * Validates OIDC-specific callback parameters.
     * Checks for authorization code or error response, CSRF protection.
     *
     * @param request  HttpServletRequest.
     * @param context  AuthenticationContext.
     * @param response HttpServletResponse.
     * @param state    State parameter.
     * @param idpId    IdP resource ID.
     * @return true if callback is valid, false otherwise.
     * @throws IOException If response cannot be sent.
     */
    @Override
    protected boolean validateCallback(HttpServletRequest request, AuthenticationContext context,
            HttpServletResponse response, String state, String idpId) throws IOException {

        String code = request.getParameter("code");
        String error = request.getParameter("error");
        String errorDescription = request.getParameter("error_description");

        // Store IdP ID in context for fallback resolution during token exchange.
        if (StringUtils.isNotEmpty(idpId)) {
            context.setProperty(OIDCDebugConstants.DEBUG_IDP_NAME, idpId);
        }

        // Handle OIDC error responses.
        if (error != null) {
            LOG.error("OIDC error from IdP: " + error + " - " + errorDescription);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, error + ": " + errorDescription);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse(error, errorDescription, "", state, context);
            return false;
        }

        // Validate authorization code presence.
        if (code == null || code.trim().isEmpty()) {
            LOG.error("Authorization code missing in OIDC callback");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Authorization code not received");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("NO_CODE",
                    "Authorization code not received from IdP", "", state, context);
            return false;
        }

        // Validate state parameter.
        if (state == null || state.trim().isEmpty()) {
            LOG.error("State parameter missing in OIDC callback");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR,
                    "State parameter missing - possible CSRF attack");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("NO_STATE",
                    "State parameter missing - possible CSRF attack", "", state, context);
            return false;
        }

        // Validate state matches stored value if available.
        String storedState = (String) context.getProperty(OIDCDebugConstants.DEBUG_STATE);
        if (storedState != null && !state.equals(storedState)) {
            LOG.error("State parameter mismatch - CSRF attack detected");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR,
                    "State validation failed - possible CSRF attack");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("STATE_MISMATCH",
                    "State validation failed - possible CSRF attack", "", state, context);
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("OIDC callback validation passed for state: " + state);
        }

        return true;
    }

    /**
     * Exchanges OIDC authorization code for tokens (access token + ID token).
     * Stores tokens in context and handles errors with detailed diagnostic info.
     * Delegates to smaller, focused methods for configuration extraction and token
     * exchange.
     *
     * @param request HttpServletRequest.
     * @param context AuthenticationContext.
     * @param response HttpServletResponse.
     * @param state State parameter.
     * @param idpId IdP resource ID.
     * @return true if token exchange succeeds, false otherwise.
     * @throws IOException If response cannot be sent.
     */
    @Override
    protected boolean processAuthentication(HttpServletRequest request, AuthenticationContext context,
            HttpServletResponse response, String state, String idpId) throws IOException {

        String code = request.getParameter("code");

        if (LOG.isDebugEnabled()) {
            LOG.debug("=== Starting OIDC Token Exchange ===");
            LOG.debug("Authorization Code: " + (code != null && !code.isEmpty() ? OIDCDebugConstants.STATUS_PRESENT
                    : OIDCDebugConstants.STATUS_ABSENT));
            LOG.debug("State: " + state);
            LOG.debug("IdP ID: " + idpId);
        }

        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Exchanging authorization code for OIDC tokens. Code present: " + (code != null));
            }

            // Validate prerequisites.
            if (!validateAndExtractPrerequisites(code, state, context)) {
                LOG.error("Token exchange failed: Prerequisites validation failed");
                context.setProperty(OIDCDebugConstants.STEP_CONNECTION_STATUS, OIDCDebugConstants.STATUS_FAILED);
                return false;
            }

            // Extract configuration from IdP and context.
            OIDCConfiguration config = extractOIDCConfiguration(context, request);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Extracted OIDC Configuration:");
                LOG.debug("  IdP Name: " + config.getIdpName());
                LOG.debug("  Token Endpoint: " + config.getTokenEndpoint());
                LOG.debug("  Client ID: " + (config.getClientId() != null ? OIDCDebugConstants.STATUS_PRESENT
                        : OIDCDebugConstants.STATUS_ABSENT));
                LOG.debug("  Client Secret: " + (config.getClientSecret() != null ? OIDCDebugConstants.STATUS_PRESENT
                        : OIDCDebugConstants.STATUS_ABSENT));
                LOG.debug("  Callback URL: " + config.getCallbackUrl());
            }

            if (!config.isValid()) {
                LOG.error("Token exchange failed: OIDC configuration is invalid");
                handleConfigurationError(config, state, context);
                return false;
            }

            // Perform token exchange.
            return performTokenExchange(code, config, state, context);

        } catch (Exception e) {
            LOG.error("Exception during OIDC token exchange: " + e.getMessage(), e);
            buildAndCacheTokenExchangeErrorResponse("TOKEN_EXCHANGE_ERROR",
                    "Token exchange error: " + e.getMessage(), e.toString(), state, context);
            context.setProperty(OIDCDebugConstants.STEP_CONNECTION_STATUS, OIDCDebugConstants.STATUS_FAILED);
            context.setProperty(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS, OIDCDebugConstants.STATUS_FAILED);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Token exchange error: " + e.getMessage());
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            return false;
        }
    }

    /**
     * Validates authorization code and IdP configuration.
     *
     * @param code Authorization code from callback.
     * @param state State parameter from callback.
     * @param context AuthenticationContext.
     * @return true if validation passes, false otherwise.
     */
    private boolean validateAndExtractPrerequisites(String code, String state, AuthenticationContext context) {

        IdentityProvider idp = deserializeIdentityProvider(context.getProperty(OIDCDebugConstants.IDP_CONFIG));

        // Try to restore properties from session cache if IDP_CONFIG not found
        if (idp == null) {
            restoreContextFromSessionCache(state, context);
            idp = deserializeIdentityProvider(context.getProperty(OIDCDebugConstants.IDP_CONFIG));
        }

        // Last resort: try to resolve IdP from cached IdP name or resource ID
        if (idp == null) {
            idp = resolveIdpFromContext(context, state);
        }

        if (idp == null) {
            LOG.error("IdP configuration not found in context");
            buildAndCacheTokenExchangeErrorResponse("IDP_CONFIG_MISSING",
                    "Identity Provider configuration not found", "", state, context);
            return false;
        }

        if (code == null || code.trim().isEmpty()) {
            LOG.error("Authorization code missing in OIDC callback");
            buildAndCacheTokenExchangeErrorResponse("NO_CODE",
                    "Authorization code not received from IdP", "", state, context);
            return false;
        }

        context.setProperty(OIDCDebugConstants.DEBUG_IDP_NAME, idp.getIdentityProviderName());
        context.setProperty(OIDCDebugConstants.IDP_CONFIG, idp);
        return true;
    }

    /**
     * Resolves IdP from cached context properties when IDP_CONFIG is not directly available.
     * Uses stored IdP name or resource ID to look up the IdentityProvider.
     *
     * @param context AuthenticationContext.
     * @param state State parameter for debugging.
     * @return IdentityProvider if found, null otherwise.
     */
    private IdentityProvider resolveIdpFromContext(AuthenticationContext context, String state) {

        try {
            String tenantDomain = org.wso2.carbon.identity.core.util.IdentityTenantUtil.resolveTenantDomain();
            
            // Try to get IdP name from context.
            String idpName = (String) context.getProperty(OIDCDebugConstants.DEBUG_IDP_NAME);
            if (StringUtils.isEmpty(idpName)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("IdP name not found in context for state: " + state);
                }
                return null;
            }

            // Try to resolve IdP by name.
            org.wso2.carbon.idp.mgt.IdentityProviderManager idpManager = 
                    org.wso2.carbon.idp.mgt.IdentityProviderManager.getInstance();
            IdentityProvider idp = idpManager.getIdPByName(idpName, tenantDomain, false);
            
            if (idp != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Resolved IdP from context cache for state: " + state + ", IdP: " + idpName);
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
     * Deserializes an IdentityProvider object from potentially serialized format.
     * Handles conversion from LinkedHashMap (from JSON deserialization) to IdentityProvider.
     *
     * @param idpObject The object to deserialize, which may be IdentityProvider or LinkedHashMap.
     * @return IdentityProvider if deserialization succeeds, null otherwise.
     */
    private IdentityProvider deserializeIdentityProvider(Object idpObject) {

        if (idpObject == null) {
            return null;
        }

        // If already an IdentityProvider instance, return as-is.
        if (idpObject instanceof IdentityProvider) {
            return (IdentityProvider) idpObject;
        }

        // Handle LinkedHashMap from JSON deserialization.
        if (idpObject instanceof LinkedHashMap) {
            try {
                IdentityProvider idp = OBJECT_MAPPER.convertValue(idpObject, IdentityProvider.class);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Successfully deserialized IdentityProvider from LinkedHashMap");
                }
                return idp;
            } catch (Exception e) {
                LOG.error("Failed to deserialize IdentityProvider from LinkedHashMap: " + e.getMessage(), e);
                return null;
            }
        }

        // Handle Map interface.
        if (idpObject instanceof Map) {
            try {
                IdentityProvider idp = OBJECT_MAPPER.convertValue(idpObject, IdentityProvider.class);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Successfully deserialized IdentityProvider from Map");
                }
                return idp;
            } catch (Exception e) {
                LOG.error("Failed to deserialize IdentityProvider from Map: " + e.getMessage(), e);
                return null;
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Cannot deserialize IdentityProvider: unexpected type " + idpObject.getClass().getName());
        }
        return null;
    }

    /**
     * Extracts OIDC configuration from context and IdP settings.
     * First tries context (set by OIDCContextResolver), then falls back to IdP
     * config.
     *
     * @param context AuthenticationContext.
     * @param request HttpServletRequest.
     * @return OIDCConfiguration containing all required endpoints and
     *         credentials.
     */
    private OIDCConfiguration extractOIDCConfiguration(AuthenticationContext context, HttpServletRequest request) {

        OIDCConfiguration config = new OIDCConfiguration();
        IdentityProvider idp = deserializeIdentityProvider(context.getProperty(OIDCDebugConstants.IDP_CONFIG));
        String idpName = idp != null ? idp.getIdentityProviderName() : "Unknown";
        config.setIdpName(idpName);
        config.setCodeVerifier((String) context.getProperty(OIDCDebugConstants.DEBUG_CODE_VERIFIER));

        // Extract from context first (set by OIDCContextProvider).
        config.setTokenEndpoint((String) context.getProperty(OIDCDebugConstants.TOKEN_ENDPOINT));
        config.setClientId((String) context.getProperty(OIDCDebugConstants.CLIENT_ID));
        config.setClientSecret((String) context.getProperty(OIDCDebugConstants.CLIENT_SECRET));
        config.setUserInfoEndpoint((String) context.getProperty(OIDCDebugConstants.USERINFO_ENDPOINT));

        if (LOG.isDebugEnabled()) {
            LOG.debug("Token exchange - from context: tokenEndpoint=" +
                    (config.getTokenEndpoint() != null ? OIDCDebugConstants.STATUS_FOUND : "null") +
                    ", clientId=" + (config.getClientId() != null ? OIDCDebugConstants.STATUS_FOUND : "null") +
                    ", clientSecret="
                    + (config.getClientSecret() != null ? OIDCDebugConstants.STATUS_FOUND : "null"));
        }

        // If not in context, extract from IdP authenticator config using
        // OIDCConfigurationExtractor.
        if (!config.hasRequiredEndpoints() && idp != null && idp.getFederatedAuthenticatorConfigs() != null) {
            extractFromIdPConfig(idp, config);
        }

        // Build callback URL.
        String callbackUrl = (String) context.getProperty(OIDCDebugConstants.REDIRECT_URI);
        if (StringUtils.isEmpty(callbackUrl)) {
            callbackUrl = request.getRequestURL().toString().split("\\?")[0];
        }
        config.setCallbackUrl(callbackUrl);

        return config;
    }

    /**
     * Extracts OIDC configuration from IdP authenticator properties
     * using {@link OIDCConfigurationExtractor} as single source of truth.
     *
     * @param idp    IdentityProvider containing authenticator configs.
     * @param config OIDCConfiguration to populate.
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
            if (StringUtils.isNotEmpty(extracted.get("tokenEndpoint"))) {
                config.setTokenEndpoint(extracted.get("tokenEndpoint"));
            }
            if (StringUtils.isNotEmpty(extracted.get("clientId"))) {
                config.setClientId(extracted.get("clientId"));
            }
            if (StringUtils.isNotEmpty(extracted.get("clientSecret"))) {
                config.setClientSecret(extracted.get("clientSecret"));
            }
            if (StringUtils.isNotEmpty(extracted.get("userInfoEndpoint"))) {
                config.setUserInfoEndpoint(extracted.get("userInfoEndpoint"));
            }
            if (config.hasRequiredEndpoints()) {
                break;
            }
        }
    }

    /**
     * Handles configuration validation errors.
     *
     * @param config OIDCConfiguration with missing values.
     * @param state State parameter.
     * @param context AuthenticationContext.
     */
    private void handleConfigurationError(OIDCConfiguration config, String state, AuthenticationContext context) {

        if (config.getTokenEndpoint() == null || config.getTokenEndpoint().trim().isEmpty()) {
            LOG.error("Token endpoint not found in context or IdP configuration");
            buildAndCacheTokenExchangeErrorResponse("TOKEN_ENDPOINT_MISSING",
                    "Token endpoint is not configured", "", state, context);
        }

        if (config.getClientId() == null || config.getClientId().trim().isEmpty()) {
            LOG.error("Client ID not found in context or IdP configuration");
            buildAndCacheTokenExchangeErrorResponse("CLIENT_ID_MISSING",
                    "Client ID is not configured", "", state, context);
        }
    }

    /**
     * Performs OIDC token exchange using the provided configuration.
     *
     * @param code Authorization code.
     * @param config OIDCConfiguration.
     * @param state State parameter.
     * @param context AuthenticationContext.
     * @return true if exchange succeeds, false otherwise.
     */
    private boolean performTokenExchange(String code, OIDCConfiguration config, String state,
            AuthenticationContext context) {

        logTokenExchangeStart(config);
        TokenResponse tokenResponse = executeTokenExchange(code, config);

        if (tokenResponse.hasError()) {
            return handleTokenExchangeError(tokenResponse, config, state, context);
        }

        return handleTokenExchangeSuccess(tokenResponse, config, context);
    }

    /**
     * Logs the start of token exchange process.
     *
     * @param config OIDCConfiguration.
     */
    private void logTokenExchangeStart(OIDCConfiguration config) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Starting token exchange with IdP: " + config.getIdpName() +
                    ", Token Endpoint: " + config.getTokenEndpoint() +
                    ", Client ID: " + (config.getClientId() != null ? "PRESENT" : "MISSING"));
        }
    }

    /**
     * Executes the actual token exchange call to the provider.
     *
     * @param code Authorization code.
     * @param config OIDCConfiguration.
     * @return Token response from provider.
     */
    private TokenResponse executeTokenExchange(String code, OIDCConfiguration config) {

        OAuth2TokenClient tokenClient = new OAuth2TokenClient();
        return tokenClient.exchangeCodeForTokens(
                code, config.getTokenEndpoint(), config.getClientId(), config.getClientSecret(),
                config.getCallbackUrl(), config.getCodeVerifier(), config.getIdpName());
    }

    /**
     * Handles token exchange error response.
     *
     * @param tokenResponse Token response with error.
     * @param config OIDCConfiguration.
     * @param state State parameter.
     * @param context AuthenticationContext.
     * @return false always, indicating exchange failed.
     */
    private boolean handleTokenExchangeError(TokenResponse tokenResponse, OIDCConfiguration config,
            String state, AuthenticationContext context) {

        String errorCode = tokenResponse.getErrorCode();
        String errorDesc = tokenResponse.getErrorDescription();
        String errorDetails = tokenResponse.getErrorDetails();

        logTokenExchangeError(config, errorCode, errorDesc, errorDetails);
        logErrorDiagnosticInfo(config);
        logErrorCauses(errorCode);

        buildAndCacheTokenExchangeErrorResponse(errorCode, errorDesc, errorDetails, state, context);
        markContextAsFailedExchange(context, errorDesc);

        return false;
    }

    /**
     * Logs detailed error information from token exchange failure.
     * Sanitizes external input to prevent log injection attacks.
     *
     * @param config OIDCConfiguration.
     * @param errorCode Error code from response.
     * @param errorDesc Error description.
     * @param errorDetails Additional error details.
     */
    private void logTokenExchangeError(OIDCConfiguration config, String errorCode,
            String errorDesc, String errorDetails) {

        LOG.error("Token exchange failed for IdP: " + sanitizeForLog(config.getIdpName()));
        LOG.error("  Error Code: " + sanitizeForLog(errorCode));
        LOG.error("  Error Description: " + sanitizeForLog(errorDesc));

        if (errorDetails != null && !errorDetails.isEmpty()) {
            LOG.error("  Error Details: " + sanitizeForLog(errorDetails));
        }
    }

    /**
     * Sanitizes a string for safe logging by removing newlines and control characters.
     * Prevents log injection attacks.
     *
     * @param input The input string to sanitize.
     * @return Sanitized string safe for logging.
     */
    private String sanitizeForLog(String input) {

        if (input == null) {
            return "null";
        }
        // Remove newlines and carriage returns to prevent log injection.
        return input.replaceAll("[\\r\\n]", " ").replaceAll("[\\x00-\\x1F\\x7F]", "");
    }

    /**
     * Logs diagnostic configuration details used for token exchange.
     *
     * @param config OIDCConfiguration.
     */
    private void logErrorDiagnosticInfo(OIDCConfiguration config) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Token exchange configuration used:");
            LOG.debug("  Token Endpoint: " + config.getTokenEndpoint());
            LOG.debug("  Client ID: " + config.getClientId());
            LOG.debug("  Callback URL: " + config.getCallbackUrl());
            LOG.debug("  Code Verifier: " + (config.getCodeVerifier() != null ? "PRESENT" : "NOT_PRESENT"));
        }
    }

    /**
     * Logs likely causes of common OIDC error codes.
     *
     * @param errorCode The error code returned from token endpoint.
     */
    private void logErrorCauses(String errorCode) {

        if ("INVALID_CLIENT".equals(errorCode) || "UNAUTHORIZED".equals(errorCode)) {
            LOG.error("Possible causes: Incorrect Client ID or Client Secret");
            LOG.error("Verify credentials in IdP authenticator configuration");
        } else if ("INVALID_GRANT".equals(errorCode)) {
            LOG.error("Possible causes: Authorization code expired or already used");
        } else if (OIDCDebugConstants.ERROR_CODE_INVALID_REQUEST.equals(errorCode)) {
            LOG.error("Possible causes: Malformed request, incorrect redirect URI, or PKCE mismatch");
        }
    }

    /**
     * Marks the authentication context as failed exchange.
     *
     * @param context   AuthenticationContext.
     * @param errorDesc Error description.
     */
    private void markContextAsFailedExchange(AuthenticationContext context, String errorDesc) {

        context.setProperty(OIDCDebugConstants.STEP_CONNECTION_STATUS, OIDCDebugConstants.STATUS_FAILED);
        context.setProperty(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS, OIDCDebugConstants.STATUS_FAILED);
        context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, errorDesc);
        context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
    }

    /**
     * Handles successful token exchange.
     *
     * @param tokenResponse Token response from provider.
     * @param config OIDCConfiguration.
     * @param context AuthenticationContext.
     * @return true always, indicating exchange succeeded.
     */
    private boolean handleTokenExchangeSuccess(TokenResponse tokenResponse, OIDCConfiguration config,
            AuthenticationContext context) {

        storeTokensInContext(tokenResponse, config, context);
        markContextAsSuccessfulExchange(context);
        logTokenExchangeSuccess(tokenResponse, config);
        return true;
    }

    /**
     * Marks the authentication context as successful exchange.
     *
     * @param context AuthenticationContext.
     */
    private void markContextAsSuccessfulExchange(AuthenticationContext context) {

        context.setProperty(OIDCDebugConstants.STEP_CONNECTION_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
        context.setProperty(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
    }

    /**
     * Logs successful token exchange completion.
     *
     * @param tokenResponse Token response from provider.
     * @param config Auth2Configuration.
     */
    private void logTokenExchangeSuccess(TokenResponse tokenResponse, OIDCConfiguration config) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("OIDC token exchange completed successfully for IdP: " + config.getIdpName() +
                    ", received tokens: " +
                    (tokenResponse.getAccessToken() != null ? "access_token present, " : "NO access_token, ") +
                    (tokenResponse.getIdToken() != null ? "id_token present" : "NO id_token"));
        }
    }

    /**
     * Stores tokens and configuration from successful exchange into context.
     *
     * @param tokenResponse Token response from provider.
     * @param config OIDCConfiguration OIDCConfiguration used for exchange.
     * @param context AuthenticationContext to populate.
     */
    private void storeTokensInContext(TokenResponse tokenResponse, OIDCConfiguration config,
            AuthenticationContext context) {

        String accessToken = tokenResponse.getAccessToken();
        String idToken = tokenResponse.getIdToken();
        String tokenType = tokenResponse.getTokenType();

        context.setProperty(OIDCDebugConstants.ACCESS_TOKEN, accessToken);
        if (idToken != null && !idToken.trim().isEmpty()) {
            context.setProperty(OIDCDebugConstants.ID_TOKEN, idToken);
        }
        if (tokenType != null && !tokenType.trim().isEmpty()) {
            context.setProperty(OIDCDebugConstants.TOKEN_TYPE, tokenType);
        }
        if (config.getUserInfoEndpoint() != null && !config.getUserInfoEndpoint().trim().isEmpty()) {
            context.setProperty(OIDCDebugConstants.USERINFO_ENDPOINT, config.getUserInfoEndpoint());
            context.setProperty(OIDCDebugConstants.USERINFO, config.getUserInfoEndpoint());
        }
    }

    /**
     * Extracts user claims from OIDC/OIDC tokens.
     * OIDC-specific implementation that parses ID token claims and fetches
     * UserInfo.
     * Generic claim mapping and formatting is handled by parent DebugProcessor
     * class.
     *
     * @param context AuthenticationContext containing ID token and access token.
     * @return Map of extracted claims, or empty map if extraction yields no
     *         results.
     */
    @Override
    protected Map<String, Object> extractDebugData(AuthenticationContext context) {

        try {
            // Extract and validate ID token.
            String idToken = (String) context.getProperty(OIDCDebugConstants.ID_TOKEN);
            if (!isValidIdToken(idToken)) {
                return new HashMap<>();
            }

            // Parse ID token to extract initial claims.
            Map<String, Object> claims = parseIdTokenClaims(idToken);

            // Attempt to merge with UserInfo endpoint claims if available.
            mergeUserInfoClaims(context, claims);

            // Return extracted claims or empty map if none found.
            return returnExtractedClaims(claims, context);

        } catch (Exception e) {
            LOG.error("Error extracting user claims from OIDC tokens: " + e.getMessage(), e);
            return new HashMap<>();
        }
    }

    /**
     * Validates if the ID token is present and not empty.
     *
     * @param idToken The ID token to validate.
     * @return true if token is valid, false otherwise.
     */
    private boolean isValidIdToken(String idToken) {

        if (idToken == null || idToken.trim().isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No ID token available for claim extraction");
            }
            return false;
        }
        return true;
    }

    /**
     * Merges claims from UserInfo endpoint with ID token claims.
     * Handles the case where access token is available to call UserInfo endpoint.
     *
     * @param context AuthenticationContext.
     * @param claims  Current claims map from ID token (modified in place).
     */
    private void mergeUserInfoClaims(AuthenticationContext context, Map<String, Object> claims) {

        String accessToken = (String) context.getProperty(OIDCDebugConstants.ACCESS_TOKEN);
        if (StringUtils.isEmpty(accessToken)) {
            return;
        }

        String userInfoEndpoint = (String) context.getProperty(OIDCDebugConstants.USERINFO_ENDPOINT);
        if (StringUtils.isEmpty(userInfoEndpoint)) {
            userInfoEndpoint = (String) context.getProperty(OIDCDebugConstants.USERINFO);
        }
        if (StringUtils.isEmpty(userInfoEndpoint)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("UserInfo endpoint URL not available in context");
            }
            return;
        }

        try {
            // Delegate to OIDCTokenClient instead of inline HTTP client.
            OAuth2TokenClient tokenClient = new OAuth2TokenClient();
            Map<String, Object> userInfoClaims = tokenClient.fetchUserInfoClaims(
                    accessToken, userInfoEndpoint, new UrlConnectionHttpFetcher());
            if (!userInfoClaims.isEmpty()) {
                userInfoClaims.putAll(claims);
                claims.clear();
                claims.putAll(userInfoClaims);
                context.setProperty(OIDCDebugConstants.DEBUG_USERINFO_CALLED, "true");
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Successfully merged UserInfo claims with ID token claims. Total: " + claims.size());
                }
            }
        } catch (Exception e) {
            context.setProperty(OIDCDebugConstants.DEBUG_USERINFO_ERROR, e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("UserInfo endpoint call failed, continuing with ID token claims: " + e.getMessage());
            }
        }
    }

    /**
     * Returns extracted claims with appropriate logging.
     *
     * @param claims  Extracted claims.
     * @param context AuthenticationContext.
     * @return Claims if not empty, empty map otherwise.
     */
    private Map<String, Object> returnExtractedClaims(Map<String, Object> claims,
            AuthenticationContext context) {

        if (!claims.isEmpty()) {
            context.setProperty(OIDCDebugConstants.STEP_CLAIM_EXTRACTION_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
            context.setProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS, claims);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully extracted " + claims.size() + " claims from tokens: " + claims.keySet());
            }
            return claims;
        }

        context.setProperty(OIDCDebugConstants.STEP_CLAIM_EXTRACTION_STATUS, OIDCDebugConstants.STATUS_FAILED);
        if (LOG.isDebugEnabled()) {
            LOG.debug("No claims extracted from ID token or UserInfo endpoint");
        }
        return new HashMap<>();
    }

    /**
     * Parses JWT ID token and extracts claims from the payload.
     * Handles JWT format with three parts: header.payload.signature.
     *
     * @param idToken The JWT ID token.
     * @return Map of claims extracted from the token payload, or empty map if
     *         parsing fails.
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
     * Parses JSON string to claims map.
     *
     * @param json The JSON string to parse.
     * @return Map of claims from the JSON, or empty map if parsing fails.
     */
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
     * Checks if authorization code was already processed (replay attack
     * prevention).
     * For OIDC, uses state parameter as session key to track processed codes.
     *
     * @param authorizationCode The authorization code from callback.
     * @param request           HttpServletRequest.
     * @param context           AuthenticationContext.
     * @param response          HttpServletResponse.
     * @param state             State parameter for session tracking.
     * @param idpId             IdP resource ID.
     * @return true if duplicate code detected, false otherwise.
     * @throws IOException If response cannot be sent.
     */
    protected boolean isAuthorizationCodeAlreadyProcessed(String authorizationCode, HttpServletRequest request,
            AuthenticationContext context, HttpServletResponse response, String state, String idpId)
            throws IOException {

        // Check if code was already processed in this session using state parameter.
        Object processedCode = context.getProperty(OIDCDebugConstants.DEBUG_PROCESSED_CODE_PREFIX + state);
        if (processedCode != null && processedCode.equals(authorizationCode)) {
            LOG.error("Authorization code replay detected - code already processed for state: " + state);
            buildAndCacheTokenExchangeErrorResponse("CODE_REPLAY",
                    "Authorization code was already processed", "", state, context);
            return true;
        }

        // Mark this code as processed for this state.
        context.setProperty(OIDCDebugConstants.DEBUG_PROCESSED_CODE_PREFIX + state, authorizationCode);
        return false;
    }

    /**
     * Handles claim extraction result and validates successful extraction.
     * For OIDC, validates that required claims (sub/user ID) are present.
     *
     * @param claims   Map of extracted claims.
     * @param context  AuthenticationContext.
     * @param response HttpServletResponse.
     * @param state    State parameter.
     * @param idpId    IdP resource ID.
     * @return true if claims extraction succeeded, false otherwise.
     * @throws IOException If response cannot be sent.
     */
    @Override
    protected boolean validateDebugData(Map<String, Object> claims, AuthenticationContext context,
            HttpServletResponse response, String state, String idpId) throws IOException {

        if (claims == null || claims.isEmpty()) {
            LOG.error("No claims extracted from OIDC tokens");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "No user claims extracted from IdP");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("NO_CLAIMS",
                    "No user claims available from IdP", "", state, context);
            return false;
        }

        // Validate that at least a user identifier is present.
        if (!claims.containsKey("sub") && !claims.containsKey("user_id") &&
                !claims.containsKey("userId") && !claims.containsKey("email")) {
            LOG.error("Required user identifier claim not found in extracted claims");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "User identifier claim missing");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("NO_USER_IDENTIFIER",
                    "User identifier (sub/user_id/email) not found in claims", "", state, context);
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Claims extraction validation passed. Claims found: " + claims.keySet());
        }

        return true;
    }

    /**
     * Builds and caches the final debug result after successful authentication.
     * Includes comprehensive claim mapping information and diagnostic data.
     * Persists to DebugResultCache for API retrieval.
     *
     * @param context AuthenticationContext containing all debug information.
     * @param state   State parameter for session identification.
     */
    @Override
    protected void buildAndCacheDebugResult(AuthenticationContext context, String state) {

        try {
            Map<String, Object> debugResult = initializeDebugResult(context, state);
            Map<String, Object> incomingClaims = extractIncomingClaims(context);
            extractAndProcessUserIdentifiers(incomingClaims, debugResult);
            processClaimMappingsAndDiagnostics(context, incomingClaims, debugResult);
            buildUserAttributesAndMetadata(incomingClaims, debugResult, context);
            
            // Determine overall success based on step statuses.
            determineOverallSuccessStatus(debugResult, context);
            
            persistDebugResultToCache(state, context, debugResult);

        } catch (Exception e) {
            LOG.error("Error building and caching debug result: " + e.getMessage(), e);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Error caching debug result: " + e.getMessage());
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
        }
    }

    /**
     * Initializes the debug result map with basic properties and step statuses.
     *
     * @param context AuthenticationContext.
     * @param state   State parameter.
     * @return Initialized debug result map.
     */
    private Map<String, Object> initializeDebugResult(AuthenticationContext context, String state) {

        Map<String, Object> debugResult = new HashMap<>();
        debugResult.put("state", state);
        debugResult.put(OIDCDebugConstants.DEBUG_RESULT_SUCCESS, true);
        debugResult.put("authenticator", DebugFrameworkConstants.IMPLEMENTATION_OPENID_CONNECT);
        debugResult.put(OIDCDebugConstants.DEBUG_RESULT_IDPNAME,
                context.getProperty(OIDCDebugConstants.DEBUG_IDP_NAME));
        debugResult.put(OIDCDebugConstants.DEBUG_RESULT_SESSIONID,
                context.getProperty(OIDCDebugConstants.DEBUG_CONTEXT_ID));
        debugResult.put("executor", "UnknownExecutor");

        return debugResult;
    }

    /**
     * Extracts incoming claims from context.
     *
     * @param context AuthenticationContext.
     * @return Incoming claims map or empty map if not available.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> extractIncomingClaims(AuthenticationContext context) {

        Map<String, Object> incomingClaims = (Map<String, Object>) context
                .getProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS);
        return incomingClaims != null ? incomingClaims : new HashMap<>();
    }

    /**
     * Extracts user identifier claims (sub, email, username) from incoming claims.
     *
     * @param incomingClaims Map of incoming claims.
     * @param debugResult    Debug result map to populate with userId and username.
     */
    private void extractAndProcessUserIdentifiers(Map<String, Object> incomingClaims,

            Map<String, Object> debugResult) {
        String userId = null;
        String username = null;

        if (!incomingClaims.isEmpty()) {
            userId = (String) incomingClaims.get("sub");
            username = (String) incomingClaims.get("email");
            if (username == null) {
                username = (String) incomingClaims.get("username");
            }
        }

        debugResult.put("userId", userId);
        debugResult.put("username", username);
    }

    /**
     * Processes claim mappings from IdP configuration and builds diagnostic
     * information.
     *
     * @param context AuthenticationContext.
     * @param incomingClaims Incoming claims map.
     * @param debugResult Debug result map to populate.
     */
    private void processClaimMappingsAndDiagnostics(AuthenticationContext context,
            Map<String, Object> incomingClaims, Map<String, Object> debugResult) {

        IdentityProvider idp = deserializeIdentityProvider(context.getProperty(OIDCDebugConstants.IDP_CONFIG));
        Map<String, Map<String, String>> idpClaimMappings = extractIdPClaimMappings(idp);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Building mapped claims array from " + idpClaimMappings.size() +
                    " configured mappings. Incoming claims: " +
                    (incomingClaims.isEmpty() ? "none" : incomingClaims.keySet()));
        }

        List<Map<String, Object>> mappedClaimsArray = buildMappedClaimsArray(
                idpClaimMappings, incomingClaims);

        debugResult.put("mappedClaims", mappedClaimsArray);
        debugResult.put("idpConfiguredClaimMappings", idpClaimMappings);

        // Determine claim mapping status: FAILED if any configured mapping is not found.
        String claimMappingStatus = determineClaimMappingStatus(mappedClaimsArray, idpClaimMappings);
        context.setProperty(OIDCDebugConstants.STEP_CLAIM_MAPPING_STATUS, claimMappingStatus);
    }

    /**
     * Determines the claim mapping status based on whether all configured mappings
     * were found in incoming claims.
     * Returns FAILED if any configured claim mapping was not successfully mapped.
     *
     * @param mappedClaimsArray List of mapped claim entries.
     * @param idpClaimMappings IdP configured mappings.
     * @return STATUS_FAILED if any "Not Mapped" status found, STATUS_SUCCESS otherwise.
     */
    private String determineClaimMappingStatus(List<Map<String, Object>> mappedClaimsArray,
            Map<String, Map<String, String>> idpClaimMappings) {

        // If no configured mappings, status is success.
        if (idpClaimMappings.isEmpty()) {
            return OIDCDebugConstants.STATUS_SUCCESS;
        }

        // If any configured mapping is "Not Mapped", status is failed.
        for (Map<String, Object> claim : mappedClaimsArray) {
            String status = (String) claim.get(OIDCDebugConstants.CLAIM_MAPPING_STATUS);
            if ("Not Mapped".equals(status)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Claim mapping status set to FAILED due to unmapped claim: " +
                            claim.get(OIDCDebugConstants.CLAIM_MAPPING_IDP_CLAIM));
                }
                return OIDCDebugConstants.STATUS_FAILED;
            }
        }

        return OIDCDebugConstants.STATUS_SUCCESS;
    }

    /**
     * Builds the mapped claims array by processing configured mappings and
    * configured mappings.
     *
     * @param idpClaimMappings IdP configured claim mappings.
     * @param incomingClaims Incoming claims from tokens.
     * @return List of mapped claim entries with status information.
     */
    private List<Map<String, Object>> buildMappedClaimsArray(
            Map<String, Map<String, String>> idpClaimMappings, Map<String, Object> incomingClaims) {

        List<Map<String, Object>> mappedClaimsArray = new ArrayList<>();
        Set<String> processedClaims = new HashSet<>();

        // Process configured mappings.
        if (!idpClaimMappings.isEmpty()) {
            for (Map.Entry<String, Map<String, String>> mapping : idpClaimMappings.entrySet()) {
                String remoteClaimUri = mapping.getValue().get(OIDCDebugConstants.CLAIM_MAPPING_REMOTE);
                String localClaimUri = mapping.getValue().get(OIDCDebugConstants.CLAIM_MAPPING_LOCAL);

                Map<String, Object> claimEntry = processConfiguredMapping(
                        remoteClaimUri, localClaimUri, incomingClaims, processedClaims);
                mappedClaimsArray.add(claimEntry);
            }
        }

        return mappedClaimsArray;
    }

    /**
     * Processes a single configured claim mapping.
     *
     * @param remoteClaimUri Remote claim URI from IdP.
     * @param localClaimUri Local claim URI mapping.
     * @param incomingClaims Incoming claims from tokens.
     * @param processedClaims Set to track processed claim names.
     * @return Claim entry map with status and value information.
     */
    private Map<String, Object> processConfiguredMapping(String remoteClaimUri, String localClaimUri,
            Map<String, Object> incomingClaims, Set<String> processedClaims) {

        Map<String, Object> claimEntry = new HashMap<>();
        claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_IDP_CLAIM, remoteClaimUri != null ? remoteClaimUri : "");
        claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_LOCAL_CLAIM, localClaimUri != null ? localClaimUri : "");

        Object claimValue = null;
        String claimStatus = "Not Mapped";

        if (remoteClaimUri != null && incomingClaims.containsKey(remoteClaimUri)) {
            claimValue = incomingClaims.get(remoteClaimUri);
            claimStatus = "Successful";
            processedClaims.add(remoteClaimUri);
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

    /**
     * Builds user attributes map and step status information.
     *
     * @param incomingClaims Incoming claims.
     * @param debugResult Debug result to populate.
     * @param context AuthenticationContext.
     */
    private void buildUserAttributesAndMetadata(Map<String, Object> incomingClaims,
            Map<String, Object> debugResult, AuthenticationContext context) {

        // Build user attributes map.
        Map<String, Object> userAttributes = new HashMap<>();
        if (!incomingClaims.isEmpty()) {
            userAttributes.putAll(incomingClaims);
        }
        debugResult.put("userAttributes", userAttributes);

        // Add URLs and tokens.
        String externalRedirectUrl = (String) context.getProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
        debugResult.put("externalRedirectUrl", externalRedirectUrl);

        String idToken = (String) context.getProperty(OIDCDebugConstants.ID_TOKEN);
        debugResult.put("idToken", idToken);

        String callbackUrl = (String) context.getProperty(OIDCDebugConstants.REDIRECT_URI);
        debugResult.put("callbackUrl", callbackUrl);

        debugResult.put("error", null);
        debugResult.put("timestamp", null);

        debugResult.put(OIDCDebugConstants.STEP_STATUS, buildStepStatus(context));
    }

    /**
     * Persists debug result to cache with JSON serialization.
     *
     * @param state State parameter.
     * @param context AuthenticationContext.
     * @param debugResult Debug result to persist.
     */
    private void persistDebugResultToCache(String state, AuthenticationContext context,
            Map<String, Object> debugResult) {

        try {
            String debugResultJson = OBJECT_MAPPER.writeValueAsString(debugResult);

            // Cache in context.
            context.setProperty(DEBUG_RESULT_CACHE_KEY, debugResultJson);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, true);

            // Get context ID and persist to DebugResultCache.
            String contextId = (String) context.getProperty(OIDCDebugConstants.DEBUG_CONTEXT_ID);
            persistDebugResultToCache(state, contextId, debugResultJson);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Debug result cached and persisted for state: " + state);
            }
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            LOG.error("Failed to serialize debug result to JSON: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts claim mappings from IdP configuration.
     * Converts ClaimMapping objects to a map format for easier processing.
     *
     * @param idp The IdentityProvider configuration.
     * @return Map of claim mappings, empty if no mappings found.
     */
    private Map<String, Map<String, String>> extractIdPClaimMappings(IdentityProvider idp) {

        Map<String, Map<String, String>> mappings = new HashMap<>();

        if (!hasClaimMappings(idp)) {
            logNoClaimConfiguration();
            return mappings;
        }

        try {
            processClaimMappingsFromIdP(idp, mappings);
        } catch (Exception e) {
            logClaimMappingExtractionError(e);
        }

        return mappings;
    }

    /**
     * Checks if the IdP has valid claim mappings.
     *
     * @param idp The IdentityProvider configuration.
     * @return true if claim mappings exist and are valid, false otherwise.
     */
    private boolean hasClaimMappings(IdentityProvider idp) {

        return idp != null && idp.getClaimConfig() != null &&
                idp.getClaimConfig().getClaimMappings() != null;
    }

    /**
     * Logs when no claim configuration is found.
     */
    private void logNoClaimConfiguration() {

        if (LOG.isDebugEnabled()) {
            LOG.debug("No claim configuration found in IdP");
        }
    }

    /**
     * Processes claim mappings from IdP configuration and populates the mappings
     * map.
     *
     * @param idp The IdentityProvider configuration.
     * @param mappings Map to populate with extracted mappings.
     */
    private void processClaimMappingsFromIdP(IdentityProvider idp, Map<String, Map<String, String>> mappings) {

        ClaimMapping[] claimMappings = idp.getClaimConfig().getClaimMappings();
        for (int i = 0; i < claimMappings.length; i++) {
            processClaimMapping(claimMappings[i], i, mappings);
        }
    }

    /**
     * Processes a single claim mapping and adds it to the mappings map if valid.
     *
     * @param claimMapping The claim mapping to process.
     * @param index The index of the mapping in the array (used as fallback
     *               key).
     * @param mappings Map to add the processed mapping to.
     */
    private void processClaimMapping(ClaimMapping claimMapping, int index,
            Map<String, Map<String, String>> mappings) {

        if (!isValidClaimMapping(claimMapping)) {
            return;
        }

        String remoteClaimUri = claimMapping.getRemoteClaim().getClaimUri();
        String localClaimUri = claimMapping.getLocalClaim().getClaimUri();

        Map<String, String> mapping = buildClaimMappingEntry(remoteClaimUri, localClaimUri);
        String mappingKey = remoteClaimUri != null ? remoteClaimUri : ("claim_" + index);

        mappings.put(mappingKey, mapping);
        logClaimMappingExtracted(remoteClaimUri, localClaimUri);
    }

    /**
     * Validates if a claim mapping is complete and usable.
     *
     * @param claimMapping The claim mapping to validate.
     * @return true if all required parts are present, false otherwise.
     */
    private boolean isValidClaimMapping(ClaimMapping claimMapping) {

        return claimMapping != null && claimMapping.getRemoteClaim() != null &&
                claimMapping.getLocalClaim() != null;
    }

    /**
     * Builds a claim mapping entry with remote and local URIs.
     *
     * @param remoteClaimUri The remote claim URI.
     * @param localClaimUri The local claim URI.
     * @return Map with remote and local keys.
     */
    private Map<String, String> buildClaimMappingEntry(String remoteClaimUri, String localClaimUri) {

        Map<String, String> mapping = new HashMap<>();
        mapping.put(OIDCDebugConstants.CLAIM_MAPPING_REMOTE, remoteClaimUri);
        mapping.put(OIDCDebugConstants.CLAIM_MAPPING_LOCAL, localClaimUri);
        return mapping;
    }

    /**
     * Logs the extraction of a claim mapping.
     *
     * @param remoteClaimUri The remote claim URI.
     * @param localClaimUri  The local claim URI.
     */
    private void logClaimMappingExtracted(String remoteClaimUri, String localClaimUri) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Extracted claim mapping: " + remoteClaimUri + " -> " + localClaimUri);
        }
    }

    /**
     * Logs error during claim mapping extraction.
     *
     * @param e The exception that occurred.
     */
    private void logClaimMappingExtractionError(Exception e) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Error extracting claim mappings from IdP: " + e.getMessage());
        }
    }

    /**
     * Builds and caches token exchange error response with detailed error
     * information.
     * Formats error details for debug API response.
     * Persists to DebugResultCache for API retrieval.
     *
     * @param errorCode The error code from token exchange failure.
     * @param errorDescription The error description/message.
     * @param errorDetails Additional error details or stack trace.
     * @param state The state parameter for session identification.
     * @param context AuthenticationContext.
     */
    protected void buildAndCacheTokenExchangeErrorResponse(String errorCode, String errorDescription,
            String errorDetails, String state, AuthenticationContext context) {

        try {
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, Boolean.FALSE);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("state", state);
            errorResponse.put("success", false);
            errorResponse.put("error_code", errorCode);
            errorResponse.put("error_description", errorDescription);
            if (errorDetails != null && !errorDetails.isEmpty()) {
                errorResponse.put("error_details", errorDetails);
            }

            // Add external redirect URL if available.
            String externalRedirectUrl = (String) context.getProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
            if (externalRedirectUrl != null && !externalRedirectUrl.isEmpty()) {
                errorResponse.put("externalRedirectUrl", externalRedirectUrl);
            }

            errorResponse.put(OIDCDebugConstants.STEP_STATUS, buildStepStatus(context));

            String errorResponseJson = OBJECT_MAPPER.writeValueAsString(errorResponse);

            // Cache in context.
            context.setProperty(DEBUG_RESULT_CACHE_KEY, errorResponseJson);

            // Get context ID for dual-key caching.
            String contextId = (String) context.getProperty(OIDCDebugConstants.DEBUG_CONTEXT_ID);

            // Persist to DebugResultCache for API endpoint retrieval (with both state and
            // contextId as keys).
            persistDebugResultToCache(state, contextId, errorResponseJson);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Error response cached and persisted for state: " + state + " with error: " + errorCode);
            }

        } catch (Exception e) {
            LOG.error("Error building and caching error response: " + e.getMessage(), e);
        }
    }

    private Map<String, Object> buildStepStatus(AuthenticationContext context) {

        Map<String, Object> stepStatus = new LinkedHashMap<>();
        stepStatus.put(OIDCDebugConstants.STEP_CONNECTION_STATUS,
                resolveStepStatus(context, OIDCDebugConstants.STEP_CONNECTION_STATUS,
                        hasExternalRedirectUrl(context) ? OIDCDebugConstants.STATUS_SUCCESS
                                : OIDCDebugConstants.STATUS_PENDING));
        stepStatus.put(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS,
                resolveStepStatus(context, OIDCDebugConstants.STEP_AUTHENTICATION_STATUS,
                        isAuthenticationFailed(context) ? OIDCDebugConstants.STATUS_FAILED
                                : OIDCDebugConstants.STATUS_PENDING));
        stepStatus.put(OIDCDebugConstants.STEP_CLAIM_EXTRACTION_STATUS,
                resolveStepStatus(context, OIDCDebugConstants.STEP_CLAIM_EXTRACTION_STATUS,
                        OIDCDebugConstants.STATUS_PENDING));
        stepStatus.put(OIDCDebugConstants.STEP_CLAIM_MAPPING_STATUS,
                resolveStepStatus(context, OIDCDebugConstants.STEP_CLAIM_MAPPING_STATUS,
                        OIDCDebugConstants.STATUS_PENDING));
        return stepStatus;
    }

    /**
     * Determines overall success status based on individual step statuses.
     * Sets the top-level "status" to FAILED if any step has FAILED status.
     *
     * @param debugResult Debug result map containing stepStatus.
     * @param context AuthenticationContext.
     */
    @SuppressWarnings("unchecked")
    private void determineOverallSuccessStatus(Map<String, Object> debugResult, AuthenticationContext context) {

        Map<String, Object> stepStatus = (Map<String, Object>) debugResult.get(OIDCDebugConstants.STEP_STATUS);
        if (stepStatus == null) {
            return;
        }

        // If any step status is FAILED, overall status is FAILED.
        boolean hasFailedStep = stepStatus.values().stream()
                .anyMatch(status -> OIDCDebugConstants.STATUS_FAILED.equals(status));

        if (hasFailedStep) {
            debugResult.put(OIDCDebugConstants.DEBUG_RESULT_SUCCESS, false);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Overall debug status set to FAILED due to failed step: " + stepStatus);
            }
        } else {
            debugResult.put(OIDCDebugConstants.DEBUG_RESULT_SUCCESS, true);
        }
    }

    private Object resolveStepStatus(AuthenticationContext context, String stepKey, String fallbackStatus) {

        Object stepStatus = context.getProperty(stepKey);
        if (stepStatus instanceof String && StringUtils.isNotBlank((String) stepStatus)) {
            return stepStatus;
        }
        return fallbackStatus;
    }

    private boolean hasExternalRedirectUrl(AuthenticationContext context) {

        Object externalRedirectUrl = context.getProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
        return externalRedirectUrl instanceof String && StringUtils.isNotBlank((String) externalRedirectUrl);
    }

    private boolean isAuthenticationFailed(AuthenticationContext context) {

        Object authSuccess = context.getProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS);
        return authSuccess instanceof Boolean && !((Boolean) authSuccess);
    }

    /**
     * Persists debug result to DebugResultCache.
     * The result can then be retrieved via the GET /debug/result/{session-id}
     * endpoint.
     * Caches under both state and contextId to support flexible lookups.
     *
     * @param state The state parameter (primary cache key).
     * @param contextId The context ID/session ID (alternate cache key).
     * @param resultJson The JSON-serialized debug result to cache.
     */
    private void persistDebugResultToCache(String state, String contextId, String resultJson) {

        try {
            DebugSessionCache.getInstance().putResult(state, resultJson);
            if (contextId != null && !contextId.equals(state)) {
                DebugSessionCache.getInstance().putResult(contextId, resultJson);
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
     * Redirects to the debug success page after processing.
     * Sends HTTP redirect response with cached debug result.
     * Only allows redirects to the known debug success JSP path.
     *
     * @param response HttpServletResponse for sending the redirect.
     * @param state The state parameter for session identification.
     * @param idpId The IdP resource ID.
     * @throws IOException If response fails.
     */
    @Override
    protected void sendDebugResponse(HttpServletResponse response, String state, String idpId) throws IOException {

        if (!response.isCommitted()) {
            String encodedState = encodeForUrl(state);
            String encodedIdpId = encodeForUrl(idpId);

            // Validate encoded parameters are not empty (encoding succeeded).
            if (encodedState.isEmpty() && state != null && !state.isEmpty()) {
                LOG.error("Failed to encode state parameter for redirect, aborting redirect.");
                return;
            }

            // Construct redirect URL using a fixed path to prevent open redirect.
            String redirectUrl = "/authenticationendpoint/debugSuccess.jsp?state=" + encodedState +
                    "&idpId=" + encodedIdpId;
            response.sendRedirect(redirectUrl);
        }
    }

    /**
     * Restores context properties from DebugSessionCache using state parameter.
     * Transfers cached properties to AuthenticationContext for use in callback
     * processing.
     *
     * @param state State parameter (cache key).
     * @param context AuthenticationContext to populate.
     */
    private void restoreContextFromSessionCache(String state, AuthenticationContext context) {

        try {
            Map<String, Object> cachedContext = DebugSessionCache.getInstance().get(state);
            if (cachedContext == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No cached context found for state: " + state);
                }
                return;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Restoring context from DebugSessionCache for state: " + state);
            }
            restorePropertiesToContext(cachedContext, context);

        } catch (Exception e) {
            LOG.debug("Unable to restore context from DebugSessionCache: " + e.getMessage());
        }
    }

    /**
     * Restores individual properties from cached context to authentication context.
     *
     * @param cachedContext The cached context map.
     * @param context       The authentication context to populate.
     */
    private void restorePropertiesToContext(Map<String, Object> cachedContext, AuthenticationContext context) {

        String[] propertiesToRestore = {
                OIDCDebugConstants.TOKEN_ENDPOINT, OIDCDebugConstants.CLIENT_ID, OIDCDebugConstants.CLIENT_SECRET,
                OIDCDebugConstants.USERINFO_ENDPOINT, OIDCDebugConstants.DEBUG_CODE_VERIFIER,
                OIDCDebugConstants.REDIRECT_URI,
                OIDCDebugConstants.DEBUG_IDP_NAME, OIDCDebugConstants.IDP_CONFIG,
                OIDCDebugConstants.AUTHORIZATION_ENDPOINT,
                OIDCDebugConstants.DEBUG_CONTEXT_ID, OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL,
                OIDCDebugConstants.ACCESS_TOKEN, OIDCDebugConstants.ID_TOKEN, OIDCDebugConstants.TOKEN_TYPE,
                OIDCDebugConstants.USERINFO
        };

        for (String property : propertiesToRestore) {
            restorePropertyIfPresent(cachedContext, context, property);
        }
    }

    /**
     * Restores a single property from cached context if it exists.
     *
     * @param cachedContext The cached context map.
     * @param context The authentication context to populate.
     * @param property The property name to restore.
     */
    private void restorePropertyIfPresent(Map<String, Object> cachedContext, AuthenticationContext context,
            String property) {

        Object value = cachedContext.get(property);
        if (value != null) {
            context.setProperty(property, value);
        }
    }

    /**
     * URL-encodes a parameter for safe use in HTTP redirects.
     * Prevents XSS and injection vulnerabilities.
     * Returns empty string on encoding failure to prevent injection.
     *
     * @param param Parameter to encode.
     * @return URL-encoded parameter, or empty string on failure.
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
