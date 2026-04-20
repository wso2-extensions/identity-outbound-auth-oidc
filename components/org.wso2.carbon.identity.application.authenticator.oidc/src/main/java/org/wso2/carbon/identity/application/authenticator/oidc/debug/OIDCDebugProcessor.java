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
import org.wso2.carbon.identity.application.common.model.AccountLookupAttributeMappingConfig;
import org.wso2.carbon.identity.debug.framework.cache.DebugSessionCache;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.OAuth2TokenClient;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.TokenResponse;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.UrlConnectionHttpFetcher;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCDebugDiagnosticsUtil;
import org.wso2.carbon.identity.debug.framework.core.DebugProcessor;

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
        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CALLBACK_VALIDATION,
                OIDCDebugConstants.STATUS_STARTED, "Validating OIDC callback parameters.");

        // Store IdP ID in context for fallback resolution during token exchange.
        if (StringUtils.isNotEmpty(idpId)) {
            context.setProperty(OIDCDebugConstants.DEBUG_IDP_NAME, idpId);
        }

        // Handle OIDC error responses.
        if (error != null) {
            LOG.error("OIDC error from IdP: " + error + " - " + errorDescription);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, error + ": " + errorDescription);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CALLBACK_VALIDATION,
                    OIDCDebugConstants.STATUS_FAILED, "OIDC callback returned an error response.",
                    buildErrorDetails(error, errorDescription));
            buildAndCacheTokenExchangeErrorResponse(error, errorDescription, "", state, context);
            return false;
        }

        // Validate authorization code presence.
        if (code == null || code.trim().isEmpty()) {
            LOG.error("Authorization code missing in OIDC callback");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Authorization code not received");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CALLBACK_VALIDATION,
                    OIDCDebugConstants.STATUS_FAILED, "Authorization code is missing in the callback.");
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
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CALLBACK_VALIDATION,
                    OIDCDebugConstants.STATUS_FAILED, "State parameter is missing in the callback.");
            buildAndCacheTokenExchangeErrorResponse("NO_STATE",
                    "State parameter missing - possible CSRF attack", "", state, context);
            return false;
        }

    // Validate callback correlation value against the debug identifier.
    String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_CONTEXT_ID);
    if (debugId != null && !state.equals(debugId)) {
            LOG.error("State parameter mismatch - CSRF attack detected");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR,
                    "State validation failed - possible CSRF attack");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CALLBACK_VALIDATION,
                    OIDCDebugConstants.STATUS_FAILED, "State parameter validation failed.",
            buildErrorDetails("STATE_MISMATCH", "Received state does not match debug identifier."));
            buildAndCacheTokenExchangeErrorResponse("STATE_MISMATCH",
                    "State validation failed - possible CSRF attack", "", state, context);
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("OIDC callback validation passed for state: " + state);
        }
        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CALLBACK_VALIDATION,
                OIDCDebugConstants.STATUS_SUCCESS, "OIDC callback parameters validated successfully.");

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
        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_STARTED, "Starting OIDC token exchange.");

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
                context.setProperty(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS, OIDCDebugConstants.STATUS_FAILED);
                context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
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
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_FAILED, "OIDC token exchange failed with an exception.",
                    buildErrorDetails("TOKEN_EXCHANGE_ERROR", e.getMessage()));
            context.setProperty(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS, OIDCDebugConstants.STATUS_FAILED);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Token exchange error: " + e.getMessage());
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("TOKEN_EXCHANGE_ERROR",
                    "Token exchange error: " + e.getMessage(), e.toString(), state, context);
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
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_FAILED, "Identity Provider configuration was not found.");
            buildAndCacheTokenExchangeErrorResponse("IDP_CONFIG_MISSING",
                    "Identity Provider configuration not found", "", state, context);
            return false;
        }

        if (code == null || code.trim().isEmpty()) {
            LOG.error("Authorization code missing in OIDC callback");
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_FAILED, "Authorization code is missing for token exchange.");
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
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_FAILED, "Token endpoint is not configured for the IdP.");
            buildAndCacheTokenExchangeErrorResponse("TOKEN_ENDPOINT_MISSING",
                    "Token endpoint is not configured", "", state, context);
        }

        if (config.getClientId() == null || config.getClientId().trim().isEmpty()) {
            LOG.error("Client ID not found in context or IdP configuration");
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_FAILED, "Client ID is not configured for the IdP.");
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
        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_FAILED, "OIDC token exchange failed.",
                buildTokenExchangeFailureDetails(config, errorCode, errorDesc));

        markContextAsFailedExchange(context, errorDesc);
        buildAndCacheTokenExchangeErrorResponse(errorCode, errorDesc, errorDetails, state, context);

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
        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_SUCCESS, "OIDC token exchange completed successfully.",
                buildTokenExchangeSuccessDetails(tokenResponse, config));
        logTokenExchangeSuccess(tokenResponse, config);
        return true;
    }

    /**
     * Marks the authentication context as successful exchange.
     *
     * @param context AuthenticationContext.
     */
    private void markContextAsSuccessfulExchange(AuthenticationContext context) {

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
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                    OIDCDebugConstants.STATUS_STARTED, "Extracting claims from OIDC tokens.");
            // Extract and validate ID token.
            String idToken = (String) context.getProperty(OIDCDebugConstants.ID_TOKEN);
            if (!isValidIdToken(idToken)) {
                OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                        OIDCDebugConstants.STATUS_FAILED, "ID token is not available for claim extraction.");
                return new HashMap<>();
            }

            // Parse ID token to extract initial claims.
            Map<String, Object> claims = parseIdTokenClaims(idToken);

            // Validate nonce claim against value generated in authorization request.
            if (!isValidNonceClaim(context, claims)) {
                OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                        OIDCDebugConstants.STATUS_FAILED,
                        "ID token nonce claim validation failed.",
                        buildErrorDetails("NONCE_VALIDATION_FAILED",
                                "ID token nonce claim is missing or does not match the original request nonce."));
                return new HashMap<>();
            }

            // Attempt to merge with UserInfo endpoint claims if available.
            mergeUserInfoClaims(context, claims);

            // Return extracted claims or empty map if none found.
            return returnExtractedClaims(claims, context);

        } catch (Exception e) {
            LOG.error("Error extracting user claims from OIDC tokens: " + e.getMessage(), e);
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                    OIDCDebugConstants.STATUS_FAILED, "Error extracting claims from OIDC tokens.",
                    buildErrorDetails("CLAIM_EXTRACTION_ERROR", e.getMessage()));
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
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                    OIDCDebugConstants.STATUS_SUCCESS, "Claims extracted successfully from OIDC tokens.",
                    buildClaimExtractionDetails(claims, context));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully extracted " + claims.size() + " claims from tokens: " + claims.keySet());
            }
            return claims;
        }

        context.setProperty(OIDCDebugConstants.STEP_CLAIM_EXTRACTION_STATUS, OIDCDebugConstants.STATUS_FAILED);
        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                OIDCDebugConstants.STATUS_FAILED, "No claims could be extracted from the OIDC tokens.");
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
     * Validates the nonce claim in the ID token claims map against expected nonce from context.
     *
     * @param context Authentication context holding expected nonce.
     * @param claims ID token claims.
     * @return true if nonce is valid, false otherwise.
     */
    private boolean isValidNonceClaim(AuthenticationContext context, Map<String, Object> claims) {

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

        Object tokenNonceObj = claims.get("nonce");
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

        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_VALIDATION,
                OIDCDebugConstants.STATUS_STARTED, "Validating extracted claims for required user identifiers.");

        if (claims == null || claims.isEmpty()) {
            LOG.error("No claims extracted from OIDC tokens");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "No user claims extracted from IdP");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_VALIDATION,
                    OIDCDebugConstants.STATUS_FAILED, "No claims are available to validate.");
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
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_VALIDATION,
                    OIDCDebugConstants.STATUS_FAILED,
                    "Required user identifier claim is missing from the extracted claims.");
            buildAndCacheTokenExchangeErrorResponse("NO_USER_IDENTIFIER",
                    "User identifier (sub/user_id/email) not found in claims", "", state, context);
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Claims extraction validation passed. Claims found: " + claims.keySet());
        }
        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_VALIDATION,
                OIDCDebugConstants.STATUS_SUCCESS, "Extracted claims passed validation.",
                buildClaimValidationDetails(claims));

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
            Map<String, Object> debugResult = new HashMap<>();
            debugResult.put(OIDCDebugConstants.DEBUG_RESULT_SUCCESS, true);
            Map<String, Object> incomingClaims = extractIncomingClaims(context);
            processClaimMappings(context, incomingClaims, debugResult);
            evaluateAccountLinking(context, incomingClaims);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, Boolean.TRUE);
            buildResultMetadata(debugResult, context);
            determineOverallSuccessStatus(debugResult, context);
            
            persistDebugResultToCache(state, context, debugResult);

        } catch (Exception e) {
            LOG.error("Error building and caching debug result: " + e.getMessage(), e);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Error caching debug result: " + e.getMessage());
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
        }
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
     * Processes claim mappings from IdP configuration.
     *
     * @param context AuthenticationContext.
     * @param incomingClaims Incoming claims map.
     * @param debugResult Debug result map to populate.
     */
    private void processClaimMappings(AuthenticationContext context,
            Map<String, Object> incomingClaims, Map<String, Object> debugResult) {

        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_MAPPING,
                OIDCDebugConstants.STATUS_STARTED, "Processing configured claim mappings.");
        IdentityProvider idp = deserializeIdentityProvider(context.getProperty(OIDCDebugConstants.IDP_CONFIG));
        Map<String, Map<String, String>> idpClaimMappings = extractIdPClaimMappings(idp);
        Map<String, Object> normalizedClaims = normalizeIncomingClaimsForDebug(incomingClaims);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Building mapped claims array from " + idpClaimMappings.size() +
                    " configured mappings. Incoming claims: " +
                    (normalizedClaims.isEmpty() ? "none" : normalizedClaims.keySet()));
        }

        List<Map<String, Object>> mappedClaimsArray = buildMappedClaimsArray(
                idpClaimMappings, normalizedClaims);

        debugResult.put("mappedClaims", mappedClaimsArray);

        // Determine claim mapping status: SUCCESS if all mappings succeed and PARTIAL
        // for any incomplete mapping outcome.
        String claimMappingStatus = determineClaimMappingStatus(mappedClaimsArray, idpClaimMappings);
        context.setProperty(OIDCDebugConstants.STEP_CLAIM_MAPPING_STATUS, claimMappingStatus);
        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_MAPPING, claimMappingStatus,
                "Claim mapping processing completed.",
                buildClaimMappingDetails(mappedClaimsArray, idpClaimMappings));
    }

    /**
     * Determines the claim mapping status based on whether all configured mappings
     * were found in incoming claims.
     * Returns SUCCESS if all configured mappings were resolved and PARTIAL for any
     * incomplete mapping outcome.
     *
     * @param mappedClaimsArray List of mapped claim entries.
     * @param idpClaimMappings IdP configured mappings.
     * @return Claim mapping step status.
     */
    private String determineClaimMappingStatus(List<Map<String, Object>> mappedClaimsArray,
            Map<String, Map<String, String>> idpClaimMappings) {

        // If no configured mappings, status is success.
        if (idpClaimMappings.isEmpty()) {
            return OIDCDebugConstants.STATUS_SUCCESS;
        }

        int mappedCount = 0;
        int unmappedCount = 0;
        for (Map<String, Object> claim : mappedClaimsArray) {
            String status = (String) claim.get(OIDCDebugConstants.CLAIM_MAPPING_STATUS);
            if ("Successful".equals(status)) {
                mappedCount++;
            } else if ("Not Mapped".equals(status)) {
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

        // Process configured mappings.
        if (!idpClaimMappings.isEmpty()) {
            for (Map.Entry<String, Map<String, String>> mapping : idpClaimMappings.entrySet()) {
                String remoteClaimUri = mapping.getValue().get(OIDCDebugConstants.CLAIM_MAPPING_REMOTE);
                String localClaimUri = mapping.getValue().get(OIDCDebugConstants.CLAIM_MAPPING_LOCAL);

                Map<String, Object> claimEntry = processConfiguredMapping(
                        remoteClaimUri, localClaimUri, incomingClaims);
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
     * @return Claim entry map with status and value information.
     */
    private Map<String, Object> processConfiguredMapping(String remoteClaimUri, String localClaimUri,
            Map<String, Object> incomingClaims) {

        Map<String, Object> claimEntry = new HashMap<>();
        claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_IDP_CLAIM, remoteClaimUri != null ? remoteClaimUri : "");
        claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_LOCAL_CLAIM, localClaimUri != null ? localClaimUri : "");

        Object claimValue = null;
        String claimStatus = "Not Mapped";

        if (remoteClaimUri != null && incomingClaims.containsKey(remoteClaimUri)) {
            claimValue = incomingClaims.get(remoteClaimUri);
            claimStatus = "Successful";
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
     * Builds debug result metadata and step status information.
     *
     * @param debugResult Debug result to populate.
     * @param context AuthenticationContext.
     */
    private void buildResultMetadata(Map<String, Object> debugResult, AuthenticationContext context) {

        // Add URLs and tokens.
        String externalRedirectUrl = (String) context.getProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
        debugResult.put("externalRedirectUrl", externalRedirectUrl);

        String idToken = resolveIdTokenFromContext(context);
        debugResult.put(OIDCDebugConstants.DEBUG_RESULT_ID_TOKEN_PRESENT, StringUtils.isNotBlank(idToken));
        if (StringUtils.isNotBlank(idToken)) {
            debugResult.put(OIDCDebugConstants.ID_TOKEN, idToken);
        }

        String callbackUrl = (String) context.getProperty(OIDCDebugConstants.REDIRECT_URI);
        debugResult.put("callbackUrl", callbackUrl);

        debugResult.put(OIDCDebugConstants.STEP_STATUS, buildStepStatus(context));
        debugResult.put(OIDCDebugConstants.DEBUG_DIAGNOSTICS, OIDCDebugDiagnosticsUtil.getDiagnostics(context));
    }

    /**
     * Resolves ID token from context using primary and fallback keys.
     *
     * @param context AuthenticationContext.
     * @return ID token value, or null if unavailable.
     */
    private String resolveIdTokenFromContext(AuthenticationContext context) {

        String idToken = (String) context.getProperty(OIDCDebugConstants.ID_TOKEN);
        if (StringUtils.isNotBlank(idToken)) {
            return idToken;
        }

        Object fallbackIdToken = context.getProperty(OIDCDebugConstants.DEBUG_ID_TOKEN);
        return fallbackIdToken != null ? String.valueOf(fallbackIdToken) : null;
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
            errorResponse.put("success", false);
            errorResponse.put("error_code", errorCode);
            errorResponse.put("error_description", resolveErrorDescription(errorDescription, errorDetails));

            // Add external redirect URL if available.
            String externalRedirectUrl = (String) context.getProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
            if (externalRedirectUrl != null && !externalRedirectUrl.isEmpty()) {
                errorResponse.put("externalRedirectUrl", externalRedirectUrl);
            }

            errorResponse.put(OIDCDebugConstants.STEP_STATUS, buildStepStatus(context));
            errorResponse.put(OIDCDebugConstants.DEBUG_DIAGNOSTICS, OIDCDebugDiagnosticsUtil.getDiagnostics(context));

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

    private String resolveErrorDescription(String errorDescription, String errorDetails) {

        if (StringUtils.isBlank(errorDetails)) {
            return errorDescription;
        }
        return errorDetails;
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
        if (isAccountLinkingEnabled(context)) {
            stepStatus.put(OIDCDebugConstants.STEP_ACCOUNT_LINKING_STATUS,
                    resolveAccountLinkingStatus(context));
        }
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

    private String resolveAccountLinkingStatus(AuthenticationContext context) {

        Object accountLinkingStatus = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS);
        if (accountLinkingStatus instanceof String && StringUtils.isNotBlank((String) accountLinkingStatus)) {
            return (String) accountLinkingStatus;
        }

        return OIDCDebugConstants.STATUS_PENDING;
    }

    private String resolveAccountLinkingMessage(AuthenticationContext context) {

        Object accountLinkingMessage = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE);
        if (accountLinkingMessage instanceof String && StringUtils.isNotBlank((String) accountLinkingMessage)) {
            return (String) accountLinkingMessage;
        }

        if (OIDCDebugConstants.STATUS_FAILED.equals(resolveAccountLinkingStatus(context))) {
            return "Account linking attribute validation failed.";
        }

        return null;
    }

    private void evaluateAccountLinking(AuthenticationContext context, Map<String, Object> incomingClaims) {

        if (!isAccountLinkingEnabled(context)
                || hasResolvedAccountLinkingStatus(context)) {
            return;
        }

        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                OIDCDebugConstants.STATUS_STARTED, "Evaluating account linking attributes.");

        IdentityProvider idp = deserializeIdentityProvider(context.getProperty(OIDCDebugConstants.IDP_CONFIG));
        if (idp == null || idp.getJustInTimeProvisioningConfig() == null) {
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                    OIDCDebugConstants.STATUS_PENDING, "Account linking configuration is not available.",
                    buildAccountLinkingDetails(context));
            return;
        }

        Map<String, Object> normalizedClaims = normalizeIncomingClaimsForDebug(incomingClaims);
        AccountLookupAttributeMappingConfig[] accountLookupMappings =
                idp.getJustInTimeProvisioningConfig().getAccountLookupAttributeMappings();
        if (accountLookupMappings == null || accountLookupMappings.length == 0) {
            evaluateDefaultAccountLinkingAttribute(context, normalizedClaims);
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                    resolveAccountLinkingStatus(context), "Default account linking attribute evaluation completed.",
                    buildAccountLinkingDetails(context));
            return;
        }

        evaluateConfiguredAccountLinkingAttributes(context, normalizedClaims, accountLookupMappings);
        OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                resolveAccountLinkingStatus(context), "Configured account linking attribute evaluation completed.",
                buildAccountLinkingDetails(context));
    }

    private Map<String, Object> buildAccountLinkingDetails(AuthenticationContext context) {

        Map<String, Object> details = new LinkedHashMap<>();

        String accountLinkingMessage = resolveAccountLinkingMessage(context);
        if (StringUtils.isNotBlank(accountLinkingMessage)) {
            details.put(OIDCDebugConstants.ACCOUNT_LINKING_REASON, accountLinkingMessage);
        }
        return details;
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

    @SuppressWarnings("unchecked")
    private void addAddressScopeClaims(Map<String, Object> incomingClaims, Map<String, Object> normalizedClaims) {

        Object addressClaim = incomingClaims.get("address");
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

    private void evaluateDefaultAccountLinkingAttribute(AuthenticationContext context,
            Map<String, Object> incomingClaims) {

        String email = getStringClaim(incomingClaims, "email");
        if (StringUtils.isBlank(email)) {
            setAccountLinkingFailure(context, "\"email\" is missing.");
            return;
        }

        setAccountLinkingSuccess(context);
    }

    private void evaluateConfiguredAccountLinkingAttributes(AuthenticationContext context,
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

    private boolean hasResolvedAccountLinkingStatus(AuthenticationContext context) {

        Object accountLinkingStatus = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS);
        return accountLinkingStatus instanceof String && StringUtils.isNotBlank((String) accountLinkingStatus);
    }

    private void setAccountLinkingSuccess(AuthenticationContext context) {

        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE, null);
    }

    private void setAccountLinkingFailure(AuthenticationContext context, String message) {

        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS, OIDCDebugConstants.STATUS_FAILED);
        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE, message);
    }

    private String buildMissingAccountLinkingAttributeMessage(AccountLookupAttributeMappingConfig mappingConfig) {

        String federatedAttribute = mappingConfig.getFederatedAttribute();
        String localAttribute = mappingConfig.getLocalAttribute();

        if (StringUtils.isNotBlank(localAttribute)) {
            return "Required IdP attribute '" + federatedAttribute + "' is missing for account linking to local " +
                    "attribute '" + localAttribute + "'.";
        }

        return "Required IdP attribute '" + federatedAttribute + "' is missing for account linking.";
    }

    private String getStringClaim(Map<String, Object> incomingClaims, String claimName) {

        Object claimValue = incomingClaims.get(claimName);
        return claimValue instanceof String ? (String) claimValue : null;
    }

    private boolean isAccountLinkingEnabled(AuthenticationContext context) {

        IdentityProvider idp = deserializeIdentityProvider(context.getProperty(OIDCDebugConstants.IDP_CONFIG));
        if (idp == null) {
            return false;
        }

        JustInTimeProvisioningConfig jitProvisioningConfig = idp.getJustInTimeProvisioningConfig();
        return jitProvisioningConfig != null && jitProvisioningConfig.isProvisioningEnabled()
                && jitProvisioningConfig.isAssociateLocalUserEnabled();
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
                OIDCDebugConstants.DEBUG_AUTHENTICATOR_NAME, OIDCDebugConstants.DEBUG_EXECUTOR_CLASS,
                OIDCDebugConstants.IDP_SCOPE,
                OIDCDebugConstants.STEP_CONNECTION_STATUS, OIDCDebugConstants.STEP_AUTHENTICATION_STATUS,
                OIDCDebugConstants.STEP_CLAIM_EXTRACTION_STATUS, OIDCDebugConstants.STEP_CLAIM_MAPPING_STATUS,
                OIDCDebugConstants.STEP_ACCOUNT_LINKING_STATUS, OIDCDebugConstants.DEBUG_DIAGNOSTICS,
                OIDCDebugConstants.ACCESS_TOKEN, OIDCDebugConstants.ID_TOKEN, OIDCDebugConstants.TOKEN_TYPE,
        OIDCDebugConstants.USERINFO, OIDCDebugConstants.CONTEXT_PROTOCOL
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

    private Map<String, Object> buildErrorDetails(String errorCode, String errorDescription) {

        Map<String, Object> details = new LinkedHashMap<>();
        if (StringUtils.isNotBlank(errorCode)) {
            details.put("errorCode", errorCode);
        }
        if (StringUtils.isNotBlank(errorDescription)) {
            details.put("errorDescription", errorDescription);
        }
        return details;
    }

    private Map<String, Object> buildTokenExchangeFailureDetails(OIDCConfiguration config, String errorCode,
            String errorDescription) {

        Map<String, Object> details = buildErrorDetails(errorCode, errorDescription);
        details.put("idpName", config.getIdpName());
        details.put("tokenEndpoint", config.getTokenEndpoint());
        return details;
    }

    private Map<String, Object> buildTokenExchangeSuccessDetails(TokenResponse tokenResponse,
            OIDCConfiguration config) {

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("idpName", config.getIdpName());
        details.put("accessTokenPresent", StringUtils.isNotBlank(tokenResponse.getAccessToken()));
        details.put("idTokenPresent", StringUtils.isNotBlank(tokenResponse.getIdToken()));
        details.put("tokenType", tokenResponse.getTokenType());
        return details;
    }

    private Map<String, Object> buildClaimExtractionDetails(Map<String, Object> claims,
            AuthenticationContext context) {

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("claimCount", claims.size());
        details.put("userInfoCalled",
                Boolean.parseBoolean(String.valueOf(context.getProperty(OIDCDebugConstants.DEBUG_USERINFO_CALLED))));
        details.put("claimNames", new ArrayList<>(claims.keySet()));
        return details;
    }

    private Map<String, Object> buildClaimValidationDetails(Map<String, Object> claims) {

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("claimCount", claims.size());
        details.put("hasSub", claims.containsKey("sub"));
        details.put("hasEmail", claims.containsKey("email"));
        return details;
    }

    private Map<String, Object> buildClaimMappingDetails(List<Map<String, Object>> mappedClaimsArray,
            Map<String, Map<String, String>> idpClaimMappings) {

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("configuredMappings", idpClaimMappings.size());
        details.put("mappedClaimEntries", mappedClaimsArray.size());
        long successfulMappings = mappedClaimsArray.stream()
                .filter(claim -> "Successful".equals(claim.get(OIDCDebugConstants.CLAIM_MAPPING_STATUS)))
                .count();
        details.put("successfulMappings", successfulMappings);
        return details;
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
