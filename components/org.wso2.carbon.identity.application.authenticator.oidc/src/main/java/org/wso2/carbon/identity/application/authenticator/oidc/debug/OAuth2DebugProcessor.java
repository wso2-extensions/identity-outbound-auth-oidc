/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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
import org.wso2.carbon.identity.debug.framework.cache.DebugSessionCache;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.OAuth2TokenClient;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.TokenResponse;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.UrlConnectionHttpFetcher;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OAuth2ConfigurationExtractor;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.debug.framework.cache.DebugResultCache;
import org.wso2.carbon.identity.debug.framework.extension.DebugProcessor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OAuth2-specific implementation of abstract DebugProcessor.
 * Implements only protocol-specific OAuth2 logic.
 * All generic logic is inherited from DebugProcessor base class.
 *
 * Protocol-specific methods implemented:
 * - validateProtocolCallback(): OAuth2 callback validation (code, error, state)
 * - exchangeAuthorizationForTokens(): Authorization code to token exchange
 * - isOAuth2Authenticator(), isTokenEndpointProperty(), etc.: OAuth2 helpers
 *
 * Generic methods inherited from DebugProcessor:
 * - extractUserClaimsFromTokens(): ID token parsing (JWT)
 * - createAuthenticatedUser(): User creation with claim mapping
 * - processCallback(): Template method orchestration
 * - parseIdTokenClaims(), parseJsonPayload(), mapClaimsToAttributes(): Generic
 * parsing/mapping
 */
public class OAuth2DebugProcessor extends DebugProcessor {

    private static final Log LOG = LogFactory.getLog(OAuth2DebugProcessor.class);
    private static final com.fasterxml.jackson.databind.ObjectMapper OBJECT_MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();

    // Context property keys used for caching debug results.
    private static final String DEBUG_RESULT_CACHE_KEY = "DEBUG_RESULT_CACHE";
    private static final String DEBUG_AUTH_SUCCESS_KEY = "DEBUG_AUTH_SUCCESS";

    /**
     * Validates OAuth2-specific callback parameters.
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

        // Handle OAuth2 error responses.
        if (error != null) {
            LOG.error("OAuth2 error from IdP: " + error + " - " + errorDescription);
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_ERROR, error + ": " + errorDescription);
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse(error, errorDescription, "", state, context);
            return false;
        }

        // Validate authorization code presence.
        if (code == null || code.trim().isEmpty()) {
            LOG.error("Authorization code missing in OAuth2 callback");
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_ERROR, "Authorization code not received");
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("NO_CODE",
                    "Authorization code not received from IdP", "", state, context);
            return false;
        }

        // Validate state parameter.
        if (state == null || state.trim().isEmpty()) {
            LOG.error("State parameter missing in OAuth2 callback");
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_ERROR,
                    "State parameter missing - possible CSRF attack");
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("NO_STATE",
                    "State parameter missing - possible CSRF attack", "", state, context);
            return false;
        }

        // Validate state matches stored value if available.
        String storedState = (String) context.getProperty(OAuth2DebugConstants.DEBUG_STATE);
        if (storedState != null && !state.equals(storedState)) {
            LOG.error("State parameter mismatch - CSRF attack detected");
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_ERROR,
                    "State validation failed - possible CSRF attack");
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("STATE_MISMATCH",
                    "State validation failed - possible CSRF attack", "", state, context);
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("OAuth2 callback validation passed for state: " + state);
        }

        return true;
    }

    /**
     * Exchanges OAuth2 authorization code for tokens (access token + ID token).
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
            LOG.debug("=== Starting OAuth2 Token Exchange ===");
            LOG.debug("Authorization Code: " + (code != null && !code.isEmpty() ? OAuth2DebugConstants.STATUS_PRESENT
                    : OAuth2DebugConstants.STATUS_ABSENT));
            LOG.debug("State: " + state);
            LOG.debug("IdP ID: " + idpId);
        }

        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Exchanging authorization code for OAuth2 tokens. Code present: " + (code != null));
            }

            // Validate prerequisites.
            if (!validateAndExtractPrerequisites(code, state, context)) {
                LOG.error("Token exchange failed: Prerequisites validation failed");
                context.setProperty(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                return false;
            }

            // Extract configuration from IdP and context.
            OAuth2Configuration config = extractOAuth2Configuration(context, request);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Extracted OAuth2 Configuration:");
                LOG.debug("  IdP Name: " + config.getIdpName());
                LOG.debug("  Token Endpoint: " + config.getTokenEndpoint());
                LOG.debug("  Client ID: " + (config.getClientId() != null ? OAuth2DebugConstants.STATUS_PRESENT
                        : OAuth2DebugConstants.STATUS_ABSENT));
                LOG.debug("  Client Secret: " + (config.getClientSecret() != null ? OAuth2DebugConstants.STATUS_PRESENT
                        : OAuth2DebugConstants.STATUS_ABSENT));
                LOG.debug("  Callback URL: " + config.getCallbackUrl());
            }

            if (!config.isValid()) {
                LOG.error("Token exchange failed: OAuth2 configuration is invalid");
                handleConfigurationError(config, state, context);
                return false;
            }

            // Perform token exchange.
            return performTokenExchange(code, config, state, context);

        } catch (Exception e) {
            LOG.error("Exception during OAuth2 token exchange: " + e.getMessage(), e);
            buildAndCacheTokenExchangeErrorResponse("TOKEN_EXCHANGE_ERROR",
                    "Token exchange error: " + e.getMessage(), e.toString(), state, context);
            context.setProperty(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
            context.setProperty(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_ERROR, "Token exchange error: " + e.getMessage());
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_SUCCESS, false);
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

        IdentityProvider idp = (IdentityProvider) context.getProperty(OAuth2DebugConstants.IDP_CONFIG);

        // Try to restore properties from session cache if IDP_CONFIG not found
        if (idp == null) {
            restoreContextFromSessionCache(state, context);
            idp = (IdentityProvider) context.getProperty(OAuth2DebugConstants.IDP_CONFIG);
        }

        if (idp == null) {
            LOG.error("IdP configuration not found in context");
            buildAndCacheTokenExchangeErrorResponse("IDP_CONFIG_MISSING",
                    "Identity Provider configuration not found", "", state, context);
            return false;
        }

        if (code == null || code.trim().isEmpty()) {
            LOG.error("Authorization code missing in OAuth2 callback");
            buildAndCacheTokenExchangeErrorResponse("NO_CODE",
                    "Authorization code not received from IdP", "", state, context);
            return false;
        }

        context.setProperty(OAuth2DebugConstants.DEBUG_IDP_NAME, idp.getIdentityProviderName());
        return true;
    }

    /**
     * Extracts OAuth2 configuration from context and IdP settings.
     * First tries context (set by OAuth2ContextResolver), then falls back to IdP
     * config.
     *
     * @param context AuthenticationContext.
     * @param request HttpServletRequest.
     * @return OAuth2Configuration containing all required endpoints and
     *         credentials.
     */
    private OAuth2Configuration extractOAuth2Configuration(AuthenticationContext context, HttpServletRequest request) {

        OAuth2Configuration config = new OAuth2Configuration();
        IdentityProvider idp = (IdentityProvider) context.getProperty(OAuth2DebugConstants.IDP_CONFIG);
        String idpName = idp != null ? idp.getIdentityProviderName() : "Unknown";
        config.setIdpName(idpName);
        config.setCodeVerifier((String) context.getProperty(OAuth2DebugConstants.DEBUG_CODE_VERIFIER));

        // Extract from context first (set by OAuth2ContextProvider).
        config.setTokenEndpoint((String) context.getProperty(OAuth2DebugConstants.TOKEN_ENDPOINT));
        config.setClientId((String) context.getProperty(OAuth2DebugConstants.CLIENT_ID));
        config.setClientSecret((String) context.getProperty(OAuth2DebugConstants.CLIENT_SECRET));
        config.setUserInfoEndpoint((String) context.getProperty(OAuth2DebugConstants.USERINFO_ENDPOINT));

        if (LOG.isDebugEnabled()) {
            LOG.debug("Token exchange - from context: tokenEndpoint=" +
                    (config.getTokenEndpoint() != null ? OAuth2DebugConstants.STATUS_FOUND : "null") +
                    ", clientId=" + (config.getClientId() != null ? OAuth2DebugConstants.STATUS_FOUND : "null") +
                    ", clientSecret="
                    + (config.getClientSecret() != null ? OAuth2DebugConstants.STATUS_FOUND : "null"));
        }

        // If not in context, extract from IdP authenticator config using
        // OAuth2ConfigurationExtractor.
        if (!config.hasRequiredEndpoints() && idp != null && idp.getFederatedAuthenticatorConfigs() != null) {
            extractFromIdPConfig(idp, config);
        }

        // Build callback URL.
        String callbackUrl = (String) context.getProperty(OAuth2DebugConstants.REDIRECT_URI);
        if (StringUtils.isEmpty(callbackUrl)) {
            callbackUrl = request.getRequestURL().toString().split("\\?")[0];
        }
        config.setCallbackUrl(callbackUrl);

        return config;
    }

    /**
     * Extracts OAuth2 configuration from IdP authenticator properties
     * using {@link OAuth2ConfigurationExtractor} as single source of truth.
     *
     * @param idp    IdentityProvider containing authenticator configs.
     * @param config OAuth2Configuration to populate.
     */
    private void extractFromIdPConfig(IdentityProvider idp, OAuth2Configuration config) {

        for (FederatedAuthenticatorConfig authConfig : idp.getFederatedAuthenticatorConfigs()) {
            if (authConfig == null) {
                continue;
            }
            Map<String, String> extracted = OAuth2ConfigurationExtractor.extractConfiguration(authConfig);
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
     * @param config OAuth2Configuration with missing values.
     * @param state State parameter.
     * @param context AuthenticationContext.
     */
    private void handleConfigurationError(OAuth2Configuration config, String state, AuthenticationContext context) {

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
     * Performs OAuth2 token exchange using the provided configuration.
     *
     * @param code Authorization code.
     * @param config OAuth2Configuration.
     * @param state State parameter.
     * @param context AuthenticationContext.
     * @return true if exchange succeeds, false otherwise.
     */
    private boolean performTokenExchange(String code, OAuth2Configuration config, String state,
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
     * @param config OAuth2Configuration.
     */
    private void logTokenExchangeStart(OAuth2Configuration config) {

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
     * @param config OAuth2Configuration.
     * @return Token response from provider.
     */
    private TokenResponse executeTokenExchange(String code, OAuth2Configuration config) {

        OAuth2TokenClient tokenClient = new OAuth2TokenClient();
        return tokenClient.exchangeCodeForTokens(
                code, config.getTokenEndpoint(), config.getClientId(), config.getClientSecret(),
                config.getCallbackUrl(), config.getCodeVerifier(), config.getIdpName());
    }

    /**
     * Handles token exchange error response.
     *
     * @param tokenResponse Token response with error.
     * @param config OAuth2Configuration.
     * @param state State parameter.
     * @param context AuthenticationContext.
     * @return false always, indicating exchange failed.
     */
    private boolean handleTokenExchangeError(TokenResponse tokenResponse, OAuth2Configuration config,
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
     *
     * @param config OAuth2Configuration.
     * @param errorCode Error code from response.
     * @param errorDesc Error description.
     * @param errorDetails Additional error details.
     */
    private void logTokenExchangeError(OAuth2Configuration config, String errorCode,
            String errorDesc, String errorDetails) {

        LOG.error("Token exchange failed for IdP: " + config.getIdpName());
        LOG.error("  Error Code: " + errorCode);
        LOG.error("  Error Description: " + errorDesc);

        if (errorDetails != null && !errorDetails.isEmpty()) {
            LOG.error("  Error Details: " + errorDetails);
        }
    }

    /**
     * Logs diagnostic configuration details used for token exchange.
     *
     * @param config OAuth2Configuration.
     */
    private void logErrorDiagnosticInfo(OAuth2Configuration config) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Token exchange configuration used:");
            LOG.debug("  Token Endpoint: " + config.getTokenEndpoint());
            LOG.debug("  Client ID: " + config.getClientId());
            LOG.debug("  Callback URL: " + config.getCallbackUrl());
            LOG.debug("  Code Verifier: " + (config.getCodeVerifier() != null ? "PRESENT" : "NOT_PRESENT"));
        }
    }

    /**
     * Logs likely causes of common OAuth2 error codes.
     *
     * @param errorCode The error code returned from token endpoint.
     */
    private void logErrorCauses(String errorCode) {

        if ("INVALID_CLIENT".equals(errorCode) || "unauthorized".equals(errorCode)) {
            LOG.error("Possible causes: Incorrect Client ID or Client Secret");
            LOG.error("Verify credentials in IdP authenticator configuration");
        } else if ("INVALID_GRANT".equals(errorCode)) {
            LOG.error("Possible causes: Authorization code expired or already used");
        } else if ("INVALID_REQUEST".equals(errorCode)) {
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

        context.setProperty(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
        context.setProperty(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
        context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_ERROR, errorDesc);
        context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_SUCCESS, false);
    }

    /**
     * Handles successful token exchange.
     *
     * @param tokenResponse Token response from provider.
     * @param config OAuth2Configuration.
     * @param context AuthenticationContext.
     * @return true always, indicating exchange succeeded.
     */
    private boolean handleTokenExchangeSuccess(TokenResponse tokenResponse, OAuth2Configuration config,
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

        context.setProperty(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_SUCCESS);
        context.setProperty(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_SUCCESS);
    }

    /**
     * Logs successful token exchange completion.
     *
     * @param tokenResponse Token response from provider.
     * @param config Auth2Configuration.
     */
    private void logTokenExchangeSuccess(TokenResponse tokenResponse, OAuth2Configuration config) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("OAuth2 token exchange completed successfully for IdP: " + config.getIdpName() +
                    ", received tokens: " +
                    (tokenResponse.getAccessToken() != null ? "access_token present, " : "NO access_token, ") +
                    (tokenResponse.getIdToken() != null ? "id_token present" : "NO id_token"));
        }
    }

    /**
     * Stores tokens and configuration from successful exchange into context.
     *
     * @param tokenResponse Token response from provider.
     * @param config OAuth2Configuration OAuth2Configuration used for exchange.
     * @param context AuthenticationContext to populate.
     */
    private void storeTokensInContext(TokenResponse tokenResponse, OAuth2Configuration config,
            AuthenticationContext context) {

        String accessToken = tokenResponse.getAccessToken();
        String idToken = tokenResponse.getIdToken();
        String tokenType = tokenResponse.getTokenType();

        context.setProperty(OAuth2DebugConstants.ACCESS_TOKEN, accessToken);
        if (idToken != null && !idToken.trim().isEmpty()) {
            context.setProperty(OAuth2DebugConstants.ID_TOKEN, idToken);
        }
        if (tokenType != null && !tokenType.trim().isEmpty()) {
            context.setProperty(OAuth2DebugConstants.TOKEN_TYPE, tokenType);
        }
        if (config.getUserInfoEndpoint() != null && !config.getUserInfoEndpoint().trim().isEmpty()) {
            context.setProperty(OAuth2DebugConstants.USERINFO, config.getUserInfoEndpoint());
        }
    }

    /**
     * Data holder for OAuth2 configuration values extracted from IdP settings.
     * Provides validation and null-safe access to required endpoints and
     * credentials.
     */
    private static class OAuth2Configuration {

        private String tokenEndpoint;
        private String clientId;
        private String clientSecret;
        private String userInfoEndpoint;
        private String codeVerifier;
        private String callbackUrl;
        private String idpName;

        public boolean isValid() {
            return tokenEndpoint != null && !tokenEndpoint.trim().isEmpty() &&
                    clientId != null && !clientId.trim().isEmpty();
        }

        public boolean hasRequiredEndpoints() {
            return tokenEndpoint != null && clientId != null;
        }

        // Getters and setters.
        public String getTokenEndpoint() {
            return tokenEndpoint;
        }

        public void setTokenEndpoint(String tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getUserInfoEndpoint() {
            return userInfoEndpoint;
        }

        public void setUserInfoEndpoint(String userInfoEndpoint) {
            this.userInfoEndpoint = userInfoEndpoint;
        }

        public String getCodeVerifier() {
            return codeVerifier;
        }

        public void setCodeVerifier(String codeVerifier) {
            this.codeVerifier = codeVerifier;
        }

        public String getCallbackUrl() {
            return callbackUrl;
        }

        public void setCallbackUrl(String callbackUrl) {
            this.callbackUrl = callbackUrl;
        }

        public String getIdpName() {
            return idpName;
        }

        public void setIdpName(String idpName) {
            this.idpName = idpName;
        }
    }

    /**
     * Extracts user claims from OAuth2/OIDC tokens.
     * OAuth2-specific implementation that parses ID token claims and fetches
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
            String idToken = (String) context.getProperty(OAuth2DebugConstants.ID_TOKEN);
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
            LOG.error("Error extracting user claims from OAuth2 tokens: " + e.getMessage(), e);
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

        String accessToken = (String) context.getProperty(OAuth2DebugConstants.ACCESS_TOKEN);
        if (StringUtils.isEmpty(accessToken)) {
            return;
        }

        String userInfoEndpoint = (String) context.getProperty(OAuth2DebugConstants.DEBUG_USERINFO_ENDPOINT);
        if (StringUtils.isEmpty(userInfoEndpoint)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("UserInfo endpoint URL not available in context");
            }
            return;
        }

        try {
            // Delegate to OAuth2TokenClient instead of inline HTTP client.
            OAuth2TokenClient tokenClient = new OAuth2TokenClient();
            Map<String, Object> userInfoClaims = tokenClient.fetchUserInfoClaims(
                    accessToken, userInfoEndpoint, new UrlConnectionHttpFetcher());
            if (!userInfoClaims.isEmpty()) {
                userInfoClaims.putAll(claims);
                claims.clear();
                claims.putAll(userInfoClaims);
                context.setProperty(OAuth2DebugConstants.DEBUG_USERINFO_CALLED, "true");
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Successfully merged UserInfo claims with ID token claims. Total: " + claims.size());
                }
            }
        } catch (Exception e) {
            context.setProperty(OAuth2DebugConstants.DEBUG_USERINFO_ERROR, e.getMessage());
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
            context.setProperty(OAuth2DebugConstants.DEBUG_INCOMING_CLAIMS, claims);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully extracted " + claims.size() + " claims from tokens: " + claims.keySet());
            }
            return claims;
        }

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
     * For OAuth2, uses state parameter as session key to track processed codes.
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
        Object processedCode = context.getProperty("DEBUG_PROCESSED_CODE_" + state);
        if (processedCode != null && processedCode.equals(authorizationCode)) {
            LOG.error("Authorization code replay detected - code already processed for state: " + state);
            buildAndCacheTokenExchangeErrorResponse("CODE_REPLAY",
                    "Authorization code was already processed", "", state, context);
            return true;
        }

        // Mark this code as processed for this state.
        context.setProperty("DEBUG_PROCESSED_CODE_" + state, authorizationCode);
        return false;
    }

    /**
     * Handles claim extraction result and validates successful extraction.
     * For OAuth2, validates that required claims (sub/user ID) are present.
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
            LOG.error("No claims extracted from OAuth2 tokens");
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_ERROR, "No user claims extracted from IdP");
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheTokenExchangeErrorResponse("NO_CLAIMS",
                    "No user claims available from IdP", "", state, context);
            return false;
        }

        // Validate that at least a user identifier is present.
        if (!claims.containsKey("sub") && !claims.containsKey("user_id") &&
                !claims.containsKey("userId") && !claims.containsKey("email")) {
            LOG.error("Required user identifier claim not found in extracted claims");
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_ERROR, "User identifier claim missing");
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_SUCCESS, false);
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
            persistDebugResultToCache(state, context, debugResult);

        } catch (Exception e) {
            LOG.error("Error building and caching debug result: " + e.getMessage(), e);
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_ERROR, "Error caching debug result: " + e.getMessage());
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_SUCCESS, false);
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
        debugResult.put(OAuth2DebugConstants.DEBUG_RESULT_SUCCESS, true);
        debugResult.put("authenticator", "OpenIDConnectAuthenticator");
        debugResult.put(OAuth2DebugConstants.DEBUG_RESULT_IDPNAME,
                context.getProperty(OAuth2DebugConstants.DEBUG_IDP_NAME));
        debugResult.put(OAuth2DebugConstants.DEBUG_RESULT_SESSIONID,
                context.getProperty(OAuth2DebugConstants.DEBUG_CONTEXT_ID));
        debugResult.put("executor", "UnknownExecutor");

        // Add step statuses.
        debugResult.put(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_SUCCESS);
        debugResult.put(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_SUCCESS);
        debugResult.put(OAuth2DebugConstants.STEP_CLAIM_EXTRACTION_STATUS, OAuth2DebugConstants.STATUS_SUCCESS);
        debugResult.put(OAuth2DebugConstants.STEP_CLAIM_MAPPING_STATUS, OAuth2DebugConstants.STATUS_SUCCESS);

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
                .getProperty(OAuth2DebugConstants.DEBUG_INCOMING_CLAIMS);
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

        IdentityProvider idp = (IdentityProvider) context.getProperty(OAuth2DebugConstants.IDP_CONFIG);
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

        if (!idpClaimMappings.isEmpty()) {
            String diagnostic = buildClaimMappingDiagnostic(mappedClaimsArray, idpClaimMappings, incomingClaims);
            debugResult.put("claimMappingDiagnostic", diagnostic);
        }
    }

    /**
     * Builds the mapped claims array by processing configured mappings and
     * auto-discovered claims.
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
                String remoteClaimUri = mapping.getValue().get(OAuth2DebugConstants.CLAIM_MAPPING_REMOTE);
                String localClaimUri = mapping.getValue().get(OAuth2DebugConstants.CLAIM_MAPPING_LOCAL);

                Map<String, Object> claimEntry = processConfiguredMapping(
                        remoteClaimUri, localClaimUri, incomingClaims, processedClaims);
                mappedClaimsArray.add(claimEntry);
            }
        }

        // Add auto-discovered claims.
        addAutoDiscoveredClaims(mappedClaimsArray, incomingClaims, processedClaims);

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
        claimEntry.put(OAuth2DebugConstants.CLAIM_MAPPING_IDP_CLAIM, remoteClaimUri != null ? remoteClaimUri : "");
        claimEntry.put(OAuth2DebugConstants.CLAIM_MAPPING_LOCAL_CLAIM, localClaimUri != null ? localClaimUri : "");

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

        claimEntry.put(OAuth2DebugConstants.CLAIM_MAPPING_VALUE,
                claimValue != null ? claimValue.toString() : null);
        claimEntry.put(OAuth2DebugConstants.CLAIM_MAPPING_STATUS, claimStatus);

        return claimEntry;
    }

    /**
     * Adds auto-discovered claims that` were not covered by configured mappings.
     *
     * @param mappedClaimsArray List to add auto-discovered claims to.
     * @param incomingClaims Incoming claims from tokens.
     * @param processedClaims Set of already processed claim names.
     */
    private void addAutoDiscoveredClaims(List<Map<String, Object>> mappedClaimsArray,
            Map<String, Object> incomingClaims, Set<String> processedClaims) {

        if (incomingClaims.isEmpty()) {
            return;
        }

        for (Map.Entry<String, Object> entry : incomingClaims.entrySet()) {
            String claimName = entry.getKey();
            if (processedClaims.contains(claimName)) {
                continue;
            }

            Map<String, Object> claimEntry = new HashMap<>();
            String claimUri = "http://wso2.org/claims/" + claimName;

            claimEntry.put(OAuth2DebugConstants.CLAIM_MAPPING_IDP_CLAIM, claimName);
            claimEntry.put(OAuth2DebugConstants.CLAIM_MAPPING_LOCAL_CLAIM, claimUri);
            claimEntry.put(OAuth2DebugConstants.CLAIM_MAPPING_VALUE,
                    entry.getValue() != null ? entry.getValue().toString() : null);
            claimEntry.put(OAuth2DebugConstants.CLAIM_MAPPING_STATUS, "Auto-Discovered");

            if (LOG.isDebugEnabled()) {
                LOG.debug("Adding unmapped incoming claim: " + claimName);
            }

            mappedClaimsArray.add(claimEntry);
        }
    }

    /**
     * Builds a diagnostic message summarizing claim mapping results.
     *
     * @param mappedClaimsArray Mapped claims array.
     * @param idpClaimMappings IdP configured mappings.
     * @param incomingClaims Incoming claims.
     * @return Diagnostic message string.
     */
    private String buildClaimMappingDiagnostic(List<Map<String, Object>> mappedClaimsArray,
            Map<String, Map<String, String>> idpClaimMappings, Map<String, Object> incomingClaims) {

        int successCount = (int) mappedClaimsArray.stream()
                .filter(c -> "Successful".equals(c.get("status")))
                .count();
        int totalCount = idpClaimMappings.size();
        int notFoundCount = totalCount - successCount;

        StringBuilder diagnostic = new StringBuilder();
        diagnostic.append("Claim Mapping Report: ").append(successCount).append(" of ").append(totalCount)
                .append(" mappings successful");

        if (notFoundCount > 0) {
            diagnostic.append(" (").append(notFoundCount).append(" not found)");
        }
        diagnostic.append(". ");

        if (!incomingClaims.isEmpty()) {
            diagnostic.append("Incoming claims received: ").append(String.join(", ", incomingClaims.keySet()))
                    .append(". ");
        }

        List<String> missingClaims = new ArrayList<>();
        for (Map<String, Object> claim : mappedClaimsArray) {
            if ("Not Mapped".equals(claim.get("status"))) {
                missingClaims.add(claim.get(OAuth2DebugConstants.CLAIM_MAPPING_IDP_CLAIM) + " -> " +
                        claim.get(OAuth2DebugConstants.CLAIM_MAPPING_LOCAL_CLAIM));
            }
        }
        if (!missingClaims.isEmpty()) {
            diagnostic.append("Missing expected claims: ");
            for (int i = 0; i < missingClaims.size(); i++) {
                if (i > 0)
                    diagnostic.append(", ");
                diagnostic.append("[").append(missingClaims.get(i)).append("]");
            }
        }

        return diagnostic.toString();
    }

    /**
     * Builds user attributes map and metadata information.
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
        String externalRedirectUrl = (String) context.getProperty(OAuth2DebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
        debugResult.put("externalRedirectUrl", externalRedirectUrl);

        String idToken = (String) context.getProperty(OAuth2DebugConstants.ID_TOKEN);
        debugResult.put("idToken", idToken);

        String callbackUrl = (String) context.getProperty(OAuth2DebugConstants.REDIRECT_URI);
        debugResult.put("callbackUrl", callbackUrl);

        debugResult.put("error", null);
        debugResult.put("timestamp", null);

        // Add metadata.
        Map<String, Object> metadata = new HashMap<>();
        metadata.put(OAuth2DebugConstants.STEP_CLAIM_MAPPING_STATUS, OAuth2DebugConstants.STATUS_SUCCESS);
        metadata.put(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_SUCCESS);
        metadata.put(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_SUCCESS);
        debugResult.put("metadata", metadata);
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
            context.setProperty(OAuth2DebugConstants.DEBUG_AUTH_SUCCESS, true);

            // Get context ID and persist to DebugResultCache.
            String contextId = (String) context.getProperty(OAuth2DebugConstants.DEBUG_CONTEXT_ID);
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
        mapping.put(OAuth2DebugConstants.CLAIM_MAPPING_REMOTE, remoteClaimUri);
        mapping.put(OAuth2DebugConstants.CLAIM_MAPPING_LOCAL, localClaimUri);
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
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("state", state);
            errorResponse.put("success", false);
            errorResponse.put("error_code", errorCode);
            errorResponse.put("error_description", errorDescription);
            if (errorDetails != null && !errorDetails.isEmpty()) {
                errorResponse.put("error_details", errorDetails);
            }

            // Add external redirect URL if available.
            String externalRedirectUrl = (String) context.getProperty(OAuth2DebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
            if (externalRedirectUrl != null && !externalRedirectUrl.isEmpty()) {
                errorResponse.put("externalRedirectUrl", externalRedirectUrl);
            }

            // Add metadata placeholder for consistency with success response.
            errorResponse.put("metadata", new HashMap<>());

            String errorResponseJson = OBJECT_MAPPER.writeValueAsString(errorResponse);

            // Cache in context.
            context.setProperty(DEBUG_RESULT_CACHE_KEY, errorResponseJson);
            context.setProperty(DEBUG_AUTH_SUCCESS_KEY, "false");

            // Get context ID for dual-key caching.
            String contextId = (String) context.getProperty(OAuth2DebugConstants.DEBUG_CONTEXT_ID);

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
            DebugResultCache.add(state, resultJson);
            if (contextId != null && !contextId.equals(state)) {
                DebugResultCache.add(contextId, resultJson);
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
                OAuth2DebugConstants.TOKEN_ENDPOINT, OAuth2DebugConstants.CLIENT_ID, OAuth2DebugConstants.CLIENT_SECRET,
                OAuth2DebugConstants.USERINFO_ENDPOINT, OAuth2DebugConstants.DEBUG_CODE_VERIFIER,
                OAuth2DebugConstants.REDIRECT_URI,
                OAuth2DebugConstants.DEBUG_IDP_NAME, OAuth2DebugConstants.IDP_CONFIG,
                OAuth2DebugConstants.AUTHORIZATION_ENDPOINT,
                OAuth2DebugConstants.DEBUG_CONTEXT_ID, OAuth2DebugConstants.DEBUG_EXTERNAL_REDIRECT_URL,
                OAuth2DebugConstants.ACCESS_TOKEN, OAuth2DebugConstants.ID_TOKEN, OAuth2DebugConstants.TOKEN_TYPE,
                OAuth2DebugConstants.USERINFO
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
