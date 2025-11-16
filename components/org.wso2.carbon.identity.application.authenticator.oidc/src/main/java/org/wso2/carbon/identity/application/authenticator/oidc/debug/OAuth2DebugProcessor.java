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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.OAuth2TokenClient;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.TokenResponse;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.debug.framework.core.DebugProcessor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

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
 * - parseIdTokenClaims(), parseJsonPayload(), mapClaimsToAttributes(): Generic parsing/mapping
 */
public class OAuth2DebugProcessor extends DebugProcessor {

    private static final Log LOG = LogFactory.getLog(OAuth2DebugProcessor.class);

    /**
     * Validates OAuth2-specific callback parameters.
     * Checks for authorization code or error response, CSRF protection.
     *
     * @param request HttpServletRequest.
     * @param context AuthenticationContext.
     * @param response HttpServletResponse.
     * @param state State parameter.
     * @param idpId IdP resource ID.
     * @return true if callback is valid, false otherwise.
     * @throws IOException If response cannot be sent.
     */
    @Override
    protected boolean validateProtocolCallback(HttpServletRequest request, AuthenticationContext context,
            HttpServletResponse response, String state, String idpId) throws IOException {
        String code = request.getParameter("code");
        String error = request.getParameter("error");
        String errorDescription = request.getParameter("error_description");

        // Handle OAuth2 error responses.
        if (error != null) {
            LOG.error("OAuth2 error from IdP: " + error + " - " + errorDescription);
            context.setProperty("DEBUG_AUTH_ERROR", error + ": " + errorDescription);
            context.setProperty("DEBUG_AUTH_SUCCESS", "false");
            buildAndCacheTokenExchangeErrorResponse(error, errorDescription, "", state, context);
            return false;
        }

        // Validate authorization code presence.
        if (code == null || code.trim().isEmpty()) {
            LOG.error("Authorization code missing in OAuth2 callback");
            context.setProperty("DEBUG_AUTH_ERROR", "Authorization code not received from IdP");
            context.setProperty("DEBUG_AUTH_SUCCESS", "false");
            buildAndCacheTokenExchangeErrorResponse("NO_CODE", 
                    "Authorization code not received from IdP", "", state, context);
            return false;
        }

        // Validate state parameter.
        if (state == null || state.trim().isEmpty()) {
            LOG.error("State parameter missing in OAuth2 callback");
            context.setProperty("DEBUG_AUTH_ERROR", "State parameter missing - possible CSRF attack");
            context.setProperty("DEBUG_AUTH_SUCCESS", "false");
            buildAndCacheTokenExchangeErrorResponse("NO_STATE", 
                    "State parameter missing - possible CSRF attack", "", state, context);
            return false;
        }

        // Validate state matches stored value if available.
        String storedState = (String) context.getProperty("DEBUG_STATE");
        if (storedState != null && !state.equals(storedState)) {
            LOG.error("State parameter mismatch - CSRF attack detected");
            context.setProperty("DEBUG_AUTH_ERROR", "State validation failed - possible CSRF attack");
            context.setProperty("DEBUG_AUTH_SUCCESS", "false");
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
     * Delegates to smaller, focused methods for configuration extraction and token exchange.
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
    protected boolean exchangeAuthorizationForTokens(HttpServletRequest request, AuthenticationContext context,
            HttpServletResponse response, String state, String idpId) throws IOException {
        String code = request.getParameter("code");
        
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Exchanging authorization code for OAuth2 tokens. Code present: " + (code != null));
            }
            
            // Validate prerequisites.
            if (!validateAndExtractPrerequisites(code, state, context)) {
                context.setProperty("step_connection_status", "failed");
                return false;
            }
            
            // Extract configuration from IdP and context.
            OAuth2Configuration config = extractOAuth2Configuration(context, request);
            if (!config.isValid()) {
                handleConfigurationError(config, state, context);
                return false;
            }
            
            // Perform token exchange.
            return performTokenExchange(code, config, state, context);

        } catch (Exception e) {
            LOG.error("Error exchanging OAuth2 authorization code: " + e.getMessage(), e);
            buildAndCacheTokenExchangeErrorResponse("TOKEN_EXCHANGE_ERROR",
                    "Token exchange error: " + e.getMessage(), e.toString(), state, context);
            context.setProperty("step_connection_status", "failed");
            context.setProperty("step_authentication_status", "failed");
            context.setProperty("DEBUG_AUTH_ERROR", "Token exchange error: " + e.getMessage());
            context.setProperty("DEBUG_AUTH_SUCCESS", "false");
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
        IdentityProvider idp = (IdentityProvider) context.getProperty("IDP_CONFIG");
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

        context.setProperty("DEBUG_IDP_NAME", idp.getIdentityProviderName());
        return true;
    }

    /**
     * Extracts OAuth2 configuration from context and IdP settings.
     * First tries context (set by OAuth2ContextResolver), then falls back to IdP config.
     *
     * @param context AuthenticationContext.
     * @param request HttpServletRequest.
     * @return OAuth2Configuration containing all required endpoints and credentials.
     */
    private OAuth2Configuration extractOAuth2Configuration(AuthenticationContext context, HttpServletRequest request) {
        OAuth2Configuration config = new OAuth2Configuration();
        IdentityProvider idp = (IdentityProvider) context.getProperty("IDP_CONFIG");
        String idpName = idp != null ? idp.getIdentityProviderName() : "Unknown";
        config.setIdpName(idpName);
        config.setCodeVerifier((String) context.getProperty("DEBUG_CODE_VERIFIER"));

        // Extract from context first (set by OAuth2ContextResolver).
        config.setTokenEndpoint((String) context.getProperty("DEBUG_TOKEN_ENDPOINT"));
        config.setClientId((String) context.getProperty("DEBUG_CLIENT_ID"));
        config.setClientSecret((String) context.getProperty("DEBUG_CLIENT_SECRET"));
        config.setUserInfoEndpoint((String) context.getProperty("DEBUG_USERINFO_ENDPOINT"));

        if (LOG.isDebugEnabled()) {
            LOG.debug("Token exchange - from context: tokenEndpoint=" + 
                    (config.getTokenEndpoint() != null ? "FOUND" : "null") +
                    ", clientId=" + (config.getClientId() != null ? "FOUND" : "null") + 
                    ", clientSecret=" + (config.getClientSecret() != null ? "FOUND" : "null"));
        }

        // If not in context, extract from IdP authenticator config.
        if (!config.hasRequiredEndpoints() && idp != null && idp.getFederatedAuthenticatorConfigs() != null) {
            extractFromIdPConfig(idp, config);
        }

        // Build callback URL.
        String callbackUrl = (String) context.getProperty("DEBUG_CALLBACK_URL");
        if (callbackUrl == null || callbackUrl.trim().isEmpty()) {
            callbackUrl = request.getRequestURL().toString().split("\\?")[0];
        }
        config.setCallbackUrl(callbackUrl);

        return config;
    }

    /**
     * Extracts OAuth2 configuration from IdP authenticator properties.
     *
     * @param idp IdentityProvider containing authenticator configs.
     * @param config OAuth2Configuration to populate.
     */
    private void extractFromIdPConfig(IdentityProvider idp, OAuth2Configuration config) {
        for (FederatedAuthenticatorConfig authConfig : idp.getFederatedAuthenticatorConfigs()) {
            if (authConfig != null && isOAuth2Authenticator(authConfig.getName())) {
                Property[] properties = authConfig.getProperties();
                if (properties != null) {
                    for (Property prop : properties) {
                        if (prop != null && prop.getName() != null) {
                            String propName = prop.getName();
                            String propValue = prop.getValue();
                            
                            if (propValue != null && !propValue.trim().isEmpty()) {
                                if (isTokenEndpointProperty(propName)) {
                                    config.setTokenEndpoint(propValue);
                                } else if (isClientIdProperty(propName)) {
                                    config.setClientId(propValue);
                                } else if (isClientSecretProperty(propName)) {
                                    config.setClientSecret(propValue);
                                } else if (isUserInfoEndpointProperty(propName)) {
                                    config.setUserInfoEndpoint(propValue);
                                }
                            }
                        }
                    }
                }
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
        // Use OAuth2TokenClient to exchange code for tokens.
        OAuth2TokenClient tokenClient = new OAuth2TokenClient();
        TokenResponse tokenResponse = tokenClient.exchangeCodeForTokens(
                code, config.getTokenEndpoint(), config.getClientId(), config.getClientSecret(), 
                config.getCallbackUrl(), config.getCodeVerifier(), config.getIdpName());

        if (tokenResponse.hasError()) {
            LOG.error("Token exchange failed: " + tokenResponse.getErrorCode() + " - " + 
                    tokenResponse.getErrorDescription());
            buildAndCacheTokenExchangeErrorResponse(tokenResponse.getErrorCode(),
                    tokenResponse.getErrorDescription(), tokenResponse.getErrorDetails(), state, context);
            context.setProperty("step_connection_status", "failed");
            context.setProperty("step_authentication_status", "failed");
            context.setProperty("DEBUG_AUTH_ERROR", tokenResponse.getErrorDescription());
            context.setProperty("DEBUG_AUTH_SUCCESS", "false");
            return false;
        }

        // Token exchange succeeded - store tokens in context.
        storeTokensInContext(tokenResponse, config, context);
        context.setProperty("step_connection_status", "success");
        context.setProperty("step_authentication_status", "success");

        if (LOG.isDebugEnabled()) {
            LOG.debug("OAuth2 token exchange completed successfully for IdP: " + config.getIdpName());
        }

        return true;
    }

    /**
     * Stores tokens and configuration from successful exchange into context.
     *
     * @param tokenResponse Token response from provider.
     * @param config OAuth2Configuration used for exchange.
     * @param context AuthenticationContext to populate.
     */
    private void storeTokensInContext(TokenResponse tokenResponse, OAuth2Configuration config, 
            AuthenticationContext context) {
        String accessToken = tokenResponse.getAccessToken();
        String idToken = tokenResponse.getIdToken();
        String tokenType = tokenResponse.getTokenType();

        context.setProperty("DEBUG_ACCESS_TOKEN", accessToken);
        if (idToken != null && !idToken.trim().isEmpty()) {
            context.setProperty("DEBUG_ID_TOKEN", idToken);
        }
        if (tokenType != null && !tokenType.trim().isEmpty()) {
            context.setProperty("DEBUG_TOKEN_TYPE", tokenType);
        }
        if (config.getUserInfoEndpoint() != null && !config.getUserInfoEndpoint().trim().isEmpty()) {
            context.setProperty("DEBUG_USERINFO_ENDPOINT", config.getUserInfoEndpoint());
        }
    }

    /**
     * Data holder for OAuth2 configuration values extracted from IdP settings.
     * Provides validation and null-safe access to required endpoints and credentials.
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
        public String getTokenEndpoint() { return tokenEndpoint; }
        public void setTokenEndpoint(String tokenEndpoint) { this.tokenEndpoint = tokenEndpoint; }

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }

        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

        public String getUserInfoEndpoint() { return userInfoEndpoint; }
        public void setUserInfoEndpoint(String userInfoEndpoint) { this.userInfoEndpoint = userInfoEndpoint; }

        public String getCodeVerifier() { return codeVerifier; }
        public void setCodeVerifier(String codeVerifier) { this.codeVerifier = codeVerifier; }

        public String getCallbackUrl() { return callbackUrl; }
        public void setCallbackUrl(String callbackUrl) { this.callbackUrl = callbackUrl; }

        public String getIdpName() { return idpName; }
        public void setIdpName(String idpName) { this.idpName = idpName; }
    }

    /**
     * Checks if an authenticator name is OAuth2/OIDC.
     * Supports multiple name variations.
     *
     * @param authName The authenticator name to check.
     * @return true if the name matches OAuth2/OIDC variations, false otherwise.
     */
    private boolean isOAuth2Authenticator(String authName) {
        if (authName == null || authName.isEmpty()) {
            return false;
        }
        String normalizedName = authName.toLowerCase();
        return normalizedName.contains("openidconnect") || normalizedName.contains("oauth2") ||
               "oidcauthenticator".equals(normalizedName) || "oauth2authenticator".equals(normalizedName);
    }



    /**
     * Checks if a property name matches token endpoint property names.
     * Tries multiple variations to support different IdP configurations.
     *
     * @param propertyName The property name to check.
     * @return true if the property name matches token endpoint variations.
     */
    private boolean isTokenEndpointProperty(String propertyName) {
        return "OAuth2TokenEPUrl".equals(propertyName) || 
               "OAuth2TokenURL".equals(propertyName) ||
               "tokenEndpoint".equals(propertyName) || 
               "token_endpoint".equals(propertyName) ||
               "TokenEndpoint".equals(propertyName);
    }

    /**
     * Checks if a property name matches client ID property names.
     * Tries multiple variations to support different IdP configurations.
     *
     * @param propertyName The property name to check.
     * @return true if the property name matches client ID variations.
     */
    private boolean isClientIdProperty(String propertyName) {
        return "ClientId".equals(propertyName) || 
               "client_id".equals(propertyName) ||
               "clientId".equals(propertyName);
    }

    /**
     * Checks if a property name matches client secret property names.
     * Tries multiple variations to support different IdP configurations.
     *
     * @param propertyName The property name to check.
     * @return true if the property name matches client secret variations.
     */
    private boolean isClientSecretProperty(String propertyName) {
        return "ClientSecret".equals(propertyName) || 
               "client_secret".equals(propertyName) ||
               "clientSecret".equals(propertyName);
    }

    /**
     * Checks if a property name matches UserInfo endpoint property names.
     * Tries multiple variations to support different IdP configurations.
     *
     * @param propertyName The property name to check.
     * @return true if the property name matches UserInfo endpoint variations.
     */
    private boolean isUserInfoEndpointProperty(String propertyName) {
        return "OAuth2UserInfoEPUrl".equals(propertyName) || 
               "OAuth2UserInfoURL".equals(propertyName) ||
               "userInfoEndpoint".equals(propertyName) || 
               "userinfo_endpoint".equals(propertyName) ||
               "UserInfoEndpoint".equals(propertyName) ||
               "userInfoUrl".equals(propertyName);
    }

    /**
     * Extracts user claims from OAuth2/OIDC tokens.
     * OAuth2-specific implementation that parses ID token claims and fetches UserInfo.
     * Generic claim mapping and formatting is handled by parent DebugProcessor class.
     *
     * @param context AuthenticationContext containing ID token and access token.
     * @return Map of extracted claims, or empty map if extraction yields no results.
     */
    @Override
    protected Map<String, Object> extractUserClaims(AuthenticationContext context) {
        try {
            String idToken = (String) context.getProperty("DEBUG_ID_TOKEN");
            if (idToken == null || idToken.trim().isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No ID token available for claim extraction");
                }
                return new HashMap<>();
            }

            // Parse JWT ID token to extract claims.
            Map<String, Object> claims = parseIdTokenClaims(idToken);
            if (claims == null) {
                claims = new HashMap<>();
            }

            // Get access token for UserInfo endpoint call.
            String accessToken = (String) context.getProperty("DEBUG_ACCESS_TOKEN");
            if (accessToken != null && !accessToken.trim().isEmpty()) {
                try {
                    // Attempt to call UserInfo endpoint to get complete user profile claims.
                    Map<String, Object> userInfoClaims = callUserInfoEndpoint(context, accessToken);
                    if (userInfoClaims != null && !userInfoClaims.isEmpty()) {
                        // Merge UserInfo claims with ID token claims (UserInfo takes precedence).
                        userInfoClaims.putAll(claims);
                        claims = userInfoClaims;
                        context.setProperty("DEBUG_USERINFO_CALLED", "true");
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Successfully merged UserInfo claims with ID token claims. Total: " + 
                                      claims.size());
                        }
                    }
                } catch (Exception e) {
                    // Log error but continue with ID token claims.
                    context.setProperty("DEBUG_USERINFO_ERROR", e.getMessage());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("UserInfo endpoint call failed, continuing with ID token claims: " + 
                                  e.getMessage());
                    }
                }
            }

            if (!claims.isEmpty()) {
                context.setProperty("DEBUG_INCOMING_CLAIMS", claims);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Successfully extracted " + claims.size() + " claims from tokens: " + 
                              claims.keySet());
                }
                return claims;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("No claims extracted from ID token or UserInfo endpoint");
            }
            return new HashMap<>();

        } catch (Exception e) {
            LOG.error("Error extracting user claims from OAuth2 tokens: " + e.getMessage(), e);
            return new HashMap<>();
        }
    }

    /**
     * Parses JWT ID token and extracts claims from the payload.
     * Handles JWT format with three parts: header.payload.signature.
     * Includes null safety checks.
     *
     * @param idToken The JWT ID token.
     * @return Map of claims extracted from the token payload, or empty map if parsing fails.
     */
    private Map<String, Object> parseIdTokenClaims(String idToken) {
        if (idToken == null || idToken.trim().isEmpty()) {
            return new HashMap<>();
        }
        try {
            // Validate JWT format (must have three parts).
            String[] parts = idToken.split("\\.");
            if (parts.length != 3) {
                LOG.error("Invalid ID token format - expected 3 parts (header.payload.signature), got " + parts.length);
                return new HashMap<>();
            }

            // Decode the payload (second part) from Base64.
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
     * Handles JSON parsing errors gracefully with null safety.
     *
     * @param json The JSON string to parse.
     * @return Map of claims from the JSON, or empty map if parsing fails.
     */
    private Map<String, Object> parseJsonToClaims(String json) {
        if (json == null || json.trim().isEmpty()) {
            return new HashMap<>();
        }
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = 
                    new com.fasterxml.jackson.databind.ObjectMapper();
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = mapper.readValue(json, Map.class);
            return claims != null ? claims : new HashMap<>();
        } catch (Exception e) {
            LOG.error("Error parsing JSON to claims: " + e.getMessage(), e);
            return new HashMap<>();
        }
    }

    /**
     * Calls the UserInfo endpoint to retrieve complete user profile claims.
     * UserInfo endpoint provides claims not available in ID token (email, profile, etc.).
     * Properly manages HTTP connection resource cleanup.
     *
     * @param context AuthenticationContext containing UserInfo endpoint URL.
     * @param accessToken Access token for authorization.
     * @return Map of user claims from UserInfo endpoint, or empty map if call fails.
     */
    private Map<String, Object> callUserInfoEndpoint(AuthenticationContext context, String accessToken) {
        java.net.HttpURLConnection connection = null;
        try {
            // Get UserInfo endpoint URL from context or IdP configuration.
            String userInfoEndpoint = (String) context.getProperty("DEBUG_USERINFO_ENDPOINT");
            if (userInfoEndpoint == null || userInfoEndpoint.trim().isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("UserInfo endpoint URL not available in context");
                }
                return new HashMap<>();
            }

            // Make HTTP GET request to UserInfo endpoint with Bearer token.
            java.net.URL url = new java.net.URL(userInfoEndpoint);
            connection = (java.net.HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Authorization", "Bearer " + accessToken);
            connection.setRequestProperty("Accept", "application/json");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            int responseCode = connection.getResponseCode();
            if (responseCode != 200) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("UserInfo endpoint returned status code: " + responseCode);
                }
                return new HashMap<>();
            }

            // Read and parse response.
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            String responseBody = response.toString();
            if (LOG.isDebugEnabled()) {
                LOG.debug("UserInfo endpoint response received with " + responseBody.length() + " bytes");
            }

            // Parse JSON response to claims map.
            return parseJsonToClaims(responseBody);

        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error calling UserInfo endpoint: " + e.getMessage());
            }
            return new HashMap<>();
        } finally {
            // Ensure connection is properly closed.
            if (connection != null) {
                try {
                    connection.disconnect();
                } catch (Exception e) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Error disconnecting UserInfo endpoint connection: " + e.getMessage());
                    }
                }
            }
        }
    }
}
