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
            
            // Retrieve IdP configuration.
            IdentityProvider idp = (IdentityProvider) context.getProperty("IDP_CONFIG");
            if (idp == null) {
                LOG.error("IdP configuration not found in context");
                buildAndCacheTokenExchangeErrorResponse("IDP_CONFIG_MISSING", 
                        "Identity Provider configuration not found", "", state, context);
                context.setProperty("step_connection_status", "failed");
                return true;
            }

            // Validate authorization code.
            if (code == null || code.trim().isEmpty()) {
                LOG.error("Authorization code missing in OAuth2 callback");
                buildAndCacheTokenExchangeErrorResponse("NO_CODE", 
                        "Authorization code not received from IdP", "", state, context);
                context.setProperty("step_connection_status", "failed");
                return true;
            }

            // Store IdP information in context.
            context.setProperty("DEBUG_IDP_NAME", idp.getIdentityProviderName());
            // DEBUG_EXTERNAL_REDIRECT_URL already set by OAuth2UrlBuilder to the IdP's authorization URL.
            // Do not overwrite it here with the callback URL.

            // Extract configuration from IdP authenticator.
            String tokenEndpoint = null;
            String clientId = null;
            String clientSecret = null;
            String userInfoEndpoint = null;
            String codeVerifier = (String) context.getProperty("DEBUG_CODE_VERIFIER");
            String idpName = idp.getIdentityProviderName();

            // Try to get from context first (set by OAuth2ContextResolver).
            tokenEndpoint = (String) context.getProperty("DEBUG_TOKEN_ENDPOINT");
            clientId = (String) context.getProperty("DEBUG_CLIENT_ID");
            clientSecret = (String) context.getProperty("DEBUG_CLIENT_SECRET");
            userInfoEndpoint = (String) context.getProperty("DEBUG_USERINFO_ENDPOINT");

            if (LOG.isDebugEnabled()) {
                LOG.debug("Token exchange - from context: tokenEndpoint=" + (tokenEndpoint != null ? "FOUND" : "null") +
                        ", clientId=" + (clientId != null ? "FOUND" : "null") + 
                        ", clientSecret=" + (clientSecret != null ? "FOUND" : "null"));
            }

            // If not in context, extract from IdP authenticator config.
            if (tokenEndpoint == null || clientId == null || userInfoEndpoint == null) {
                if (idp.getFederatedAuthenticatorConfigs() != null) {
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
                                                tokenEndpoint = propValue;
                                            } else if (isClientIdProperty(propName)) {
                                                clientId = propValue;
                                            } else if (isClientSecretProperty(propName)) {
                                                clientSecret = propValue;
                                            } else if (isUserInfoEndpointProperty(propName)) {
                                                userInfoEndpoint = propValue;
                                            }
                                        }
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }

            // Build callback URL.
            String callbackUrl = (String) context.getProperty("DEBUG_CALLBACK_URL");
            if (callbackUrl == null || callbackUrl.trim().isEmpty()) {
                callbackUrl = request.getRequestURL().toString().split("\\?")[0];
            }

            // Use OAuth2TokenClient to exchange code for tokens.
            OAuth2TokenClient tokenClient = new OAuth2TokenClient();
            TokenResponse tokenResponse = tokenClient.exchangeCodeForTokens(
                    code, tokenEndpoint, clientId, clientSecret, callbackUrl, codeVerifier, idpName);

            if (tokenResponse.hasError()) {
                LOG.error("Token exchange failed: " + tokenResponse.getErrorCode() + " - " + tokenResponse.getErrorDescription());
                buildAndCacheTokenExchangeErrorResponse(tokenResponse.getErrorCode(),
                        tokenResponse.getErrorDescription(), tokenResponse.getErrorDetails(), state, context);
                context.setProperty("step_connection_status", "failed");
                context.setProperty("step_authentication_status", "failed");
                context.setProperty("DEBUG_AUTH_ERROR", tokenResponse.getErrorDescription());
                context.setProperty("DEBUG_AUTH_SUCCESS", "false");
                return false;
            }

            // Token exchange succeeded - store tokens in context.
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
            if (userInfoEndpoint != null && !userInfoEndpoint.trim().isEmpty()) {
                context.setProperty("DEBUG_USERINFO_ENDPOINT", userInfoEndpoint);
            }

            context.setProperty("step_connection_status", "success");
            context.setProperty("step_authentication_status", "success");

            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuth2 token exchange completed successfully for IdP: " + idpName);
            }

            return true;

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
     * Checks if an authenticator name is OAuth2/OIDC.
     * Supports multiple name variations.
     */
    private boolean isOAuth2Authenticator(String authName) {
        if (authName == null) {
            return false;
        }
        return "openidconnect".equals(authName) || "oauth2".equals(authName) ||
                "OIDCAuthenticator".equals(authName) || "OAuth2Authenticator".equals(authName);
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
     * OAuth2-specific implementation that parses ID token claims.
     * Generic claim mapping and formatting is handled by parent DebugProcessor class.
     *
     * @param context AuthenticationContext containing ID token and access token.
     * @return Map of extracted claims, or null if extraction fails.
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
            return null;
        }
    }

    /**
     * Parses JWT ID token and extracts claims from the payload.
     * Handles JWT format with three parts: header.payload.signature.
     *
     * @param idToken The JWT ID token.
     * @return Map of claims extracted from the token payload.
     */
    private Map<String, Object> parseIdTokenClaims(String idToken) {
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
     * Handles JSON parsing errors gracefully.
     *
     * @param json The JSON string to parse.
     * @return Map of claims from the JSON.
     */
    private Map<String, Object> parseJsonToClaims(String json) {
        try {
            if (json == null || json.trim().isEmpty()) {
                return new HashMap<>();
            }
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
     *
     * @param context AuthenticationContext containing UserInfo endpoint URL.
     * @param accessToken Access token for authorization.
     * @return Map of user claims from UserInfo endpoint, or empty map if call fails.
     */
    private Map<String, Object> callUserInfoEndpoint(AuthenticationContext context, String accessToken) {
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
            java.net.HttpURLConnection connection = (java.net.HttpURLConnection) url.openConnection();
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
            connection.disconnect();

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
        }
    }
}
