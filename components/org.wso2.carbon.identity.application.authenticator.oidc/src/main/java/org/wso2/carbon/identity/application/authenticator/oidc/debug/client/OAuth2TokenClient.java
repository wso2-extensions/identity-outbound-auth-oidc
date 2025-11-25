/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.debug.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.OAuth2DebugConstants;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Responsible for performing OAuth2 token exchanges. Isolates HTTP/network logic from higher-level processors.
 * OAuth2TokenClient is stateless and protocol-focused - it receives pre-extracted configuration from the caller.
 */
public class OAuth2TokenClient {

    private static final Log LOG = LogFactory.getLog(OAuth2TokenClient.class);

    /**
     * Exchange an authorization code for tokens using the Apache Oltu OAuth client.
     * All configuration parameters must be provided by the caller (typically OAuth2DebugProcessor).
     *
     * @param authorizationCode The authorization code from the IdP.
     * @param tokenEndpoint The token endpoint URL of the IdP.
     * @param clientId The OAuth2 client ID.
     * @param clientSecret The OAuth2 client secret.
     * @param redirectUri The redirect URI.
     * @param codeVerifier The PKCE code verifier (may be null).
     * @param idpName The IdP name for logging and special-case handling.
     * @return TokenResponse with either tokens or error details.
     */
    public TokenResponse exchangeCodeForTokens(String authorizationCode, String tokenEndpoint, String clientId,
            String clientSecret, String redirectUri, String codeVerifier, String idpName) {
        
        // Validate all required parameters.
        TokenResponse validationError = validateRequiredParameters(authorizationCode, tokenEndpoint, clientId,
                clientSecret, redirectUri);
        if (validationError != null) {
            return validationError;
        }

        try {
            OAuthClientRequest request = buildTokenRequest(tokenEndpoint, clientId, clientSecret, redirectUri,
                    authorizationCode, codeVerifier, idpName);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Exchanging authorization code for tokens at endpoint: " + tokenEndpoint + 
                        " for IdP: " + idpName);
            }

            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthJSONAccessTokenResponse oAuthResponse = oAuthClient.accessToken(request);

            return extractTokenResponse(oAuthResponse, idpName);
        } catch (Exception e) {
            return handleTokenExchangeError(e, idpName);
        }
    }

    /**
     * Validates that all required parameters are present and non-empty.
     *
     * @param authorizationCode The authorization code from the IdP.
     * @param tokenEndpoint The token endpoint URL of the IdP.
     * @param clientId The OAuth2 client ID.
     * @param clientSecret The OAuth2 client secret.
     * @param redirectUri The redirect URI.
     * @return TokenResponse with error if validation fails, null if all parameters are valid.
     */
    private TokenResponse validateRequiredParameters(String authorizationCode, String tokenEndpoint,
            String clientId, String clientSecret, String redirectUri) {

        if (authorizationCode == null || authorizationCode.trim().isEmpty()) {
            return new TokenResponse(OAuth2DebugConstants.ERROR_CODE_INVALID_REQUEST, "Authorization code is required",
                    "Authorization code parameter was null or empty");
        }
        if (tokenEndpoint == null || tokenEndpoint.trim().isEmpty()) {
            return new TokenResponse(OAuth2DebugConstants.ERROR_CODE_INVALID_REQUEST, "Token endpoint URL is required",
                    "Token endpoint URL was null or empty");
        }
        if (clientId == null || clientId.trim().isEmpty()) {
            return new TokenResponse(OAuth2DebugConstants.ERROR_CODE_INVALID_REQUEST, "Client ID is required",
                    "Client ID was null or empty");
        }
        if (clientSecret == null || clientSecret.trim().isEmpty()) {
            return new TokenResponse(OAuth2DebugConstants.ERROR_CODE_INVALID_REQUEST, "Client secret is required",
                    "Client secret was null or empty");
        }
        if (redirectUri == null || redirectUri.trim().isEmpty()) {
            return new TokenResponse(OAuth2DebugConstants.ERROR_CODE_INVALID_REQUEST, "Redirect URI is required",
                    "Redirect URI was null or empty");
        }
        return null;
    }

    /**
     * Builds the OAuth2 token request with appropriate headers and parameters.
     *
     * @param tokenEndpoint The token endpoint URL.
     * @param clientId The OAuth2 client ID.
     * @param clientSecret The OAuth2 client secret.
     * @param redirectUri The redirect URI.
     * @param authorizationCode The authorization code.
     * @param codeVerifier The PKCE code verifier (may be null).
     * @param idpName The IdP name for special handling.
     * @return Configured OAuthClientRequest ready to send.
     */
    private OAuthClientRequest buildTokenRequest(String tokenEndpoint, String clientId, String clientSecret,
            String redirectUri, String authorizationCode, String codeVerifier, String idpName) {

        try {
            OAuthClientRequest request = OAuthClientRequest.tokenLocation(tokenEndpoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(clientId)
                    .setClientSecret(clientSecret)
                    .setRedirectURI(redirectUri)
                    .setCode(authorizationCode)
                    .setParameter("code_verifier", codeVerifier)
                    .buildBodyMessage();

            // Add Accept: application/json header for GitHub token endpoint and other special cases.
            if (idpName != null && idpName.toLowerCase().contains("github")) {
                request.addHeader("Accept", "application/json");
            }

            return request;
        } catch (Exception e) {
            // Re-throw to be caught by the calling method's try-catch.
            throw new IllegalStateException("Failed to build OAuth2 token request", e);
        }
    }

    /**
     * Extracts tokens from the OAuth2 response.
     *
     * @param oAuthResponse The OAuth2 response from the IdP.
     * @param idpName The IdP name for logging.
     * @return TokenResponse with extracted tokens.
     */
    private TokenResponse extractTokenResponse(OAuthJSONAccessTokenResponse oAuthResponse, String idpName) {

        String accessToken = oAuthResponse.getAccessToken();
        String refreshToken = oAuthResponse.getRefreshToken();
        String tokenType = oAuthResponse.getParam("token_type");
        String idToken = oAuthResponse.getParam("id_token");

        if (LOG.isDebugEnabled()) {
            LOG.debug("Token exchange successful for IdP: " + idpName + ", received access_token and token_type.");
        }

        return new TokenResponse(accessToken, idToken, refreshToken, tokenType);
    }

    /**
     * Handles errors that occur during token exchange.
     *
     * @param e The exception that occurred.
     * @param idpName The IdP name for logging.
     * @return TokenResponse with error details.
     */
    private TokenResponse handleTokenExchangeError(Exception e, String idpName) {

        String errorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
        String errorCode = extractErrorCode(e);
        String enhancedDetails = buildDetailedErrorDescription(e, errorCode);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Token exchange failed with error code: " + errorCode + ", message: " + errorMessage + 
                    ". IdP: " + idpName);
        }
        LOG.error("Token exchange failed for IdP: " + idpName + " - Code: " + errorCode + 
                ", Message: " + errorMessage, e);

        return new TokenResponse(errorCode, errorMessage, enhancedDetails);
    }

    /**
     * Extracts error code from OAuth exceptions with comprehensive pattern matching.
     *
     * @param e The exception to extract error code from.
     * @return Error code string or generic TOKEN_EXCHANGE_ERROR if code cannot be determined.
     */
    private String extractErrorCode(Exception e) {

        if (e == null) {
            return "TOKEN_EXCHANGE_ERROR";
        }
        String exceptionMessage = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
        if (exceptionMessage.contains("invalid_client")) {
            return "INVALID_CLIENT";
        } else if (exceptionMessage.contains("invalid_grant")) {
            return "INVALID_GRANT";
        } else if (exceptionMessage.contains("unauthorized")) {
            return "UNAUTHORIZED";
        } else if (exceptionMessage.contains("invalid_request")) {
            return OAuth2DebugConstants.ERROR_CODE_INVALID_REQUEST;
        } else if (exceptionMessage.contains("unsupported_grant_type")) {
            return "UNSUPPORTED_GRANT_TYPE";
        } else if (exceptionMessage.contains("connection")) {
            return "CONNECTION_ERROR";
        } else if (exceptionMessage.contains("timeout")) {
            return "TIMEOUT_ERROR";
        } else if (exceptionMessage.contains("ssl") || exceptionMessage.contains("certificate")) {
            return "SSL_CERTIFICATE_ERROR";
        } else {
            return "TOKEN_EXCHANGE_ERROR";
        }
    }

    /**
     * Builds a detailed error description from exception details.
     * Focuses on actionable information without verbose stack traces.
     *
     * @param e The exception that occurred.
     * @param errorCode The error code extracted from the exception.
     * @param idpName The Identity Provider name for context in error message.
     * @return A detailed error description with troubleshooting hints.
     */
    private String buildDetailedErrorDescription(Exception e, String errorCode) {

        StringBuilder details = new StringBuilder();
        
        // Add context-specific troubleshooting hints.
        switch (errorCode) {
            case "INVALID_CLIENT":
                details.append("Client credentials are invalid. Verify that the Client ID and Client Secret ")
                    .append("are correct in the IdP authenticator configuration.");
                break;
            case "INVALID_GRANT":
                details.append("The authorization code may have expired (usually after 5-10 minutes) ")
                    .append("or was already used. Start the authentication process again to get a new ")
                    .append("authorization code.");
                break;
            case OAuth2DebugConstants.ERROR_CODE_INVALID_REQUEST:
                details.append("The token request is malformed. Verify redirect URI and PKCE parameters ")
                    .append("are configured correctly.");
                break;
            case "UNAUTHORIZED":
                details.append("The IdP rejected the request. Check that client credentials are correct ")
                    .append("and the authenticator type matches the IdP's requirements.");
                break;
            case "CONFIG_MISSING":
                details.append("Required OAuth 2.0 configuration is missing. Verify that Client ID, ")
                    .append("Client Secret, and Token Endpoint URL are all configured in the IdP ")
                    .append("authenticator settings.");
                break;
            case "CONNECTION_ERROR":
                details.append("Cannot connect to the IdP token endpoint. Verify the token endpoint URL ")
                    .append("is correct and the IdP server is reachable.");
                break;
            case "TIMEOUT_ERROR":
                details.append("The request to the IdP token endpoint timed out. ")
                    .append("Check if the IdP server is running and network connectivity is available.");
                break;
            case "SSL_CERTIFICATE_ERROR":
                details.append("SSL certificate validation failed. Verify that the IdP's SSL certificate ")
                    .append("is valid and trusted.");
                break;
            default:
                details.append("An error occurred during token exchange.")
                    .append(" Check the error code and message for details: ").append(e.getMessage());
        }
        
        return details.toString();
    }

    /**
     * Fetches UserInfo claims using the provided access token and endpoint.
     * HttpFetcher implementation must be injected to allow for flexibility (real HTTP or mocked in tests).
     *
     * @param accessToken The OAuth2 access token.
     * @param userInfoEndpoint The UserInfo endpoint URL.
     * @param fetcher The HttpFetcher implementation to use for fetching.
     * @return Map of user claims from the UserInfo endpoint.
     */
    public Map<String, Object> fetchUserInfoClaims(String accessToken, String userInfoEndpoint, HttpFetcher fetcher) {
        
        if (userInfoEndpoint == null || userInfoEndpoint.trim().isEmpty() || fetcher == null) {
            return Collections.emptyMap();
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + accessToken);
        // Add Accept header for GitHub API if endpoint is GitHub.
        if (userInfoEndpoint.contains("api.github.com")) {
            headers.put("Accept", "application/vnd.github.v3+json");
        }
        return fetcher.getJson(userInfoEndpoint, headers);
    }
}
