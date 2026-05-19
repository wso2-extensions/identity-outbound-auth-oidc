/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

import java.util.Objects;

/**
 * Immutable value object representing the outcome of an OAuth2 token exchange.
 * Constructed exclusively through the {@link #success} and {@link #error} factory methods.
 * Callers should check {@link #hasError()} before accessing token fields.
 */
public class TokenResponse {

    private final String accessToken;
    private final String idToken;
    private final String refreshToken;
    private final String tokenType;
    private final String errorCode;
    private final String errorDescription;

    private TokenResponse(String accessToken, String idToken, String refreshToken, String tokenType,
            String errorCode, String errorDescription) {

        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.tokenType = tokenType;
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }

    /**
     * Creates a successful token response.
     *
     * @param accessToken  OAuth2 access token (required).
     * @param idToken      OIDC ID token, may be null for non-OIDC flows.
     * @param refreshToken Refresh token, may be null.
     * @param tokenType    Token type (e.g. "Bearer"), may be null.
     * @return TokenResponse representing a successful exchange.
     */
    public static TokenResponse success(String accessToken, String idToken, String refreshToken, String tokenType) {

        Objects.requireNonNull(accessToken, "accessToken required for success response");
        return new TokenResponse(accessToken, idToken, refreshToken, tokenType, null, null);
    }

    /**
     * Creates an error token response.
     *
     * @param errorCode        OAuth2 error code (e.g. {@code "invalid_grant"}, required).
     * @param errorDescription Human-readable description of the error.
     * @return TokenResponse representing a failed exchange.
     */
    public static TokenResponse error(String errorCode, String errorDescription) {

        Objects.requireNonNull(errorCode, "errorCode required for error response");
        return new TokenResponse(null, null, null, null, errorCode, errorDescription);
    }

    /**
     * Returns the OAuth2 access token.
     * Null when {@link #hasError()} is true.
     *
     * @return Access token string, or null on error.
     */
    public String getAccessToken() {

        return accessToken;
    }

    /**
     * Returns the OIDC ID token.
     * May be null even on success for non-OIDC IdPs.
     *
     * @return ID token string, or null if not present.
     */
    public String getIdToken() {

        return idToken;
    }

    /**
     * Returns the OAuth2 refresh token.
     * May be null if the IdP did not issue one.
     *
     * @return Refresh token string, or null if not present.
     */
    public String getRefreshToken() {

        return refreshToken;
    }

    /**
     * Returns the token type (e.g. {@code "Bearer"}).
     *
     * @return Token type string, or null if not present.
     */
    public String getTokenType() {

        return tokenType;
    }

    /**
     * Returns true if this response represents a failed token exchange.
     * When true, {@link #getErrorCode()} and {@link #getErrorDescription()} contain failure details.
     *
     * @return true if the exchange failed, false on success.
     */
    public boolean hasError() {

        return errorCode != null;
    }

    /**
     * Returns the OAuth2 error code from a failed exchange.
     * Null when {@link #hasError()} is false.
     *
     * @return Error code string, or null on success.
     */
    public String getErrorCode() {

        return errorCode;
    }

    /**
     * Returns a human-readable description of the error.
     * Null when {@link #hasError()} is false.
     *
     * @return Error description string, or null on success.
     */
    public String getErrorDescription() {

        return errorDescription;
    }
}
