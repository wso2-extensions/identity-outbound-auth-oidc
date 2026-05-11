/*
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

package org.wso2.carbon.identity.application.authenticator.oidc.debug.util;

import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Data holder for OIDC configuration values extracted from IdP settings.
 * Provides validation and null-safe access to required endpoints and credentials.
 */
public class OIDCConfiguration {

    private String tokenEndpoint;
    private String clientId;
    private String clientSecret;
    private String codeVerifier;
    private String callbackUrl;
    private String idpName;

    /**
     * Default constructor for incremental population via setters.
     */
    public OIDCConfiguration() {

        // Default constructor.
    }

    /**
     * Validates that all required configuration values are present.
     * Required values: tokenEndpoint, clientId, clientSecret.
     *
     * @return true if configuration has all required values, false otherwise.
     */
    public boolean isValid() {

        return StringUtils.isNotBlank(tokenEndpoint) && StringUtils.isNotBlank(clientId)
                && StringUtils.isNotBlank(clientSecret);
    }

    /**
     * Checks if required endpoints are configured.
     *
     * @return true if tokenEndpoint and clientId are not null.
     */
    public boolean hasRequiredEndpoints() {

        return StringUtils.isNotBlank(tokenEndpoint) && StringUtils.isNotBlank(clientId);
    }

    /**
     * Returns list of validation errors for required fields.
     * Useful for detailed error reporting.
     *
     * @return List of validation error messages, empty if valid.
     */
    public List<String> getValidationErrors() {

        List<String> errors = new ArrayList<>();
        if (StringUtils.isBlank(tokenEndpoint)) {
            errors.add("Token endpoint is required but not configured");
        }
        if (StringUtils.isBlank(clientId)) {
            errors.add("Client ID is required but not configured");
        }
        if (StringUtils.isBlank(clientSecret)) {
            errors.add("Client secret is required but not configured");
        }
        return Collections.unmodifiableList(errors);
    }

    /**
     * Checks if PKCE code verifier is configured.
     *
     * @return true if codeVerifier is not blank.
     */
    public boolean hasCodeVerifier() {

        return StringUtils.isNotBlank(codeVerifier);
    }

    // Getters and Setters.

    /**
     * Gets the token endpoint URL.
     *
     * @return Token endpoint URL or null if not configured.
     */
    public String getTokenEndpoint() {

        return tokenEndpoint;
    }

    /**
     * Sets the token endpoint URL.
     *
     * @param tokenEndpoint Token endpoint URL.
     */
    public void setTokenEndpoint(String tokenEndpoint) {

        this.tokenEndpoint = tokenEndpoint;
    }

    /**
     * Gets the OAuth2 client ID.
     *
     * @return Client ID or null if not configured.
     */
    public String getClientId() {

        return clientId;
    }

    /**
     * Sets the OAuth2 client ID.
     *
     * @param clientId Client ID.
     */
    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    /**
     * Gets the OAuth2 client secret.
     *
     * @return Client secret or null if not configured.
     */
    public String getClientSecret() {

        return clientSecret;
    }

    /**
     * Sets the OAuth2 client secret.
     *
     * @param clientSecret Client secret.
     */
    public void setClientSecret(String clientSecret) {

        this.clientSecret = clientSecret;
    }

    /**
     * Gets the PKCE code verifier.
     *
     * @return Code verifier or null if not configured.
     */
    public String getCodeVerifier() {

        return codeVerifier;
    }

    /**
     * Sets the PKCE code verifier.
     *
     * @param codeVerifier Code verifier.
     */
    public void setCodeVerifier(String codeVerifier) {

        this.codeVerifier = codeVerifier;
    }

    /**
     * Gets the OAuth2 callback URL.
     *
     * @return Callback URL or null if not configured.
     */
    public String getCallbackUrl() {

        return callbackUrl;
    }

    /**
     * Sets the OAuth2 callback URL.
     *
     * @param callbackUrl Callback URL.
     */
    public void setCallbackUrl(String callbackUrl) {

        this.callbackUrl = callbackUrl;
    }

    /**
     * Gets the Identity Provider name.
     *
     * @return IdP name or null if not configured.
     */
    public String getIdpName() {

        return idpName;
    }

    /**
     * Sets the Identity Provider name.
     *
     * @param idpName IdP name.
     */
    public void setIdpName(String idpName) {

        this.idpName = idpName;
    }

    @Override
    public String toString() {

        return "OIDCConfiguration{" +
                // tokenEndpoint is a public URL — not masked
                "tokenEndpoint='" + tokenEndpoint + '\'' +
                // clientId and clientSecret are credentials — masked
                ", clientId='" + (clientId != null ? "****" : "null") + '\'' +
                ", clientSecret='" + (clientSecret != null ? "****" : "null") + '\'' +
                ", callbackUrl='" + callbackUrl + '\'' +
                ", idpName='" + idpName + '\'' +
                '}';
    }
}
