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
 * Supports both Builder pattern for clean construction and setters for incremental population.
 */
public class OIDCConfiguration {

    private String tokenEndpoint;
    private String clientId;
    private String clientSecret;
    private String userInfoEndpoint;
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
     * Private constructor for Builder pattern.
     *
     * @param builder Builder instance containing configuration values.
     */
    private OIDCConfiguration(Builder builder) {

        this.tokenEndpoint = builder.tokenEndpoint;
        this.clientId = builder.clientId;
        this.clientSecret = builder.clientSecret;
        this.userInfoEndpoint = builder.userInfoEndpoint;
        this.codeVerifier = builder.codeVerifier;
        this.callbackUrl = builder.callbackUrl;
        this.idpName = builder.idpName;
    }

    /**
     * Creates a new Builder instance for constructing OIDCConfiguration.
     *
     * @return New Builder instance.
     */
    public static Builder builder() {

        return new Builder();
    }

    /**
     * Validates that all required configuration values are present.
     * Required values: tokenEndpoint, clientId.
     *
     * @return true if configuration has all required values, false otherwise.
     */
    public boolean isValid() {

        return StringUtils.isNotBlank(tokenEndpoint) && StringUtils.isNotBlank(clientId);
    }

    /**
     * Checks if required endpoints are configured (non-null).
     * Less strict than isValid() - only checks for null, not empty strings.
     *
     * @return true if tokenEndpoint and clientId are not null.
     */
    public boolean hasRequiredEndpoints() {

        return tokenEndpoint != null && clientId != null;
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
        return Collections.unmodifiableList(errors);
    }

    /**
     * Checks if UserInfo endpoint is configured.
     *
     * @return true if userInfoEndpoint is not blank.
     */
    public boolean hasUserInfoEndpoint() {

        return StringUtils.isNotBlank(userInfoEndpoint);
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
     * Gets the UserInfo endpoint URL.
     *
     * @return UserInfo endpoint URL or null if not configured.
     */
    public String getUserInfoEndpoint() {

        return userInfoEndpoint;
    }

    /**
     * Sets the UserInfo endpoint URL.
     *
     * @param userInfoEndpoint UserInfo endpoint URL.
     */
    public void setUserInfoEndpoint(String userInfoEndpoint) {

        this.userInfoEndpoint = userInfoEndpoint;
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
                "tokenEndpoint='" + tokenEndpoint + '\'' +
                ", clientId='" + (clientId != null ? "****" : "null") + '\'' +
                ", clientSecret='" + (clientSecret != null ? "****" : "null") + '\'' +
                ", userInfoEndpoint='" + userInfoEndpoint + '\'' +
                ", callbackUrl='" + callbackUrl + '\'' +
                ", idpName='" + idpName + '\'' +
                '}';
    }

    /**
     * Builder class for constructing OIDCConfiguration instances.
     * Provides fluent API for setting configuration values.
     */
    public static class Builder {

        private String tokenEndpoint;
        private String clientId;
        private String clientSecret;
        private String userInfoEndpoint;
        private String codeVerifier;
        private String callbackUrl;
        private String idpName;

        /**
         * Private constructor - use OIDCConfiguration.builder() to create.
         */
        private Builder() {

            // Private constructor.
        }

        /**
         * Sets the token endpoint URL.
         *
         * @param tokenEndpoint Token endpoint URL.
         * @return This builder instance for chaining.
         */
        public Builder tokenEndpoint(String tokenEndpoint) {

            this.tokenEndpoint = tokenEndpoint;
            return this;
        }

        /**
         * Sets the OAuth2 client ID.
         *
         * @param clientId Client ID.
         * @return This builder instance for chaining.
         */
        public Builder clientId(String clientId) {

            this.clientId = clientId;
            return this;
        }

        /**
         * Sets the OAuth2 client secret.
         *
         * @param clientSecret Client secret.
         * @return This builder instance for chaining.
         */
        public Builder clientSecret(String clientSecret) {

            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * Sets the UserInfo endpoint URL.
         *
         * @param userInfoEndpoint UserInfo endpoint URL.
         * @return This builder instance for chaining.
         */
        public Builder userInfoEndpoint(String userInfoEndpoint) {

            this.userInfoEndpoint = userInfoEndpoint;
            return this;
        }

        /**
         * Sets the PKCE code verifier.
         *
         * @param codeVerifier Code verifier.
         * @return This builder instance for chaining.
         */
        public Builder codeVerifier(String codeVerifier) {

            this.codeVerifier = codeVerifier;
            return this;
        }

        /**
         * Sets the OAuth2 callback URL.
         *
         * @param callbackUrl Callback URL.
         * @return This builder instance for chaining.
         */
        public Builder callbackUrl(String callbackUrl) {

            this.callbackUrl = callbackUrl;
            return this;
        }

        /**
         * Sets the Identity Provider name.
         *
         * @param idpName IdP name.
         * @return This builder instance for chaining.
         */
        public Builder idpName(String idpName) {

            this.idpName = idpName;
            return this;
        }

        /**
         * Builds and returns an OIDCConfiguration instance.
         * Does not validate - call isValid() on returned instance to check validity.
         *
         * @return New OIDCConfiguration instance.
         */
        public OIDCConfiguration build() {

            return new OIDCConfiguration(this);
        }

        /**
         * Builds and returns an OIDCConfiguration instance after validating required fields.
         * Throws IllegalStateException if required fields are missing.
         *
         * @return New validated OIDCConfiguration instance.
         * @throws IllegalStateException If required fields (tokenEndpoint, clientId) are missing.
         */
        public OIDCConfiguration buildValidated() {

            OIDCConfiguration config = new OIDCConfiguration(this);
            List<String> errors = config.getValidationErrors();
            if (!errors.isEmpty()) {
                throw new IllegalStateException("Invalid OIDC configuration: " + String.join(", ", errors));
            }
            return config;
        }
    }
}
