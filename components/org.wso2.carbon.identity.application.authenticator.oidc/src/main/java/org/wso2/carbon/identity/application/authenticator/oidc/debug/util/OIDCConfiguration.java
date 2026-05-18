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

    public OIDCConfiguration() {

    }

    /**
     * Returns true if all required configuration values (tokenEndpoint, clientId, clientSecret) are present.
     *
     * @return true if configuration is complete, false otherwise.
     */
    public boolean isValid() {

        return StringUtils.isNotBlank(tokenEndpoint) && StringUtils.isNotBlank(clientId)
                && StringUtils.isNotBlank(clientSecret);
    }

    /**
     * Returns true if tokenEndpoint and clientId are present (client secret may still be missing).
     * Used to determine which specific configuration field is missing for targeted error messages.
     *
     * @return true if tokenEndpoint and clientId are present.
     */
    public boolean hasRequiredEndpoints() {

        return StringUtils.isNotBlank(tokenEndpoint) && StringUtils.isNotBlank(clientId);
    }

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

    @Override
    public String toString() {

        return "OIDCConfiguration{" +
                "tokenEndpoint='" + tokenEndpoint + '\'' +
                // clientId and clientSecret are credentials — masked in logs.
                ", clientId='" + (clientId != null ? "****" : "null") + '\'' +
                ", clientSecret='" + (clientSecret != null ? "****" : "null") + '\'' +
                ", callbackUrl='" + callbackUrl + '\'' +
                ", idpName='" + idpName + '\'' +
                '}';
    }
}
