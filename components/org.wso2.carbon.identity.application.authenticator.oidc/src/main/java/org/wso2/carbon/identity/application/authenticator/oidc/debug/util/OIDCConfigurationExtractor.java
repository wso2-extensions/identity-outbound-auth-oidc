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

package org.wso2.carbon.identity.application.authenticator.oidc.debug.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.Property;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility class for extracting OAuth2 configuration parameters from IdP settings.
 * Provides centralized, testable configuration extraction with multiple fallback strategies.
 * Separates OAuth2 configuration logic from authentication/protocol flow logic.
 */
public class OIDCConfigurationExtractor {

    private static final Log LOG = LogFactory.getLog(OIDCConfigurationExtractor.class);

    private OIDCConfigurationExtractor() {

    }

    // Single source of truth for property key lookups — shared with OIDCContextProvider.
    private static final List<String> CLIENT_ID_PROPERTY_NAMES = Arrays.asList(
            "ClientId", "client_id", "OAuth2ClientId", "OIDCClientId");
    private static final List<String> CLIENT_SECRET_PROPERTY_NAMES = Arrays.asList(
            "ClientSecret", "client_secret");
    private static final List<String> TOKEN_ENDPOINT_PROPERTY_NAMES = Arrays.asList(
            "TokenEndpoint", "Token Endpoint", "OAuth2TokenEPUrl", "OIDCTokenEPUrl", "token_endpoint");
    private static final List<String> AUTHZ_ENDPOINT_PROPERTY_NAMES = Arrays.asList(
            "AuthorizationEndpoint", "Authorization Endpoint",
            "OAuth2AuthzEPUrl", "OIDCAuthzEPUrl", "authorization_endpoint");
    private static final List<String> SCOPE_PROPERTY_NAMES = Arrays.asList(
            "Scope", "scope", "SCOPE", "scopes", "requestedScope", "requestedScopes");

    /**
     * Extracts OAuth2 configuration from a FederatedAuthenticatorConfig.
     * Returns a map with extracted configuration values; may be incomplete if some values are missing.
     * Caller is responsible for validating required fields are present.
     *
     * @param authenticatorConfig The authenticator configuration to extract from.
     * @return Map with extracted OAuth2 parameters (clientId, clientSecret, endpoints, etc.).
     */
    public static Map<String, String> extractConfiguration(FederatedAuthenticatorConfig authenticatorConfig) {

        Map<String, String> result = new HashMap<>();

        if (authenticatorConfig == null || authenticatorConfig.getProperties() == null) {
            return result;
        }

        Map<String, String> propertyMap = buildPropertyMap(authenticatorConfig.getProperties());

        extractClientId(propertyMap, result);
        extractClientSecret(propertyMap, result);
        extractTokenEndpoint(propertyMap, result);
        extractAuthorizationEndpoint(propertyMap, result);

        return result;
    }

    /**
     * Builds a name-to-value map from a Property array.
     * Public to allow reuse across the debug package hierarchy.
     *
     * @param properties Array of Property objects from authenticator config.
     * @return Map of property names to values.
     */
    public static Map<String, String> buildPropertyMap(Property[] properties) {

        Map<String, String> propertyMap = new HashMap<>();
        if (properties != null) {
            for (Property prop : properties) {
                if (prop != null && prop.getName() != null && prop.getValue() != null) {
                    propertyMap.put(prop.getName(), prop.getValue());
                }
            }
        }
        return propertyMap;
    }

    private static void extractClientId(Map<String, String> propertyMap, Map<String, String> result) {

        String value = findPropertyValue(propertyMap, CLIENT_ID_PROPERTY_NAMES);
        if (value != null && !value.trim().isEmpty()) {
            result.put("clientId", value);
        }
    }

    private static void extractClientSecret(Map<String, String> propertyMap, Map<String, String> result) {

        String value = findPropertyValue(propertyMap, CLIENT_SECRET_PROPERTY_NAMES);
        if (value != null && !value.trim().isEmpty()) {
            result.put("clientSecret", value);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client secret found: PRESENT");
            }
        }
    }

    private static void extractTokenEndpoint(Map<String, String> propertyMap, Map<String, String> result) {

        String value = findPropertyValue(propertyMap, TOKEN_ENDPOINT_PROPERTY_NAMES);
        if (value != null && !value.trim().isEmpty()) {
            result.put("tokenEndpoint", value);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Token endpoint found: " + value);
            }
        }
    }

    private static void extractAuthorizationEndpoint(Map<String, String> propertyMap, Map<String, String> result) {

        String value = findPropertyValue(propertyMap, AUTHZ_ENDPOINT_PROPERTY_NAMES);
        if (value != null && !value.trim().isEmpty()) {
            result.put("authzEndpoint", value);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authorization endpoint found: " + value);
            }
        }
    }

    /**
     * Returns the first non-empty value from the property map matching any of the given names, or null if none found.
     * Public to allow reuse across the debug package hierarchy.
     *
     * @param propertyMap   Source property map.
     * @param propertyNames Property names to try in order.
     * @return First non-empty value found, or null.
     */
    public static String findPropertyValue(Map<String, String> propertyMap, List<String> propertyNames) {

        if (propertyMap == null || propertyNames == null) {
            return null;
        }

        for (String propName : propertyNames) {
            String value = propertyMap.get(propName);
            if (value != null && !value.trim().isEmpty()) {
                return value;
            }
        }

        return null;
    }

    public static List<String> getClientSecretPropertyNames() {

        return CLIENT_SECRET_PROPERTY_NAMES;
    }

    public static List<String> getClientIdPropertyNames() {

        return CLIENT_ID_PROPERTY_NAMES;
    }

    public static List<String> getTokenEndpointPropertyNames() {

        return TOKEN_ENDPOINT_PROPERTY_NAMES;
    }

    public static List<String> getAuthorizationEndpointPropertyNames() {

        return AUTHZ_ENDPOINT_PROPERTY_NAMES;
    }

    public static List<String> getScopePropertyNames() {

        return SCOPE_PROPERTY_NAMES;
    }
}
