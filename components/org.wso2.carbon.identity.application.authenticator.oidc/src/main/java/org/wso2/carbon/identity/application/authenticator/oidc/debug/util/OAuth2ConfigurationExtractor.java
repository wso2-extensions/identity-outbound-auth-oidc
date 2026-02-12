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

package org.wso2.carbon.identity.application.authenticator.oidc.debug.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.Property;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for extracting OAuth2 configuration parameters from IdP settings.
 * Provides centralized, testable configuration extraction with multiple fallback strategies.
 * Separates OAuth2 configuration logic from authentication/protocol flow logic.
 */
public class OAuth2ConfigurationExtractor {

    private static final Log LOG = LogFactory.getLog(OAuth2ConfigurationExtractor.class);

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private OAuth2ConfigurationExtractor() {
        
        // Prevent instantiation
    }

    /**
     * Property name variations for OAuth2 configuration parameters.
     */
    private static final String[] CLIENT_ID_PROPERTY_NAMES = {"ClientId", "client_id", "OAuth2ClientId"};
    private static final String[] CLIENT_SECRET_PROPERTY_NAMES = {"ClientSecret", "client_secret"};
    private static final String[] TOKEN_ENDPOINT_PROPERTY_NAMES = {"TokenEndpoint", "Token Endpoint", 
                                                                   "OAuth2TokenEPUrl", "token_endpoint"};
    private static final String[] AUTHZ_ENDPOINT_PROPERTY_NAMES = {"AuthorizationEndpoint", 
                                                                   "Authorization Endpoint", 
                                                                   "OAuth2AuthzEPUrl", "authorization_endpoint"};
    private static final String[] USERINFO_ENDPOINT_PROPERTY_NAMES = {"UserInfoEndpoint", "User Info Endpoint", 
                                                                      "userinfo_endpoint"};

    /**
     * Extracts OAuth2 configuration from a FederatedAuthenticatorConfig.
     * Returns a map with extracted configuration values (may be incomplete if some values are missing).
     * Caller should validate required fields are present.
     *
     * @param authenticatorConfig The authenticator configuration to extract from.
     * @return Map with extracted OAuth2 parameters (clientId, clientSecret, endpoints, etc.).
     */
    public static Map<String, String> extractConfiguration(FederatedAuthenticatorConfig authenticatorConfig) {

        Map<String, String> result = new HashMap<>();

        if (authenticatorConfig == null || authenticatorConfig.getProperties() == null) {
            return result;
        }

        // Build property map from authenticator properties.
        Map<String, String> propertyMap = buildPropertyMap(authenticatorConfig.getProperties());

        // Extract OAuth2 parameters using fallback strategies.
        extractClientId(propertyMap, result);
        extractClientSecret(propertyMap, result);
        extractTokenEndpoint(propertyMap, result);
        extractAuthorizationEndpoint(propertyMap, result);
        extractUserInfoEndpoint(propertyMap, result);

        return result;
    }

    /**
     * Builds a property map from Property array for easier lookups.
     * Handles null properties gracefully.
     *
     * @param properties Array of Property objects from authenticator config.
     * @return Map of property names to values.
     */
    private static Map<String, String> buildPropertyMap(Property[] properties) {

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

    /**
     * Extracts client ID from property map using multiple fallback property names.
     *
     * @param propertyMap Source property map.
     * @param result Result map to populate with "clientId" key.
     */
    private static void extractClientId(Map<String, String> propertyMap, Map<String, String> result) {

        String value = findPropertyValue(propertyMap, CLIENT_ID_PROPERTY_NAMES);
        if (value != null && !value.trim().isEmpty()) {
            result.put("clientId", value);
        }
    }

    /**
     * Extracts client secret from property map using multiple fallback property names.
     * Logs extraction with masked value for security.
     *
     * @param propertyMap Source property map.
     * @param result Result map to populate with "clientSecret" key.
     */
    private static void extractClientSecret(Map<String, String> propertyMap, Map<String, String> result) {

        String value = findPropertyValue(propertyMap, CLIENT_SECRET_PROPERTY_NAMES);
        if (value != null && !value.trim().isEmpty()) {
            result.put("clientSecret", value);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client secret found: " + (value.isEmpty() ? "EMPTY" : "PRESENT"));
            }
        }
    }

    /**
     * Extracts token endpoint from property map using multiple fallback property names.
     *
     * @param propertyMap Source property map.
     * @param result Result map to populate with "tokenEndpoint" key.
     */
    private static void extractTokenEndpoint(Map<String, String> propertyMap, Map<String, String> result) {

        String value = findPropertyValue(propertyMap, TOKEN_ENDPOINT_PROPERTY_NAMES);
        if (value != null && !value.trim().isEmpty()) {
            result.put("tokenEndpoint", value);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Token endpoint found: " + value);
            }
        }
    }

    /**
     * Extracts authorization endpoint from property map using multiple fallback property names.
     *
     * @param propertyMap Source property map.
     * @param result Result map to populate with "authzEndpoint" key.
     */
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
     * Extracts UserInfo endpoint from property map using multiple fallback property names.
     * UserInfo endpoint is optional.
     *
     * @param propertyMap Source property map.
     * @param result Result map to populate with "userInfoEndpoint" key (if found).
     */
    private static void extractUserInfoEndpoint(Map<String, String> propertyMap, Map<String, String> result) {

        String value = findPropertyValue(propertyMap, USERINFO_ENDPOINT_PROPERTY_NAMES);
        if (value != null && !value.trim().isEmpty()) {
            result.put("userInfoEndpoint", value);
        }
    }

    /**
     * Finds a property value using multiple fallback property names.
     * Returns first non-empty value found.
     *
     * @param propertyMap Source property map.
     * @param propertyNames Array of property names to try in order.
     * @return First non-empty value found, or null if none found.
     */
    private static String findPropertyValue(Map<String, String> propertyMap, String[] propertyNames) {

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

    /**
     * Validates that required OAuth2 configuration parameters are present.
     *
     * @param config Configuration map to validate.
     * @return true if clientId and tokenEndpoint are present, false otherwise.
     */
    public static boolean isValid(Map<String, String> config) {

        if (config == null) {
            return false;
        }

        String clientId = config.get("clientId");
        String tokenEndpoint = config.get("tokenEndpoint");

        return clientId != null && !clientId.trim().isEmpty() &&
               tokenEndpoint != null && !tokenEndpoint.trim().isEmpty();
    }

    /**
     * Retrieves a configuration value safely with null handling.
     *
     * @param config Configuration map.
     * @param key Key to retrieve.
     * @return Value or null if not present or empty.
     */
    public static String getConfigValue(Map<String, String> config, String key) {

        if (config == null || key == null) {
            return null;
        }

        String value = config.get(key);
        return (value != null && !value.trim().isEmpty()) ? value : null;
    }
}
