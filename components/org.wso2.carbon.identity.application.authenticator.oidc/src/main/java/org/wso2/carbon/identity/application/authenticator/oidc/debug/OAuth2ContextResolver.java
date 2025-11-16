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


package org.wso2.carbon.identity.application.authenticator.oidc.debug;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.debug.framework.core.DebugContextResolver;
import org.wso2.carbon.identity.debug.framework.exception.ContextResolutionException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * OAuth2 context resolver for debug operations.
 * Extends the framework's DebugContextResolver to provide OAuth2-specific context resolution.
 * Resolves OAuth2-specific context from IdP configuration using IdentityProviderManager.
 */
public class OAuth2ContextResolver extends DebugContextResolver {

    private static final Log LOG = LogFactory.getLog(OAuth2ContextResolver.class);

    /**
     * Resolves and creates an OAuth2 debug context from the given HTTP request.
     *
     * @param request HTTP servlet request containing debug parameters (idpId, authenticator).
     * @return Map containing resolved OAuth2 debug context data.
     * @throws ContextResolutionException If context resolution fails.
     */
    @Override
    public Map<String, Object> resolveContext(HttpServletRequest request) throws ContextResolutionException {
        try {
            if (request == null) {
                throw new ContextResolutionException("HTTP request is null");
            }

            // Extract parameters from request.
            String idpId = request.getParameter("idpId");
            String authenticatorName = request.getParameter("authenticator");

            if (StringUtils.isEmpty(idpId)) {
                throw new ContextResolutionException("IdP ID parameter is missing");
            }
            
            // Validate IdP ID format to prevent injection attacks
            // Allow only alphanumeric, hyphens, underscores, and dots (UUIDs and typical names)
            if (!idpId.matches("^[a-zA-Z0-9._-]+$")) {
                throw new ContextResolutionException("Invalid IdP ID format - contains invalid characters");
            }
            
            // Validate authenticator name if provided
            if (StringUtils.isNotEmpty(authenticatorName) && 
                !authenticatorName.matches("^[a-zA-Z0-9._-]+$")) {
                throw new ContextResolutionException("Invalid authenticator name format - contains invalid characters");
            }

            return resolveContext(idpId, authenticatorName);
        } catch (ContextResolutionException e) {
            LOG.error("Error resolving OAuth2 debug context from request: " + e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error resolving OAuth2 debug context from request: " + e.getMessage(), e);
            throw new ContextResolutionException("Error resolving OAuth2 debug context: " + e.getMessage(), e);
        }
    }

    /**
     * Resolves and creates an OAuth2 debug context from a provided Map input.
     * This method is used by the API layer which invokes the resolver reflectively
     * with a Map argument containing keys such as `idpName` and `authenticatorName`.
     *
     * @param input Map containing debug request parameters (idpName, authenticatorName, etc.).
     * @return Map containing resolved OAuth2 debug context data.
     * @throws ContextResolutionException If context resolution fails.
     */
    public Map<String, Object> resolveContext(Map<String, Object> input) throws ContextResolutionException {
        if (input == null) {
            throw new ContextResolutionException("Input context map is null");
        }

        Object idpObj = input.get("idpName");
        String idpId = idpObj != null ? idpObj.toString() : null;

        Object authObj = input.get("authenticatorName");
        String authenticatorName = authObj != null ? authObj.toString() : null;

        // Fallback: some callers may use the key 'authenticator'.
        if (StringUtils.isEmpty(authenticatorName)) {
            Object altAuth = input.get("authenticator");
            if (altAuth != null) {
                authenticatorName = altAuth.toString();
            }
        }

        return resolveContext(idpId, authenticatorName);
    }

    /**
     * Resolves and creates an OAuth2 debug context with specific parameters.
     *
     * @param idpId         Identity Provider resource ID or name.
     * @param authenticator Optional authenticator name (defaults to first enabled OAuth2 authenticator).
     * @return Map containing resolved OAuth2 debug context data.
     * @throws ContextResolutionException If context resolution fails.
     */
    @Override
    public Map<String, Object> resolveContext(String idpId, String authenticator) throws ContextResolutionException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Resolving OAuth2 debug context for IdP: " + idpId + " with authenticator: " + authenticator);
        }

        if (StringUtils.isEmpty(idpId)) {
            throw new ContextResolutionException("IdP ID is null or empty");
        }

        Map<String, Object> context = new HashMap<>();
        try {
            // Use IdentityTenantUtil to resolve tenant domain dynamically.
            String tenantDomain = IdentityTenantUtil.resolveTenantDomain();

            // Retrieve IdP using IdentityProviderManager.
            IdentityProviderManager idpManager = IdentityProviderManager.getInstance();
            IdentityProvider idp = null;

            try {
                // First try to get by resource ID.
                idp = idpManager.getIdPByResourceId(idpId, tenantDomain, true);
            } catch (IdentityProviderManagementException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to get IdP by resource ID: " + e.getMessage(), e);
                }
            }

            // If not found by resource ID, try by name (legacy semantics accept either resource id or name).
            if (idp == null) {
                try {
                    idp = idpManager.getIdPByName(idpId, tenantDomain);
                } catch (IdentityProviderManagementException e2) {
                    throw new ContextResolutionException("IdP not found: " + idpId, e2);
                }
            }

            if (idp == null) {
                throw new ContextResolutionException("IdP not found: " + idpId);
            }

            if (!idp.isEnable()) {
                throw new ContextResolutionException("IdP is disabled: " + idp.getIdentityProviderName());
            }

            // Set IdP-specific context properties.
            context.put("DEBUG_IDP_NAME", idp.getIdentityProviderName());
            context.put("DEBUG_IDP_RESOURCE_ID", idp.getResourceId());
            context.put("DEBUG_IDP_DESCRIPTION", idp.getIdentityProviderDescription());
            context.put("IDP_CONFIG", idp);  // Store the full IdP config for debug processors

            // Find and extract OAuth2 authenticator configuration.
            FederatedAuthenticatorConfig authenticatorConfig = findOAuth2AuthenticatorConfig(idp, authenticator);
            if (authenticatorConfig == null) {
                // Log all available configs for this IdP to help diagnose why match failed.
                FederatedAuthenticatorConfig[] allConfigs = idp.getFederatedAuthenticatorConfigs();
                StringBuilder configList = new StringBuilder("Available authenticator configs for IdP '")
                        .append(idp.getIdentityProviderName()).append("':");
                if (allConfigs != null) {
                    for (FederatedAuthenticatorConfig cfg : allConfigs) {
                        if (cfg == null) {
                            configList.append(" [null]");
                        } else {
                            configList.append(" [name=").append(cfg.getName())
                                    .append(" enabled=").append(cfg.isEnabled()).append("]");
                        }
                    }
                } else {
                    configList.append(" [none]");
                }
                String msg = configList.toString();
                LOG.warn(msg);
                
                throw new ContextResolutionException("No OAuth2 authenticator configuration found for IdP: " +
                        idp.getIdentityProviderName());
            }

            // Extract OAuth2 parameters from authenticator configuration.
            extractOAuth2Parameters(authenticatorConfig, context, idp);

            // Set debug-specific properties.
            context.put("DEBUG_AUTHENTICATOR_NAME", authenticatorConfig.getName());
            // Legacy executor mapping: indicate which executor implementation should be used for this
            // authenticator. The executor wiring may use this key to instantiate or delegate to the
            // protocol-specific executor (keeps parity with legacy ContextProvider.createOAuth2DebugContext).
            String executorClass = null;
            String cfgName = authenticatorConfig.getName();
            if ("OpenIDConnectAuthenticator".equals(cfgName) ||
                "OAuth2OpenIDConnectAuthenticator".equals(cfgName)) {
                executorClass = "org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor";
            }
            if (executorClass != null) {
                context.put("DEBUG_EXECUTOR_CLASS", executorClass);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Mapped authenticator '" + cfgName + "' to executor '" + executorClass + "'.");
                }
            }
            context.put("isDebugFlow", Boolean.TRUE);
            context.put("DEBUG_SESSION_ID", java.util.UUID.randomUUID().toString());
            context.put("DEBUG_TIMESTAMP", System.currentTimeMillis());
            context.put("DEBUG_TENANT_DOMAIN", tenantDomain);
            context.put("DEBUG_REQUEST_TYPE", "DFDP_DEBUG");

            // Set context identifier (used for caching and callback).
            context.put("DEBUG_CONTEXT_ID", "debug-" + java.util.UUID.randomUUID().toString());

            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuth2 debug context resolved successfully for IdP: " + idp.getIdentityProviderName());
            }

            return context;

        } catch (ContextResolutionException e) {
            LOG.error("Error resolving OAuth2 debug context: " + e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error resolving OAuth2 debug context: " + e.getMessage(), e);
            throw new ContextResolutionException("Error resolving OAuth2 debug context: " + e.getMessage(), e);
        }
    }

    /**
     * Validates if this resolver can handle the given IdP.
     * Returns true if the IdP has at least one enabled OAuth2/OIDC authenticator.
     *
     * @param idpId Identity Provider ID to check.
     * @return true if this resolver can handle the IdP, false otherwise.
     */
    @Override
    public boolean canResolve(String idpId) {
        try {
            if (StringUtils.isEmpty(idpId)) {
                return false;
            }

            IdentityProviderManager idpManager = IdentityProviderManager.getInstance();
            IdentityProvider idp = null;
            // Use IdentityTenantUtil to resolve tenant domain dynamically.
            String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
            try {
                idp = idpManager.getIdPByResourceId(idpId, tenantDomain, true);
            } catch (IdentityProviderManagementException e) {
                try {
                    idp = idpManager.getIdPByName(idpId, tenantDomain);
                } catch (IdentityProviderManagementException e2) {
                    return false;
                }
            }

            if (idp == null || !idp.isEnable()) {
                return false;
            }

            // Check if IdP has at least one enabled OAuth2/OIDC authenticator.
            return findOAuth2AuthenticatorConfig(idp, null) != null;
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error checking if resolver can handle IdP: " + e.getMessage());
            }
            return false;
        }
    }

    /**
     * Finds the OAuth2/OIDC authenticator configuration in the IdP.
     * If authenticatorName is provided, finds the specific authenticator.
     * Otherwise, returns the first enabled OAuth2 authenticator.
     *
     * @param idp Identity Provider.
     * @param authenticatorName Optional specific authenticator name.
     * @return FederatedAuthenticatorConfig or null if not found.
     */
    private FederatedAuthenticatorConfig findOAuth2AuthenticatorConfig(IdentityProvider idp, 
                                                                      String authenticatorName) {
        FederatedAuthenticatorConfig[] configs = idp.getFederatedAuthenticatorConfigs();
        if (configs == null || configs.length == 0) {
            return null;
        }

        // If an authenticatorName is explicitly provided, prefer an exact match (legacy behavior).
        if (StringUtils.isNotEmpty(authenticatorName)) {
            for (FederatedAuthenticatorConfig config : configs) {
                if (config == null || !config.isEnabled()) {
                    continue;
                }
                String configName = config.getName();
                if (StringUtils.isEmpty(configName)) {
                    continue;
                }
                if (authenticatorName.equals(configName)) {
                    return config;
                }
            }
            // No exact match found for provided authenticator name.
            // If the provided authenticatorName is a generic protocol name (e.g., "oauth2", "oidc"),
            // fall back to legacy matching behavior to find a known OAuth2/OIDC authenticator.
            if ("oauth2".equalsIgnoreCase(authenticatorName) || 
                "oidc".equalsIgnoreCase(authenticatorName) ||
                "openid".equalsIgnoreCase(authenticatorName)) {
                // Fall through to legacy matching logic below.
            } else {
                return null;
            }
        }

        // Legacy behavior: select the first enabled authenticator that matches known OAuth2/OIDC implementations.
        for (FederatedAuthenticatorConfig config : configs) {
            if (config == null || !config.isEnabled()) {
                continue;
            }
            String configName = config.getName();
            if (StringUtils.isEmpty(configName)) {
                continue;
            }

            // Match OpenIDConnectAuthenticator (main OIDC implementation in this repo).
            if ("OpenIDConnectAuthenticator".equals(configName) ||
                "OAuth2OpenIDConnectAuthenticator".equals(configName)) {
                return config;
            }
        }

        // No known OAuth2/OIDC authenticator found.
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("No OAuth2 authenticator matched for IdP '").append(idp.getIdentityProviderName()).append("'. Available configs:");
            for (FederatedAuthenticatorConfig cfg : configs) {
                if (cfg == null) {
                    sb.append(" [null]");
                    continue;
                }
                sb.append(" [name=").append(cfg.getName())
                  .append(" enabled=").append(cfg.isEnabled()).append("]");
            }
            String warnMsg = sb.toString();
            LOG.warn(warnMsg);
        } catch (Throwable t) {
            LOG.warn("Failed to build authenticator config debug info: " + t.getMessage(), t);
        }

        return null;
    }

    /**
     * Extracts OAuth2 parameters from the authenticator configuration and stores them in context.
     * Uses executor-based resolution (like legacy ContextProvider) for better compatibility.
     *
     * @param config Authenticator configuration.
     * @param context Map to store extracted parameters.
     * @param idp Identity Provider.
     * @throws ContextResolutionException If required parameters are missing.
     */
    private void extractOAuth2Parameters(FederatedAuthenticatorConfig config, Map<String, Object> context, 
                                        IdentityProvider idp) throws ContextResolutionException {
        Property[] properties = config.getProperties();
        if (properties == null || properties.length == 0) {
            throw new ContextResolutionException("No properties found in authenticator configuration");
        }

        Map<String, String> propertyMap = new HashMap<>();
        for (Property prop : properties) {
            if (prop != null && prop.getName() != null) {
                propertyMap.put(prop.getName(), prop.getValue());
            }
        }

        // Create executor instance to resolve endpoints (like legacy ContextProvider does).
        Object executor = null;
        String cfgName = config.getName();
        if ("OpenIDConnectAuthenticator".equals(cfgName) || 
            "OAuth2OpenIDConnectAuthenticator".equals(cfgName)) {
            executor = createExecutor("org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor");
        }
        // Note: Google and GitHub authenticators are in separate repositories and will have their own resolver implementations.

        // Extract client ID (use property map directly).
        String clientId = propertyMap.get("ClientId");
        if (StringUtils.isEmpty(clientId)) {
            clientId = propertyMap.get("client_id");
        }
        if (StringUtils.isEmpty(clientId)) {
            clientId = propertyMap.get("OAuth2ClientId");
        }
        if (StringUtils.isEmpty(clientId)) {
            throw new ContextResolutionException("Client ID not found in authenticator configuration");
        }
        context.put("DEBUG_CLIENT_ID", clientId);

        // Extract authorization endpoint using executor resolution (with fallback).
        String authzEndpoint = getAuthorizationEndpointFromExecutor(executor, propertyMap, cfgName);
        if (StringUtils.isEmpty(authzEndpoint)) {
            // Fallback to direct property lookup with multiple key variants.
            authzEndpoint = propertyMap.get("AuthorizationEndpoint");
            if (StringUtils.isEmpty(authzEndpoint)) {
                authzEndpoint = propertyMap.get("Authorization Endpoint");
            }
            if (StringUtils.isEmpty(authzEndpoint)) {
                authzEndpoint = propertyMap.get("OAuth2AuthzEPUrl");
            }
            if (StringUtils.isEmpty(authzEndpoint)) {
                authzEndpoint = propertyMap.get("authorization_endpoint");
            }
        }
        if (StringUtils.isEmpty(authzEndpoint)) {
            throw new ContextResolutionException("Authorization endpoint not found in authenticator configuration");
        }
        context.put("DEBUG_AUTHZ_ENDPOINT", authzEndpoint);

        // Extract token endpoint using executor resolution (with fallback).
        String tokenEndpoint = getTokenEndpointFromExecutor(executor, propertyMap, cfgName);
        if (StringUtils.isEmpty(tokenEndpoint)) {
            // Fallback to direct property lookup with multiple key variants.
            tokenEndpoint = propertyMap.get("TokenEndpoint");
            if (StringUtils.isEmpty(tokenEndpoint)) {
                tokenEndpoint = propertyMap.get("Token Endpoint");
            }
            if (StringUtils.isEmpty(tokenEndpoint)) {
                tokenEndpoint = propertyMap.get("OAuth2TokenEPUrl");
            }
            if (StringUtils.isEmpty(tokenEndpoint)) {
                tokenEndpoint = propertyMap.get("token_endpoint");
            }
        }
        if (StringUtils.isEmpty(tokenEndpoint)) {
            throw new ContextResolutionException("Token endpoint not found in authenticator configuration");
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Resolved token endpoint: " + tokenEndpoint);
        }
        context.put("DEBUG_TOKEN_ENDPOINT", tokenEndpoint);

        // Extract scope with multiple fallback strategies.
        String scope = null;
        
        // Strategy 1: Check standard scope properties (case-sensitive variations).
        String[] scopePropertyNames = {"Scope", "scope", "SCOPE", "scopes", "requestedScope", 
                                       "requestedScopes"};
        for (String scopePropName : scopePropertyNames) {
            String scopeValue = propertyMap.get(scopePropName);
            if (StringUtils.isNotEmpty(scopeValue)) {
                scope = scopeValue;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found scope in property: " + scopePropName + " = " + scope);
                }
                break;
            }
        }
        
        // Strategy 2: Check AdditionalQueryParameters for scope (like Google OIDC uses).
        if (StringUtils.isEmpty(scope)) {
            String additionalParams = propertyMap.get("AdditionalQueryParameters");
            if (additionalParams != null && !additionalParams.isEmpty()) {
                scope = extractScopeFromQueryParams(additionalParams);
                if (StringUtils.isNotEmpty(scope) && LOG.isDebugEnabled()) {
                    LOG.debug("Found scope in AdditionalQueryParameters: " + scope);
                }
            }
        }
        
        // Strategy 3: Check executor's getScope method if available.
        if (StringUtils.isEmpty(scope) && executor != null) {
            try {
                java.lang.reflect.Method method = executor.getClass().getMethod("getScope", Map.class);
                Object result = method.invoke(executor, propertyMap);
                if (result != null && !result.toString().trim().isEmpty()) {
                    scope = result.toString();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Found scope via executor.getScope(): " + scope);
                    }
                }
            } catch (NoSuchMethodException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Executor does not have getScope(Map) method");
                }
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to get scope from executor: " + e.getMessage());
                }
            }
        }
        
        // Strategy 4: Only default to "openid" if absolutely no scope found anywhere.
        if (StringUtils.isEmpty(scope)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No scope found in configuration, defaulting to 'openid'");
            }
            scope = "openid";
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Final resolved scope for authorization URL: " + scope);
        }
        context.put("DEBUG_IDP_SCOPE", scope);

        // Extract optional parameters.
        String userInfoEndpoint = getOrNull(propertyMap, "UserInfoEndpoint", "User Info Endpoint", 
                                            "userinfo_endpoint");
        if (StringUtils.isNotEmpty(userInfoEndpoint)) {
            context.put("DEBUG_USERINFO_ENDPOINT", userInfoEndpoint);
        }

        String clientSecret = propertyMap.get("ClientSecret");
        if (StringUtils.isEmpty(clientSecret)) {
            clientSecret = propertyMap.get("client_secret");
        }
        if (StringUtils.isNotEmpty(clientSecret)) {
            context.put("DEBUG_CLIENT_SECRET", clientSecret);
        }

        String responseType = propertyMap.get("ResponseType");
        if (StringUtils.isEmpty(responseType)) {
            responseType = "code";
        }
        context.put("DEBUG_RESPONSE_TYPE", responseType);

        // Check if PKCE is enabled (PKCE is REQUIRED for debug flow).
        context.put("DEBUG_PKCE_ENABLED", true);
        context.put("DEBUG_PKCE_METHOD", "S256");

        if (LOG.isDebugEnabled()) {
            LOG.debug("OAuth2 parameters extracted successfully. ClientId: FOUND, AuthzEndpoint: " + authzEndpoint);
        }
    }

    /**
     * Creates an executor instance using reflection.
     * Returns null if the executor class is not available (extension not installed).
     *
     * @param executorClassName Fully qualified executor class name.
     * @return Executor instance or null if class not found.
     */
    private Object createExecutor(String executorClassName) {
        try {
            Class<?> executorClass = Class.forName(executorClassName);
            return executorClass.getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Executor class not found: " + executorClassName);
            }
            return null;
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to instantiate executor: " + executorClassName + ". " + e.getMessage());
            }
            return null;
        }
    }

    /**
     * Gets the authorization endpoint using executor instance with fallback to properties.
     *
     * @param executor Executor instance (can be null).
     * @param authenticatorProperties Authenticator properties map.
     * @param authenticatorName Name of the authenticator.
     * @return Authorization endpoint URL or null if not found.
     */
    private String getAuthorizationEndpointFromExecutor(Object executor,
            Map<String, String> authenticatorProperties, String authenticatorName) {
        if (executor != null) {
            try {
                // Try getAuthorizationServerEndpoint first.
                java.lang.reflect.Method method = executor.getClass()
                        .getMethod("getAuthorizationServerEndpoint", Map.class);
                Object result = method.invoke(executor, authenticatorProperties);
                if (result != null && !result.toString().trim().isEmpty()) {
                    return result.toString();
                }
            } catch (NoSuchMethodException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("getAuthorizationServerEndpoint method not found");
                }
                try {
                    // Try getAuthorizationEndpoint as alternative.
                    java.lang.reflect.Method altMethod = executor.getClass()
                            .getMethod("getAuthorizationEndpoint", Map.class);
                    Object result = altMethod.invoke(executor, authenticatorProperties);
                    if (result != null && !result.toString().trim().isEmpty()) {
                        return result.toString();
                    }
                } catch (Exception ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Alternative method also failed: " + ex.getMessage());
                    }
                }
            } catch (IllegalAccessException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Method not accessible: " + e.getMessage());
                }
            } catch (java.lang.reflect.InvocationTargetException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to invoke method: " + e.getMessage());
                }
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to get authorization endpoint from executor: " + e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * Gets the token endpoint using executor instance and its fallback logic.
     *
     * @param executor Executor instance (can be null if extension not available).
     * @param authenticatorProperties Authenticator properties map.
     * @param authenticatorName Name of the authenticator.
     * @return Token endpoint URL with fallback support.
     */
    private String getTokenEndpointFromExecutor(Object executor,
            Map<String, String> authenticatorProperties, String authenticatorName) {
        if (executor != null) {
            try {
                // Use reflection to call getTokenEndpoint method.
                java.lang.reflect.Method method = executor.getClass().getMethod("getTokenEndpoint", Map.class);
                Object result = method.invoke(executor, authenticatorProperties);
                if (result != null && !result.toString().trim().isEmpty()) {
                    return result.toString();
                }
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to get token endpoint from executor: " + e.getMessage());
                }
            }
        }
        
        // Fallback to direct property lookup.
        String tokenEndpoint = authenticatorProperties.get("OAuth2TokenEPUrl");
        if (tokenEndpoint != null && !tokenEndpoint.trim().isEmpty()) {
            return tokenEndpoint;
        }
        
        tokenEndpoint = authenticatorProperties.get("TokenEndpoint");
        if (tokenEndpoint != null && !tokenEndpoint.trim().isEmpty()) {
            return tokenEndpoint;
        }
        
        tokenEndpoint = authenticatorProperties.get("token_endpoint");
        if (tokenEndpoint != null && !tokenEndpoint.trim().isEmpty()) {
            return tokenEndpoint;
        }
        
        return null;
    }

    /**
     * Helper to extract scope from AdditionalQueryParameters.
     * Example: "scope=openid+email" or "scope=openid%20email".
     *
     * @param queryParams Query parameters string.
     * @return Extracted scope value or null if not found.
     */
    private String extractScopeFromQueryParams(String queryParams) {
        if (queryParams == null || queryParams.trim().isEmpty()) {
            return null;
        }
        try {
            String[] params = queryParams.split("&");
            for (String param : params) {
                if (param.startsWith("scope=")) {
                    String scope = param.substring("scope=".length());
                    scope = java.net.URLDecoder.decode(scope, "UTF-8");
                    return scope;
                }
            }
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error extracting scope from AdditionalQueryParameters: " + queryParams, e);
            }
        }
        return null;
    }

    /**
     * Helper to get first non-empty value from property map for multiple key variants.
     *
     * @param map Property map.
     * @param keys Possible key names to check (in order).
     * @return First non-empty value or null.
     */
    private String getOrNull(Map<String, String> map, String... keys) {
        if (map == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            String value = map.get(key);
            if (StringUtils.isNotEmpty(value)) {
                return value;
            }
        }
        return null;
    }
}
