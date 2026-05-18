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

package org.wso2.carbon.identity.application.authenticator.oidc.debug;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCConfigurationExtractor;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugContextProvider;
import org.wso2.carbon.identity.debug.framework.exception.ContextResolutionException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

/**
 * OIDC context resolver for debug operations.
 * Extends the framework's IdpDebugContextProvider to provide OIDC-specific context resolution from IdP configuration.
 */
public class OIDCContextProvider extends IdpDebugContextProvider {

    private static final Log LOG = LogFactory.getLog(OIDCContextProvider.class);
    private static final Pattern SAFE_ID_PATTERN = Pattern.compile("[a-zA-Z0-9._-]+");

    /**
     * Resolves and creates an OIDC debug context from the given HTTP request.
     *
     * @param request HTTP servlet request containing debug parameters (idpId, authenticator).
     * @return DebugContext containing resolved OIDC debug context data.
     * @throws ContextResolutionException If context resolution fails.
     */
    public DebugContext resolveContext(HttpServletRequest request) throws ContextResolutionException {

        try {
            if (request == null) {
                throw new ContextResolutionException("HTTP request is null");
            }

            String idpId = request.getParameter(OIDCDebugConstants.PARAM_IDP_ID);
            String authenticatorName = request.getParameter(OIDCDebugConstants.PARAM_AUTHENTICATOR);

            if (StringUtils.isEmpty(idpId)) {
                throw new ContextResolutionException("IdP ID parameter is missing");
            }

            // Allow only alphanumeric, hyphens, underscores, and dots to prevent injection.
            if (!SAFE_ID_PATTERN.matcher(idpId).matches()) {
                throw new ContextResolutionException("Invalid IdP ID format - contains invalid characters");
            }

            if (StringUtils.isNotEmpty(authenticatorName) &&
                    !SAFE_ID_PATTERN.matcher(authenticatorName).matches()) {
                throw new ContextResolutionException("Invalid authenticator name format - contains invalid characters");
            }

            return resolveContext(idpId, authenticatorName);
        } catch (ContextResolutionException e) {
            LOG.error("Error resolving OIDC debug context from request: " + e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error resolving OIDC debug context from request: " + e.getMessage(), e);
            throw new ContextResolutionException("CTX-50001", "Error resolving OIDC debug context",
                    e.getMessage(), e);
        }
    }

    /**
     * Resolves and creates an OIDC debug context with specific parameters.
     *
     * @param idpId         Identity Provider resource ID or name.
     * @param authenticator Optional authenticator name (defaults to first enabled OIDC authenticator).
     * @return DebugContext containing resolved OIDC debug context data.
     * @throws ContextResolutionException If context resolution fails.
     */
    @Override
    public DebugContext resolveContext(String idpId, String authenticator) throws ContextResolutionException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Resolving OIDC debug context for IdP: " + idpId + " with authenticator: " + authenticator);
        }

        if (StringUtils.isEmpty(idpId)) {
            throw new ContextResolutionException("IdP ID is null or empty");
        }

        Map<String, Object> contextMap = new HashMap<>();
        try {
            String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
            if (StringUtils.isEmpty(tenantDomain)) {
                throw new ContextResolutionException("CTX-50002",
                        "Unable to resolve tenant domain for OIDC debug context",
                        "Tenant domain is not available in the current execution context.");
            }
            IdentityProvider idp = retrieveIdentityProvider(idpId, tenantDomain);
            validateIdpIsEnabled(idp);
            populateIdpContextProperties(contextMap, idp);

            FederatedAuthenticatorConfig authenticatorConfig = findOIDCAuthenticatorConfig(idp, authenticator);
            if (authenticatorConfig == null) {
                logAvailableAuthenticators(idp);
                throw new ContextResolutionException("No OIDC authenticator configuration found for IdP: " +
                        idp.getIdentityProviderName());
            }

            extractOIDCParameters(authenticatorConfig, contextMap);
            populateAuthenticatorContextProperties(contextMap, authenticatorConfig);
            populateDebugSessionProperties(contextMap, tenantDomain);

            if (LOG.isDebugEnabled()) {
                LOG.debug("OIDC debug context resolved successfully for IdP: " + idp.getIdentityProviderName());
            }

            return DebugContext.buildFromMap(contextMap);

        } catch (ContextResolutionException e) {
            LOG.error("Error resolving OIDC debug context: " + e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error resolving OIDC debug context: " + e.getMessage(), e);
            throw new ContextResolutionException("CTX-50001", "Error resolving OIDC debug context",
                    e.getMessage(), e);
        }
    }

    /**
     * Retrieves the IdP by resource ID first (UUID lookup), falling back to name lookup if not found.
     * Both strategies are attempted because callers may pass either a resource ID or an IdP name.
     */
    private IdentityProvider retrieveIdentityProvider(String idpId, String tenantDomain)
            throws ContextResolutionException {

        try {
            IdentityProviderManager idpManager = IdentityProviderManager.getInstance();
            IdentityProvider idp = idpManager.getIdPByResourceId(idpId, tenantDomain, true);
            if (idp == null) {
                idp = idpManager.getIdPByName(idpId, tenantDomain, true);
            }
            if (idp == null) {
                throw new ContextResolutionException("CTX-40401", "IdP not found: " + idpId,
                        "Identity Provider with ID or name '" + idpId + "' does not exist.");
            }
            return idp;
        } catch (ContextResolutionException e) {
            throw e;
        } catch (IdentityProviderManagementException e) {
            throw new ContextResolutionException("CTX-50001",
                    "Failed to retrieve IdP: " + idpId, e.getMessage(), e);
        } catch (Exception e) {
            throw new ContextResolutionException("CTX-50001",
                    "Unexpected error retrieving IdP: " + idpId, e.getMessage(), e);
        }
    }

    private void validateIdpIsEnabled(IdentityProvider idp) throws ContextResolutionException {

        if (!idp.isEnable()) {
            throw new ContextResolutionException("IdP is not available: " + idp.getIdentityProviderName());
        }
    }

    private void populateIdpContextProperties(Map<String, Object> context, IdentityProvider idp) {

        context.put(OIDCDebugConstants.DEBUG_IDP_NAME, idp.getIdentityProviderName());
        context.put(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID,
                StringUtils.defaultIfEmpty(idp.getResourceId(), idp.getIdentityProviderName()));
        context.put(OIDCDebugConstants.DEBUG_IDP_DESCRIPTION, idp.getIdentityProviderDescription());
    }

    private void logAvailableAuthenticators(IdentityProvider idp) {

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
        LOG.warn(configList.toString());
    }

    private void populateAuthenticatorContextProperties(Map<String, Object> context,
            FederatedAuthenticatorConfig authenticatorConfig) {

        context.put(OIDCDebugConstants.DEBUG_AUTHENTICATOR_NAME, authenticatorConfig.getName());

        String executorClass = mapAuthenticatorToExecutor(authenticatorConfig.getName());
        if (executorClass != null) {
            context.put(OIDCDebugConstants.DEBUG_EXECUTOR_CLASS, executorClass);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Mapped authenticator '" + authenticatorConfig.getName() +
                        "' to executor '" + executorClass + "'.");
            }
        }
    }

    private String mapAuthenticatorToExecutor(String authenticatorName) {

        if (isKnownOidcImplementation(authenticatorName)) {
            return OpenIDConnectExecutor.class.getName();
        }
        return null;
    }

    private void populateDebugSessionProperties(Map<String, Object> context, String tenantDomain) {

        context.put(OIDCDebugConstants.IS_DEBUG_FLOW, Boolean.TRUE);
        context.put(OIDCDebugConstants.DEBUG_ID, "debug-" + UUID.randomUUID());
        context.put(OIDCDebugConstants.DEBUG_TIMESTAMP, System.currentTimeMillis());
        context.put(OIDCDebugConstants.DEBUG_TENANT_DOMAIN, tenantDomain);
        context.put(OIDCDebugConstants.CONTEXT_PROTOCOL, OIDCDebugConstants.PROTOCOL_TYPE);
    }

    /**
     * Validates if this resolver can potentially handle the given IdP ID.
     * Performs format validation only — does not make database calls or verify that the IdP has an OIDC
     * authenticator configured. Full validation occurs in {@link #resolveContext(String, String)}.
     *
     * @param idpId Identity Provider ID to check.
     * @return true if idpId is non-empty and contains only safe characters, false otherwise.
     */
    @Override
    public boolean canHandle(String idpId) {

        return StringUtils.isNotEmpty(idpId) && SAFE_ID_PATTERN.matcher(idpId).matches();
    }

    /**
     * Finds the OIDC authenticator configuration in the IdP.
     * If authenticatorName is provided, finds the specific authenticator.
     * Otherwise, returns the first enabled OIDC authenticator found via known implementations or suffix matching.
     *
     * @param idp               Identity Provider.
     * @param authenticatorName Optional specific authenticator name.
     * @return FederatedAuthenticatorConfig or null if not found.
     */
    private FederatedAuthenticatorConfig findOIDCAuthenticatorConfig(IdentityProvider idp,
            String authenticatorName) {

        FederatedAuthenticatorConfig[] configs = idp.getFederatedAuthenticatorConfigs();
        if (configs == null || configs.length == 0) {
            return null;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Finding OIDC authenticator config with name: '" + authenticatorName +
                    "' for IdP: " + idp.getIdentityProviderName());
        }

        if (StringUtils.isNotEmpty(authenticatorName)) {
            FederatedAuthenticatorConfig exactMatch = findExactAuthenticatorMatch(configs, authenticatorName);
            if (exactMatch != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found exact match for authenticator: " + authenticatorName);
                }
                return exactMatch;
            }
        }

        FederatedAuthenticatorConfig knownMatch = findKnownOIDCAuthenticator(configs);
        if (knownMatch != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found known OIDC authenticator: " + knownMatch.getName());
            }
            return knownMatch;
        }

        FederatedAuthenticatorConfig suffixMatch = findOIDCAuthenticatorBySuffix(configs);
        if (suffixMatch != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found OIDC authenticator by suffix match: " + suffixMatch.getName());
            }
            return suffixMatch;
        }

        logNoAuthenticatorFound(idp, configs);
        return null;
    }

    private FederatedAuthenticatorConfig findExactAuthenticatorMatch(FederatedAuthenticatorConfig[] configs,
            String authenticatorName) {

        for (FederatedAuthenticatorConfig config : configs) {
            if (config != null && config.isEnabled() && authenticatorName.equals(config.getName())) {
                return config;
            }
        }
        return null;
    }

    /**
     * Matches against the explicit allowlist in {@link #isKnownOidcImplementation} — exact authenticator names
     * for OpenID Connect, Google OIDC, and GitHub.
     */
    private FederatedAuthenticatorConfig findKnownOIDCAuthenticator(FederatedAuthenticatorConfig[] configs) {

        for (FederatedAuthenticatorConfig config : configs) {
            if (config != null && config.isEnabled() && isKnownOidcImplementation(config.getName())) {
                return config;
            }
        }
        return null;
    }

    /**
     * Fallback for custom OIDC-based authenticators (e.g. FacebookOIDCAuthenticator) that are not in the
     * known-implementation allowlist but follow the naming convention of ending with "OIDCAuthenticator".
     */
    private FederatedAuthenticatorConfig findOIDCAuthenticatorBySuffix(FederatedAuthenticatorConfig[] configs) {

        for (FederatedAuthenticatorConfig config : configs) {
            if (config != null && config.isEnabled()) {
                String configName = config.getName();
                if (StringUtils.isNotEmpty(configName) && configName.endsWith("OIDCAuthenticator")) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Using OIDC-based authenticator as fallback: " + configName);
                    }
                    return config;
                }
            }
        }
        return null;
    }

    private void logNoAuthenticatorFound(IdentityProvider idp, FederatedAuthenticatorConfig[] configs) {

        StringBuilder sb = new StringBuilder();
        sb.append("No OIDC authenticator matched for IdP '").append(idp.getIdentityProviderName())
                .append("'. Available configs:");
        for (FederatedAuthenticatorConfig cfg : configs) {
            if (cfg == null) {
                sb.append(" [null]");
            } else {
                sb.append(" [name=").append(cfg.getName())
                        .append(" enabled=").append(cfg.isEnabled()).append("]");
            }
        }
        LOG.warn(sb.toString());
    }

    /**
     * Extracts OIDC parameters from the authenticator configuration and stores them in context.
     *
     * @param config  Authenticator configuration.
     * @param context Map to store extracted parameters.
     * @throws ContextResolutionException If required parameters are missing.
     */
    private void extractOIDCParameters(FederatedAuthenticatorConfig config, Map<String, Object> context)
            throws ContextResolutionException {

        Property[] properties = config.getProperties();
        if (properties == null || properties.length == 0) {
            throw new ContextResolutionException("No properties found in authenticator configuration");
        }

        Map<String, String> propertyMap = OIDCConfigurationExtractor.buildPropertyMap(properties);
        OpenIDConnectExecutor executor = createExecutorForAuthenticator(config.getName());

        extractAndStoreClientId(propertyMap, context);
        extractAndStoreAuthorizationEndpoint(propertyMap, executor, context);
        extractAndStoreTokenEndpoint(propertyMap, executor, context);
        extractAndStoreScope(propertyMap, executor, context);
        extractAndStoreOptionalParameters(propertyMap, context);

        if (LOG.isDebugEnabled()) {
            LOG.debug("OIDC parameters extracted successfully. ClientId: FOUND");
        }
    }

    private OpenIDConnectExecutor createExecutorForAuthenticator(String authenticatorName) {

        if (isKnownOidcImplementation(authenticatorName)) {
            return new OpenIDConnectExecutor();
        }
        return null;
    }

    private boolean isKnownOidcImplementation(String implementationName) {

        return IdpDebugConstants.IMPLEMENTATION_OPENID_CONNECT.equals(implementationName)
                || IdpDebugConstants.IMPLEMENTATION_GOOGLE_OIDC.equals(implementationName)
                || IdpDebugConstants.IMPLEMENTATION_GITHUB.equals(implementationName);
    }

    private void extractAndStoreClientId(Map<String, String> propertyMap, Map<String, Object> context)
            throws ContextResolutionException {

        String clientId = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.getClientIdPropertyNames());
        if (StringUtils.isEmpty(clientId)) {
            throw new ContextResolutionException("Client ID not found in authenticator configuration");
        }
        context.put(OIDCDebugConstants.CLIENT_ID, clientId);
    }

    /**
     * Resolves authorization endpoint: executor takes priority (handles IdP-specific overrides like Google),
     * falling back to raw property lookup if the executor returns nothing.
     */
    private void extractAndStoreAuthorizationEndpoint(Map<String, String> propertyMap, OpenIDConnectExecutor executor,
            Map<String, Object> context) throws ContextResolutionException {

        String authzEndpoint = getAuthorizationEndpointFromExecutor(executor, propertyMap);
        if (StringUtils.isEmpty(authzEndpoint)) {
            authzEndpoint = OIDCConfigurationExtractor.findPropertyValue(
                    propertyMap, OIDCConfigurationExtractor.getAuthorizationEndpointPropertyNames());
        }
        if (StringUtils.isEmpty(authzEndpoint)) {
            throw new ContextResolutionException("Authorization endpoint not found in authenticator configuration");
        }
        context.put(OIDCDebugConstants.AUTHORIZATION_ENDPOINT, authzEndpoint);
    }

    /**
     * Resolves token endpoint: executor takes priority, falling back to raw property lookup.
     * Same strategy as {@link #extractAndStoreAuthorizationEndpoint}.
     */
    private void extractAndStoreTokenEndpoint(Map<String, String> propertyMap, OpenIDConnectExecutor executor,
            Map<String, Object> context) throws ContextResolutionException {

        String tokenEndpoint = getTokenEndpointFromExecutor(executor, propertyMap);
        if (StringUtils.isEmpty(tokenEndpoint)) {
            tokenEndpoint = OIDCConfigurationExtractor.findPropertyValue(
                    propertyMap, OIDCConfigurationExtractor.getTokenEndpointPropertyNames());
        }
        if (StringUtils.isEmpty(tokenEndpoint)) {
            throw new ContextResolutionException("Token endpoint not found in authenticator configuration");
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Resolved token endpoint: " + tokenEndpoint);
        }
        context.put(OIDCDebugConstants.TOKEN_ENDPOINT, tokenEndpoint);
    }

    private void extractAndStoreScope(Map<String, String> propertyMap, OpenIDConnectExecutor executor,
            Map<String, Object> context) {

        String scope = extractScope(propertyMap, executor);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Final resolved scope for authorization URL: " + scope);
        }
        context.put(OIDCDebugConstants.IDP_SCOPE, scope);
    }

    /**
     * Extracts scope from authenticator properties using multiple fallback strategies.
     * Falls back to "openid" if no scope is configured anywhere.
     */
    private String extractScope(Map<String, String> propertyMap, OpenIDConnectExecutor executor) {

        // Strategy 1: Check standard scope properties.
        String scope = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.getScopePropertyNames());
        if (StringUtils.isNotEmpty(scope)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found scope in property");
            }
            return scope;
        }

        // Strategy 2: Check AdditionalQueryParameters.
        String additionalParams = propertyMap.get(OIDCDebugConstants.PROP_ADDITIONAL_QUERY_PARAMS);
        if (additionalParams != null && !additionalParams.isEmpty()) {
            scope = extractScopeFromQueryParams(additionalParams);
            if (StringUtils.isNotEmpty(scope)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found scope in AdditionalQueryParameters: " + scope);
                }
                return scope;
            }
        }

        // Strategy 3: Check executor's getScope method.
        if (executor != null) {
            scope = executor.getScope(propertyMap);
            if (StringUtils.isNotEmpty(scope)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found scope via executor.getScope(): " + scope);
                }
                return scope;
            }
        }

        // Strategy 4: Default to "openid".
        if (LOG.isDebugEnabled()) {
            LOG.debug("No scope found in configuration, defaulting to 'openid'");
        }
        return OIDCDebugConstants.DEFAULT_SCOPE;
    }

    private void extractAndStoreOptionalParameters(Map<String, String> propertyMap, Map<String, Object> context) {

        String clientSecret = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.getClientSecretPropertyNames());
        if (StringUtils.isNotEmpty(clientSecret)) {
            context.put(OIDCDebugConstants.CLIENT_SECRET, clientSecret);
        }

        String responseType = propertyMap.get(OIDCDebugConstants.PROP_RESPONSE_TYPE);
        if (StringUtils.isEmpty(responseType)) {
            responseType = "code";
        }
        context.put(OIDCDebugConstants.RESPONSE_TYPE, responseType);

        // PKCE is required for all debug flows.
        context.put(OIDCDebugConstants.PKCE_ENABLED, true);
        context.put(OIDCDebugConstants.PKCE_METHOD, OIDCDebugConstants.PKCE_METHOD_S256);
    }

    private String getAuthorizationEndpointFromExecutor(OpenIDConnectExecutor executor,
            Map<String, String> authenticatorProperties) {

        if (executor == null) {
            return null;
        }

        try {
            String endpoint = executor.getAuthorizationServerEndpoint(authenticatorProperties);
            if (StringUtils.isNotEmpty(endpoint)) {
                return endpoint;
            }
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to get authorization endpoint from executor: " + e.getMessage());
            }
        }

        return null;
    }

    private String getTokenEndpointFromExecutor(OpenIDConnectExecutor executor,
            Map<String, String> authenticatorProperties) {

        if (executor != null) {
            try {
                String result = executor.getTokenEndpoint(authenticatorProperties);
                if (StringUtils.isNotEmpty(result)) {
                    return result;
                }
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to get token endpoint from executor: " + e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * Extracts the scope value from an AdditionalQueryParameters string.
     * Handles formats: {@code scope=openid+email+profile}, {@code scope=openid%20email},
     * and the non-standard {@code scope=openid&email&profile} (bare values after scope= treated as scope tokens).
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
            int scopeIndex = -1;
            for (int i = 0; i < params.length; i++) {
                if (params[i].trim().startsWith("scope=")) {
                    scopeIndex = i;
                    break;
                }
            }

            if (scopeIndex == -1) {
                return null;
            }

            StringBuilder scopeBuilder = new StringBuilder();
            String firstScopeValue = URLDecoder.decode(
                    params[scopeIndex].substring("scope=".length()), StandardCharsets.UTF_8.name());
            scopeBuilder.append(firstScopeValue);

            // Collect subsequent bare parameters (no '=') as additional scope values.
            for (int j = scopeIndex + 1; j < params.length; j++) {
                String nextParam = params[j].trim();
                if (!nextParam.contains("=")) {
                    scopeBuilder.append(" ").append(nextParam);
                } else {
                    break;
                }
            }

            String scope = scopeBuilder.toString().trim();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Extracted scope from query params: " + scope);
            }
            return scope;
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error extracting scope from AdditionalQueryParameters: " + queryParams, e);
            }
        }
        return null;
    }
}
