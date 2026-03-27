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
import org.wso2.carbon.identity.debug.framework.core.DebugContextProvider;
import org.wso2.carbon.identity.debug.framework.exception.ContextResolutionException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * OIDC context resolver for debug operations.
 * Extends the framework's DebugContextProvider to provide OIDC-specific
 * context resolution.
 * Resolves OIDC-specific context from IdP configuration.
 */
public class OIDCContextProvider extends DebugContextProvider {

    private static final Log LOG = LogFactory.getLog(OIDCContextProvider.class);

    /**
     * Resolves and creates an OIDC debug context from the given HTTP request.
     *
     * @param request HTTP servlet request containing debug parameters (idpId,
     *                authenticator).
     * @return Map containing resolved OIDC debug context data.
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
            if (!idpId.matches("[a-zA-Z0-9._-]+")) {
                throw new ContextResolutionException("Invalid IdP ID format - contains invalid characters");
            }

            // Validate authenticator name if provided
            if (StringUtils.isNotEmpty(authenticatorName) &&
                    !authenticatorName.matches("[a-zA-Z0-9._-]+")) {
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
     * Resolves and creates an OIDC debug context from a provided Map input.
     * This method is used by the API layer which invokes the resolver reflectively
     * with a Map argument containing keys such as `idpName` and
     * `authenticatorName`.
     *
     * @param input Map containing debug request parameters (idpName,
     *              authenticatorName, etc.).
     * @return Map containing resolved OIDC debug context data.
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
     * Resolves and creates an OIDC debug context with specific parameters.
     *
     * @param idpId         Identity Provider resource ID or name.
     * @param authenticator Optional authenticator name (defaults to first enabled
     *                      OIDC authenticator).
     * @return Map containing resolved OIDC debug context data.
     * @throws ContextResolutionException If context resolution fails.
     */
    @Override
    public Map<String, Object> resolveContext(String idpId, String authenticator) throws ContextResolutionException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Resolving OIDC debug context for IdP: " + idpId + " with authenticator: " + authenticator);
        }

        if (StringUtils.isEmpty(idpId)) {
            throw new ContextResolutionException("IdP ID is null or empty");
        }

        Map<String, Object> context = new HashMap<>();
        try {
            String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
            IdentityProvider idp = retrieveIdentityProvider(idpId, tenantDomain);
            validateIdpIsEnabled(idp);

            // Set IdP-specific context properties
            populateIdpContextProperties(context, idp);

            // Find and extract OIDC authenticator configuration
            FederatedAuthenticatorConfig authenticatorConfig = findOIDCAuthenticatorConfig(idp, authenticator);
            if (authenticatorConfig == null) {
                logAvailableAuthenticators(idp);
                throw new ContextResolutionException("No OIDC authenticator configuration found for IdP: " +
                        idp.getIdentityProviderName());
            }

            // Extract OIDC parameters and set authenticator details
            extractOIDCParameters(authenticatorConfig, context);
            populateAuthenticatorContextProperties(context, authenticatorConfig);
            populateDebugSessionProperties(context, tenantDomain);

            if (LOG.isDebugEnabled()) {
                LOG.debug("OIDC debug context resolved successfully for IdP: " + idp.getIdentityProviderName());
            }

            return context;

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
     * Retrieves the Identity Provider by resource ID or name.
     *
     * @param idpId        Identity Provider resource ID or name.
     * @param tenantDomain Tenant domain.
     * @return IdentityProvider instance.
     * @throws ContextResolutionException If IdP is not found.
     */
    private IdentityProvider retrieveIdentityProvider(String idpId, String tenantDomain)
            throws ContextResolutionException {

        try {
            IdentityProviderManager idpManager = IdentityProviderManager.getInstance();
            
            // First, try to retrieve by resource ID (UUID).
            IdentityProvider idp = idpManager.getIdPByResourceId(idpId, tenantDomain, false);
            
            // If not found by ID, try by name.
            if (idp == null) {
                idp = idpManager.getIdPByName(idpId, tenantDomain, false);
            }
            
            if (idp == null) {
                throw new ContextResolutionException("CTX-40401", "IdP not found: " + idpId, 
                        "Identity Provider with ID or name '" + idpId + "' does not exist.");
            }
            
            return idp;
        } catch (ContextResolutionException e) {
            throw e;
        } catch (IdentityProviderManagementException e) {
            throw new ContextResolutionException("CTX-40401", "IdP not found: " + idpId, e.getMessage(), e);
        } catch (Exception e) {
            throw new ContextResolutionException("CTX-40401", "IdP not found: " + idpId, e.getMessage(), e);
        }
    }

    /**
     * Validates that the IdP is enabled.
     *
     * @param idp IdentityProvider to validate.
     * @throws ContextResolutionException If IdP is disabled.
     */
    private void validateIdpIsEnabled(IdentityProvider idp) throws ContextResolutionException {

        if (!idp.isEnable()) {
            throw new ContextResolutionException("IdP is not available: " + idp.getIdentityProviderName());
        }
    }

    /**
     * Populates IdP-specific context properties.
     *
     * @param context Context map to populate.
     * @param idp IdentityProvider instance.
     */
    private void populateIdpContextProperties(Map<String, Object> context, IdentityProvider idp) {

        // Populate context with IdP details.
        if (idp != null) {
            context.put(OIDCDebugConstants.DEBUG_IDP_NAME, idp.getIdentityProviderName());
            context.put("DEBUG_IDP_RESOURCE_ID", idp.getIdentityProviderName());
            context.put("DEBUG_IDP_DESCRIPTION", idp.getIdentityProviderDescription());
            // Store the full IdentityProvider so that OIDCDebugProcessor.validateAndExtractPrerequisites()
            // can cast it correctly. Previously this stored only getFederatedAuthenticatorConfigs() which
            // caused a ClassCastException when the processor tried to cast it to IdentityProvider.
            context.put(OIDCDebugConstants.IDP_CONFIG, idp);
        }
    }

    /**
     * Logs available authenticator configurations for debugging.
     *
     * @param idp IdentityProvider instance.
     */
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

    /**
     * Populates authenticator-specific context properties.
     *
     * @param context             Context map to populate.
     * @param authenticatorConfig Authenticator configuration.
     */
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

    /**
     * Maps authenticator name to executor class name.
     *
     * @param authenticatorName Name of the authenticator.
     * @return Executor class name or null if no mapping found.
     */
    private String mapAuthenticatorToExecutor(String authenticatorName) {

        if (OIDCDebugConstants.OPENID_CONNECT_AUTHENTICATOR.equals(authenticatorName) ||
                OIDCDebugConstants.OIDC_OPENID_CONNECT_AUTHENTICATOR.equals(authenticatorName)) {
            return OpenIDConnectExecutor.class.getName();
        }
        return null;
    }

    /**
     * Populates debug session properties.
     *
     * @param context Context map to populate.
     * @param tenantDomain Tenant domain.
     */
    private void populateDebugSessionProperties(Map<String, Object> context, String tenantDomain) {

        context.put(OIDCDebugConstants.IS_DEBUG_FLOW, Boolean.TRUE);
        context.put(OIDCDebugConstants.DEBUG_SESSION_ID, java.util.UUID.randomUUID().toString());
        context.put(OIDCDebugConstants.DEBUG_TIMESTAMP, System.currentTimeMillis());
        context.put(OIDCDebugConstants.DEBUG_TENANT_DOMAIN, tenantDomain);
        context.put(OIDCDebugConstants.DEBUG_CONTEXT_ID, "debug-" + java.util.UUID.randomUUID().toString());
    }

    /**
     * Validates if this resolver can handle the given IdP.
     * Returns true if the IdP has at least one enabled OIDC/OIDC authenticator.
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

            String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
            IdentityProvider idp = retrieveIdpForCanResolve(idpId, tenantDomain);

            if (idp == null || !idp.isEnable()) {
                return false;
            }

            // Check if IdP has at least one enabled OIDC/OIDC authenticator.
            return findOIDCAuthenticatorConfig(idp, null) != null;
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error checking if resolver can handle IdP: " + e.getMessage());
            }
            return false;
        }
    }

    /**
     * Retrieves the IdP for canResolve check with fallback from resource ID to
     * name.
     *
     * @param idpId Identity Provider resource ID or name.
     * @param tenantDomain Tenant domain.
     * @return IdentityProvider instance or null if not found.
     */
    private IdentityProvider retrieveIdpForCanResolve(String idpId, String tenantDomain) {

        try {
            return retrieveIdentityProvider(idpId, tenantDomain);
        } catch (ContextResolutionException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to resolve IdP for canResolve: " + e.getMessage());
            }
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unexpected error resolving IdP for canResolve: " + e.getMessage());
            }
        }
        return null;
    }

    /**
     * Finds the OIDC/OIDC authenticator configuration in the IdP.
     * If authenticatorName is provided, finds the specific authenticator.
     * Otherwise, returns the first enabled OIDC authenticator.
     *
     * @param idp Identity Provider.
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

        // Try exact match if authenticator name is provided and looks like a valid
        // authenticator name.
        if (shouldTryExactMatch(authenticatorName)) {
            FederatedAuthenticatorConfig exactMatch = findExactAuthenticatorMatch(configs, authenticatorName);
            if (exactMatch != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found exact match for authenticator: " + authenticatorName);
                }
                return exactMatch;
            }
        }

        // Try known OIDC/OIDC implementations.
        FederatedAuthenticatorConfig knownMatch = findKnownOIDCAuthenticator(configs);
        if (knownMatch != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found known OIDC/OIDC authenticator: " + knownMatch.getName());
            }
            return knownMatch;
        }

        // Try OIDC/OIDC-based authenticators by suffix matching (Google, GitHub,
        // etc.).
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

    /**
     * Determines whether to attempt exact match for authenticator name.
     *
     * @param authenticatorName Authenticator name to check.
     * @return true if exact match should be attempted.
     */
    private boolean shouldTryExactMatch(String authenticatorName) {

        return StringUtils.isNotEmpty(authenticatorName) && !isResourceTypeIdentifier(authenticatorName);
    }

    /**
     * Finds an authenticator with exact name match.
     *
     * @param configs Authenticator configurations.
     * @param authenticatorName Name to match.
     * @return Matching config or null.
     */
    private FederatedAuthenticatorConfig findExactAuthenticatorMatch(FederatedAuthenticatorConfig[] configs,
            String authenticatorName) {

        for (FederatedAuthenticatorConfig config : configs) {
            if (config != null && config.isEnabled() &&
                    authenticatorName.equals(config.getName())) {
                return config;
            }
        }
        return null;
    }

    /**
     * Checks if the provided string is a resource type identifier rather than an
     * authenticator name.
     * Resource type identifiers like "RESOURCE_DEBUG_REQUEST" should be ignored
     * when searching for authenticators.
     *
     * @param authenticatorName Name to check.
     * @return true if the string appears to be a resource type identifier.
     */
    private boolean isResourceTypeIdentifier(String authenticatorName) {

        return authenticatorName != null &&
                (authenticatorName.contains("_REQUEST") ||
                        authenticatorName.contains("RESOURCE_") ||
                        authenticatorName.contains("DEBUG_"));
    }

    /**
     * Finds known OIDC/OIDC authenticator implementations.
     *
     * @param configs Authenticator configurations.
     * @return First known OIDC authenticator or null.
     */
    private FederatedAuthenticatorConfig findKnownOIDCAuthenticator(FederatedAuthenticatorConfig[] configs) {

        for (FederatedAuthenticatorConfig config : configs) {
            if (config != null && config.isEnabled()) {
                String configName = config.getName();
                if (OIDCDebugConstants.OPENID_CONNECT_AUTHENTICATOR.equals(configName) ||
                        OIDCDebugConstants.OIDC_OPENID_CONNECT_AUTHENTICATOR.equals(configName)) {
                    return config;
                }
            }
        }
        return null;
    }

    /**
     * Finds OIDC/OIDC authenticator by name suffix (e.g.,
     * GoogleOIDCAuthenticator).
     *
     * @param configs Authenticator configurations.
     * @return First matching config or null.
     */
    private FederatedAuthenticatorConfig findOIDCAuthenticatorBySuffix(FederatedAuthenticatorConfig[] configs) {

        for (FederatedAuthenticatorConfig config : configs) {
            if (config != null && config.isEnabled()) {
                String configName = config.getName();
                if (StringUtils.isNotEmpty(configName) &&
                        configName.endsWith("OIDCAuthenticator")) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Using OIDC-based authenticator as fallback: " + configName);
                    }
                    return config;
                }
            }
        }
        return null;
    }

    /**
     * Logs warning when no OIDC authenticator is found.
     *
     * @param idp Identity Provider.
     * @param configs Available authenticator configurations.
     */
    private void logNoAuthenticatorFound(IdentityProvider idp, FederatedAuthenticatorConfig[] configs) {

        try {
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
        } catch (Exception t) {
            LOG.warn("Failed to build authenticator config debug info: " + t.getMessage(), t);
        }
    }

    /**
     * Extracts OIDC parameters from the authenticator configuration and stores
     * them in context.
     *
     * @param config Authenticator configuration.
     * @param context Map to store extracted parameters.
     * @throws ContextResolutionException If required parameters are missing.
     */
    private void extractOIDCParameters(FederatedAuthenticatorConfig config, Map<String, Object> context)
            throws ContextResolutionException {

        Property[] properties = config.getProperties();
        if (properties == null || properties.length == 0) {
            throw new ContextResolutionException("No properties found in authenticator configuration");
        }

        Map<String, String> propertyMap = buildPropertyMap(properties);
    OpenIDConnectExecutor executor = createExecutorForAuthenticator(config.getName());

        // Extract required parameters.
        extractAndStoreClientId(propertyMap, context);
    extractAndStoreAuthorizationEndpoint(propertyMap, executor, context);
    extractAndStoreTokenEndpoint(propertyMap, executor, context);
    extractAndStoreScope(propertyMap, executor, context);

        // Extract optional parameters.
    extractAndStoreOptionalParameters(propertyMap, context);

        if (LOG.isDebugEnabled()) {
            LOG.debug("OIDC parameters extracted successfully. ClientId: FOUND");
        }
    }

    /**
     * Builds a property map from Property array.
     * Delegates to {@link OIDCConfigurationExtractor#buildPropertyMap(Property[])} to avoid duplication.
     *
     * @param properties Array of Property objects.
     * @return Map of property names to values.
     */
    private Map<String, String> buildPropertyMap(Property[] properties) {

        return OIDCConfigurationExtractor.buildPropertyMap(properties);
    }

    /**
     * Creates an executor instance for the given authenticator name.
     *
     * @param authenticatorName Authenticator name.
     * @return Executor instance or null if not applicable.
     */
    private OpenIDConnectExecutor createExecutorForAuthenticator(String authenticatorName) {

        if (OIDCDebugConstants.OPENID_CONNECT_AUTHENTICATOR.equals(authenticatorName) ||
                OIDCDebugConstants.OIDC_OPENID_CONNECT_AUTHENTICATOR.equals(authenticatorName)) {
            return new OpenIDConnectExecutor();
        }
        return null;
    }

    /**
     * Extracts and stores the client ID from properties.
     * Uses {@link OIDCConfigurationExtractor#CLIENT_ID_PROPERTY_NAMES} as the single source of truth
     * for recognized property key variants.
     *
     * @param propertyMap Property map.
     * @param context Context to store result.
     * @throws ContextResolutionException If client ID is not found.
     */
    private void extractAndStoreClientId(Map<String, String> propertyMap, Map<String, Object> context)
            throws ContextResolutionException {

        String clientId = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.CLIENT_ID_PROPERTY_NAMES);
        if (StringUtils.isEmpty(clientId)) {
            throw new ContextResolutionException("Client ID not found in authenticator configuration");
        }
        context.put(OIDCDebugConstants.CLIENT_ID, clientId);
    }

    /**
     * Extracts and stores the authorization endpoint.
     * Uses {@link OIDCConfigurationExtractor#AUTHZ_ENDPOINT_PROPERTY_NAMES} as the single source of truth
     * for recognized property key variants, with executor-based resolution as the primary strategy.
     *
     * @param propertyMap Property map.
     * @param executor Executor instance (can be null).
     * @param context Context to store result.
     * @throws ContextResolutionException If endpoint is not found.
     */
    private void extractAndStoreAuthorizationEndpoint(Map<String, String> propertyMap, OpenIDConnectExecutor executor,
        Map<String, Object> context) throws ContextResolutionException {

        String authzEndpoint = getAuthorizationEndpointFromExecutor(executor, propertyMap);
        if (StringUtils.isEmpty(authzEndpoint)) {
            authzEndpoint = OIDCConfigurationExtractor.findPropertyValue(
                    propertyMap, OIDCConfigurationExtractor.AUTHZ_ENDPOINT_PROPERTY_NAMES);
        }
        if (StringUtils.isEmpty(authzEndpoint)) {
            throw new ContextResolutionException("Authorization endpoint not found in authenticator configuration");
        }
        context.put(OIDCDebugConstants.AUTHORIZATION_ENDPOINT, authzEndpoint);
    }

    /**
     * Extracts and stores the token endpoint.
     * Uses {@link OIDCConfigurationExtractor#TOKEN_ENDPOINT_PROPERTY_NAMES} as the single source of truth
     * for recognized property key variants, with executor-based resolution as the primary strategy.
     *
     * @param propertyMap Property map.
     * @param executor    Executor instance (can be null).
     * @param context     Context to store result.
     * @throws ContextResolutionException If endpoint is not found.
     */
    private void extractAndStoreTokenEndpoint(Map<String, String> propertyMap, OpenIDConnectExecutor executor,
        Map<String, Object> context) throws ContextResolutionException {

        String tokenEndpoint = getTokenEndpointFromExecutor(executor, propertyMap);
        if (StringUtils.isEmpty(tokenEndpoint)) {
            tokenEndpoint = OIDCConfigurationExtractor.findPropertyValue(
                    propertyMap, OIDCConfigurationExtractor.TOKEN_ENDPOINT_PROPERTY_NAMES);
        }
        if (StringUtils.isEmpty(tokenEndpoint)) {
            throw new ContextResolutionException("Token endpoint not found in authenticator configuration");
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Resolved token endpoint: " + tokenEndpoint);
        }
        context.put(OIDCDebugConstants.TOKEN_ENDPOINT, tokenEndpoint);
    }

    /**
     * Extracts and stores the OIDC scope parameter.
     *
     * @param propertyMap Property map.
     * @param executor    Executor instance (can be null).
     * @param context     Context to store result.
     */
    private void extractAndStoreScope(Map<String, String> propertyMap, OpenIDConnectExecutor executor,
            Map<String, Object> context) {

        String scope = extractScope(propertyMap, executor);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Final resolved scope for authorization URL: " + scope);
        }
        context.put(OIDCDebugConstants.IDP_SCOPE, scope);
    }

    /**
     * Extracts scope from authenticator properties using multiple strategies.
     * Uses {@link OIDCConfigurationExtractor#SCOPE_PROPERTY_NAMES} as the single source of truth
     * for recognized property key variants.
     *
     * @param propertyMap Configuration properties.
     * @param executor    Executor instance.
     * @return Extracted scope or "openid" (default).
     */
    private String extractScope(Map<String, String> propertyMap, OpenIDConnectExecutor executor) {

        // Strategy 1: Check standard scope properties.
        String scope = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.SCOPE_PROPERTY_NAMES);
        if (StringUtils.isNotEmpty(scope)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found scope in property");
            }
            return scope;
        }

        // Strategy 2: Check AdditionalQueryParameters.
        String additionalParams = propertyMap.get("AdditionalQueryParameters");
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
        return "openid";
    }

    /**
     * Extracts and stores optional OIDC parameters.
     * Uses {@link OIDCConfigurationExtractor} arrays as the single source of truth for
     * recognized property key variants.
     *
     * @param propertyMap Property map.
     * @param context     Context to store results.
     */
    private void extractAndStoreOptionalParameters(Map<String, String> propertyMap,
        Map<String, Object> context) {

        String userInfoEndpoint = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.USERINFO_ENDPOINT_PROPERTY_NAMES);
        if (StringUtils.isNotEmpty(userInfoEndpoint)) {
            context.put(OIDCDebugConstants.USERINFO_ENDPOINT, userInfoEndpoint);
        }

        String clientSecret = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.CLIENT_SECRET_PROPERTY_NAMES);
        if (StringUtils.isNotEmpty(clientSecret)) {
            context.put(OIDCDebugConstants.CLIENT_SECRET, clientSecret);
        }

        String responseType = propertyMap.get("ResponseType");
        if (StringUtils.isEmpty(responseType)) {
            responseType = "code";
        }
        context.put(OIDCDebugConstants.RESPONSE_TYPE, responseType);

        // PKCE is REQUIRED for debug flow.
        context.put(OIDCDebugConstants.PKCE_ENABLED, true);
        context.put(OIDCDebugConstants.PKCE_METHOD, OIDCDebugConstants.PKCE_METHOD_S256);
    }

    /**
     * Gets the authorization endpoint using executor instance with fallback
     * strategies.
     *
     * @param executor                Executor instance (can be null).
     * @param authenticatorProperties Authenticator properties map.
     * @return Authorization endpoint URL or null if not found.
     */
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

    /**
     * Gets the token endpoint using executor instance and its fallback logic.
     * Falls back to {@link OIDCConfigurationExtractor#TOKEN_ENDPOINT_PROPERTY_NAMES} for direct
     * property lookup to avoid duplicating key variants here.
     *
     * @param executor                Executor instance (can be null).
     * @param authenticatorProperties Authenticator properties map.
     * @return Token endpoint URL with fallback support.
     */
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

        // Fallback to direct property lookup using the shared canonical key list.
        return OIDCConfigurationExtractor.findPropertyValue(
                authenticatorProperties, OIDCConfigurationExtractor.TOKEN_ENDPOINT_PROPERTY_NAMES);
    }

    /**
     * Helper to extract scope from AdditionalQueryParameters.
     * Handles multiple formats:
     * - Standard: "scope=openid+email+profile" or "scope=openid%20email%20profile"
     * - Alternative: "scope=openid&email&profile" (treats subsequent params as
     * scope values)
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
            int scopeIndex = findScopeParameterIndex(params);

            if (scopeIndex == -1) {
                return null;
            }

            String scope = buildScopeFromParameters(params, scopeIndex);
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

    /**
     * Finds the index of the scope parameter in the parameters array.
     *
     * @param params Array of parameters.
     * @return Index of scope parameter, or -1 if not found.
     */
    private int findScopeParameterIndex(String[] params) {

        for (int i = 0; i < params.length; i++) {
            if (params[i].trim().startsWith("scope=")) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Builds the complete scope string from parameters starting at scopeIndex.
     * Handles format: scope=openid&email&profile by treating subsequent
     * non-key-value params as scope values.
     *
     * @param params Array of parameters.
     * @param scopeIndex Index of the scope parameter.
     * @return Complete scope string.
     * @throws java.io.UnsupportedEncodingException If URL decoding fails.
     */
    private String buildScopeFromParameters(String[] params, int scopeIndex)
            throws java.io.UnsupportedEncodingException {

        StringBuilder scopeBuilder = new StringBuilder();
        String firstScopeValue = params[scopeIndex].substring("scope=".length());
        firstScopeValue = java.net.URLDecoder.decode(firstScopeValue, "UTF-8");
        scopeBuilder.append(firstScopeValue);

        // Collect subsequent parameters that are scope values (no '=' sign).
        for (int j = scopeIndex + 1; j < params.length; j++) {
            String nextParam = params[j].trim();
            if (!nextParam.contains("=")) {
                scopeBuilder.append(" ").append(nextParam);
            } else {
                break;
            }
        }

        return scopeBuilder.toString().trim();
    }
}
