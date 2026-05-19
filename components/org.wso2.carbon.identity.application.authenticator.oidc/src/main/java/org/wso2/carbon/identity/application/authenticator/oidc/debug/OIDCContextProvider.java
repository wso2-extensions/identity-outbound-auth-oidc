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
    private static final OpenIDConnectExecutor OIDC_EXECUTOR = new OpenIDConnectExecutor();

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

            contextMap.put(OIDCDebugConstants.DEBUG_IDP_NAME, idp.getIdentityProviderName());
            contextMap.put(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID,
                    StringUtils.defaultIfEmpty(idp.getResourceId(), idp.getIdentityProviderName()));

            FederatedAuthenticatorConfig authenticatorConfig = findOIDCAuthenticatorConfig(idp, authenticator);
            if (authenticatorConfig == null) {
                throw new ContextResolutionException("No OIDC authenticator configuration found for IdP: " +
                        idp.getIdentityProviderName());
            }

            extractOIDCParameters(authenticatorConfig, contextMap);

            contextMap.put(OIDCDebugConstants.DEBUG_ID, "debug-" + UUID.randomUUID());
            contextMap.put(OIDCDebugConstants.CONTEXT_PROTOCOL, OIDCDebugConstants.PROTOCOL_TYPE);

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
     */
    private FederatedAuthenticatorConfig findOIDCAuthenticatorConfig(IdentityProvider idp,
            String authenticatorName) {

        FederatedAuthenticatorConfig[] configs = idp.getFederatedAuthenticatorConfigs();
        if (configs == null || configs.length == 0) {
            return null;
        }

        if (StringUtils.isNotEmpty(authenticatorName)) {
            for (FederatedAuthenticatorConfig config : configs) {
                if (config != null && config.isEnabled() && authenticatorName.equals(config.getName())) {
                    return config;
                }
            }
        }

        for (FederatedAuthenticatorConfig config : configs) {
            if (config != null && config.isEnabled() && isKnownOidcImplementation(config.getName())) {
                return config;
            }
        }

        for (FederatedAuthenticatorConfig config : configs) {
            if (config != null && config.isEnabled()) {
                String configName = config.getName();
                if (StringUtils.isNotEmpty(configName) && configName.endsWith("OIDCAuthenticator")) {
                    return config;
                }
            }
        }

        return null;
    }

    private boolean isKnownOidcImplementation(String implementationName) {

        return IdpDebugConstants.IMPLEMENTATION_OPENID_CONNECT.equals(implementationName)
                || IdpDebugConstants.IMPLEMENTATION_GOOGLE_OIDC.equals(implementationName)
                || IdpDebugConstants.IMPLEMENTATION_GITHUB.equals(implementationName);
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
        OpenIDConnectExecutor executor = resolveExecutor(config.getName());

        String clientId = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.getClientIdPropertyNames());
        if (StringUtils.isEmpty(clientId)) {
            throw new ContextResolutionException("Client ID not found in authenticator configuration");
        }
        context.put(OIDCDebugConstants.CLIENT_ID, clientId);

        context.put(OIDCDebugConstants.AUTHORIZATION_ENDPOINT,
                resolveEndpoint(executor, propertyMap, true));
        context.put(OIDCDebugConstants.TOKEN_ENDPOINT,
                resolveEndpoint(executor, propertyMap, false));
        context.put(OIDCDebugConstants.IDP_SCOPE, resolveScope(propertyMap, executor));

        String clientSecret = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.getClientSecretPropertyNames());
        if (StringUtils.isNotEmpty(clientSecret)) {
            context.put(OIDCDebugConstants.CLIENT_SECRET, clientSecret);
        }
    }

    private OpenIDConnectExecutor resolveExecutor(String authenticatorName) {

        if (isKnownOidcImplementation(authenticatorName)) {
            return OIDC_EXECUTOR;
        }
        return null;
    }

    /**
     * Resolves authorization or token endpoint: executor takes priority (handles IdP-specific overrides like Google),
     * falling back to raw property lookup if the executor returns nothing.
     */
    private String resolveEndpoint(OpenIDConnectExecutor executor, Map<String, String> propertyMap,
            boolean isAuthorizationEndpoint) throws ContextResolutionException {

        String endpoint = null;
        if (executor != null) {
            try {
                endpoint = isAuthorizationEndpoint
                        ? executor.getAuthorizationServerEndpoint(propertyMap)
                        : executor.getTokenEndpoint(propertyMap);
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to get endpoint from executor: " + e.getMessage());
                }
            }
        }

        if (StringUtils.isEmpty(endpoint)) {
            endpoint = OIDCConfigurationExtractor.findPropertyValue(propertyMap,
                    isAuthorizationEndpoint
                            ? OIDCConfigurationExtractor.getAuthorizationEndpointPropertyNames()
                            : OIDCConfigurationExtractor.getTokenEndpointPropertyNames());
        }

        if (StringUtils.isEmpty(endpoint)) {
            throw new ContextResolutionException((isAuthorizationEndpoint ? "Authorization" : "Token") +
                    " endpoint not found in authenticator configuration");
        }
        return endpoint;
    }

    /**
     * Extracts scope from authenticator properties using multiple fallback strategies.
     * Falls back to "openid" if no scope is configured anywhere.
     */
    private String resolveScope(Map<String, String> propertyMap, OpenIDConnectExecutor executor) {

        String scope = OIDCConfigurationExtractor.findPropertyValue(
                propertyMap, OIDCConfigurationExtractor.getScopePropertyNames());
        if (StringUtils.isNotEmpty(scope)) {
            return scope;
        }

        String additionalParams = propertyMap.get(OIDCDebugConstants.PROP_ADDITIONAL_QUERY_PARAMS);
        if (StringUtils.isNotEmpty(additionalParams)) {
            scope = extractScopeFromQueryParams(additionalParams);
            if (StringUtils.isNotEmpty(scope)) {
                return scope;
            }
        }

        if (executor != null) {
            scope = executor.getScope(propertyMap);
            if (StringUtils.isNotEmpty(scope)) {
                return scope;
            }
        }

        return OIDCDebugConstants.DEFAULT_SCOPE;
    }

    /**
     * Extracts the scope value from an AdditionalQueryParameters string.
     * Handles formats: {@code scope=openid+email+profile}, {@code scope=openid%20email},
     * and the non-standard {@code scope=openid&email&profile} (bare values after scope= treated as scope tokens).
     */
    private String extractScopeFromQueryParams(String queryParams) {

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

            StringBuilder scopeBuilder = new StringBuilder(URLDecoder.decode(
                    params[scopeIndex].substring("scope=".length()), StandardCharsets.UTF_8.name()));

            // Collect subsequent bare parameters (no '=') as additional scope values.
            for (int j = scopeIndex + 1; j < params.length; j++) {
                String nextParam = params[j].trim();
                if (!nextParam.contains("=")) {
                    scopeBuilder.append(" ").append(nextParam);
                } else {
                    break;
                }
            }

            return scopeBuilder.toString().trim();
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error extracting scope from AdditionalQueryParameters: " + queryParams, e);
            }
        }
        return null;
    }
}
