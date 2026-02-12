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

package org.wso2.carbon.identity.application.authenticator.oidc.debug;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.debug.framework.cache.DebugSessionCache;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OAuth2DebugUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.debug.framework.extension.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.exception.ExecutionException;
import org.wso2.carbon.identity.debug.framework.model.DebugResult;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

/**
 * OAuth2 debug flow executor.
 * Extends the framework's DebugExecutor to provide OAuth2-specific execution
 * logic.
 * Generates OAuth2 Authorization URLs with PKCE parameters and handles debug
 * state management.
 *
 * PKCE generation is delegated to {@link OAuth2DebugUtil} (single source of
 * truth).
 * Session caching is delegated to {@link DebugSessionCache} (standalone class).
 */
public class OAuth2DebugExecutor extends DebugExecutor {

    private static final Log LOG = LogFactory.getLog(OAuth2DebugExecutor.class);
    private static final String EXECUTOR_NAME = "OAuth2Executor";

    /**
     * Executes OAuth2 debug flow and generates authorization URL.
     * Reads resolved OAuth2 parameters from context map (populated by
     * OAuth2ContextProvider) and generates a complete Authorization URL with PKCE
     * parameters.
     *
     * @param context Map containing debug configuration and state (prepared by
     *                DebugContextProvider).
     * @return DebugResult containing the generated authorization URL and metadata.
     * @throws ExecutionException If execution fails.
     */
    @Override
    public DebugResult execute(Map<String, Object> context) throws ExecutionException {

        DebugResult result = new DebugResult();

        if (context == null) {
            throw new ExecutionException("Context map is null");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Executing OAuth2 authorization URL generation");
        }

        try {
            // Initialize step status.
            context.put(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_STARTED);
            context.put(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_STARTED);
            context.put(OAuth2DebugConstants.STEP_CLAIM_MAPPING_STATUS, OAuth2DebugConstants.STATUS_STARTED);

            // Validate required parameters from context (populated by
            // DebugContextProvider).
            String clientId = (String) context.get(OAuth2DebugConstants.CLIENT_ID);
            String authzEndpoint = (String) context.get(OAuth2DebugConstants.AUTHORIZATION_ENDPOINT);
            String redirectUri = (String) context.get(OAuth2DebugConstants.REDIRECT_URI);

            // Use default callback URI if custom one not provided.
            if (StringUtils.isEmpty(redirectUri)) {
                redirectUri = getDefaultRedirectUri();
            }

            validateRequiredParams(context, clientId, authzEndpoint, redirectUri);

            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuth2 configuration validated from context - ClientId: FOUND, AuthzEndpoint: " +
                        authzEndpoint);
            }

            // Generate PKCE parameters using the single source of truth.
            String codeVerifier = OAuth2DebugUtil.generatePKCECodeVerifier();
            String codeChallenge = OAuth2DebugUtil.generatePKCECodeChallenge(codeVerifier);

            // Use contextId as the state parameter for consistency between initial response
            // and callback.
            String contextId = (String) context.getOrDefault(OAuth2DebugConstants.DEBUG_CONTEXT_ID,
                    "debug-" + UUID.randomUUID().toString());
            String state = contextId;

            context.put(OAuth2DebugConstants.DEBUG_CODE_VERIFIER, codeVerifier);
            context.put(OAuth2DebugConstants.DEBUG_STATE, state);
            context.put(OAuth2DebugConstants.DEBUG_CONTEXT_ID, contextId);

            // Build OAuth2 Authorization URL.
            String authorizationUrl = buildAuthorizationUrl(authzEndpoint, clientId, redirectUri, state,
                    codeChallenge, context);

            if (authorizationUrl == null) {
                markAllStepsFailed(context);
                throw new ExecutionException("Failed to build authorization URL");
            }

            // Store authorization URL in context.
            context.put(OAuth2DebugConstants.DEBUG_EXTERNAL_REDIRECT_URL, authorizationUrl);
            context.put("isDebugFlow", "true");

            // Update step status.
            context.put(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_SUCCESS);
            context.put(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_SUCCESS);
            context.put(OAuth2DebugConstants.STEP_CLAIM_MAPPING_STATUS, "pending");

            // Cache authentication context for retrieval during callback.
            cacheDebugContext(context);

            // Build result.
            result.setSuccessful(true);
            result.setStatus("Authorization URL generated successfully");
            result.addResultData("authorizationUrl", authorizationUrl);
            result.addResultData("sessionId", contextId);
            result.addResultData("state", state);
            result.addMetadata("authorizationUrl", authorizationUrl);
            result.addMetadata("sessionId", contextId);
            result.addMetadata("state", state);
            result.addMetadata("codeVerifier", codeVerifier);
            result.addMetadata("idpName", context.get(OAuth2DebugConstants.DEBUG_IDP_NAME));

            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuth2 Authorization URL result: sessionId=" + contextId +
                        ", state=" + state + ", authorizationUrl present: true");
            }

            return result;

        } catch (ExecutionException e) {
            markAllStepsFailed(context);
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error generating OAuth2 Authorization URL: " + e.getMessage(), e);
            markAllStepsFailed(context);
            throw new ExecutionException("Error generating authorization URL: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean canExecute(Map<String, Object> context) {

        return context != null && context.containsKey(OAuth2DebugConstants.CLIENT_ID) &&
                context.containsKey(OAuth2DebugConstants.AUTHORIZATION_ENDPOINT) &&
                context.containsKey(OAuth2DebugConstants.IDP_SCOPE);
    }

    @Override
    public String getExecutorName() {

        return EXECUTOR_NAME;
    }

    /**
     * Validates required parameters and throws ExecutionException if any are
     * missing.
     */
    private void validateRequiredParams(Map<String, Object> context, String clientId,
            String authzEndpoint, String redirectUri) throws ExecutionException {

        if (StringUtils.isEmpty(clientId)) {
            markAllStepsFailed(context);
            throw new ExecutionException("Missing required parameter: CLIENT_ID");
        }
        if (StringUtils.isEmpty(authzEndpoint)) {
            markAllStepsFailed(context);
            throw new ExecutionException("Missing required parameter: AUTHORIZATION_ENDPOINT");
        }
        if (StringUtils.isEmpty(redirectUri)) {
            markAllStepsFailed(context);
            throw new ExecutionException("Missing required parameter: REDIRECT_URI");
        }
    }

    /**
     * Marks all step statuses as failed in the context.
     */
    private void markAllStepsFailed(Map<String, Object> context) {

        context.put(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
        context.put(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
        context.put(OAuth2DebugConstants.STEP_CLAIM_MAPPING_STATUS, OAuth2DebugConstants.STATUS_FAILED);
    }

    /**
     * Builds the complete OAuth2 Authorization URL with PKCE parameters.
     */
    private String buildAuthorizationUrl(String authzEndpoint, String clientId, String redirectUri,
            String state, String codeChallenge, Map<String, Object> context) throws ExecutionException {

        try {
            StringBuilder urlBuilder = new StringBuilder();
            urlBuilder.append(authzEndpoint);
            urlBuilder.append("?response_type=code");
            urlBuilder.append("&client_id=").append(encodeParam(clientId));
            urlBuilder.append("&redirect_uri=").append(encodeParam(redirectUri));

            String scope = (String) context.get(OAuth2DebugConstants.IDP_SCOPE);
            if (StringUtils.isEmpty(scope)) {
                throw new ExecutionException("Scope not found in context");
            }
            urlBuilder.append("&scope=").append(encodeParam(scope));
            urlBuilder.append("&state=").append(encodeParam(state));

            // Add PKCE parameters (always enabled for debug flow).
            urlBuilder.append("&code_challenge=").append(encodeParam(codeChallenge));
            urlBuilder.append("&code_challenge_method=S256");

            // Add optional access_type for refresh token support.
            String accessType = (String) context.get(OAuth2DebugConstants.DEBUG_CUSTOM_ACCESS_TYPE);
            if (StringUtils.isNotEmpty(accessType)) {
                urlBuilder.append("&access_type=").append(encodeParam(accessType));
            }

            // Add login_hint if username is available.
            String username = (String) context.get(OAuth2DebugConstants.DEBUG_USERNAME);
            if (StringUtils.isNotEmpty(username)) {
                urlBuilder.append("&login_hint=").append(encodeParam(username));
            }

            // Add any additional custom parameters from context.
            appendAdditionalParams(urlBuilder, context);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Generated OAuth2 Authorization URL with PKCE for IdP: " +
                        context.get(OAuth2DebugConstants.DEBUG_IDP_NAME));
            }

            return urlBuilder.toString();
        } catch (ExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new ExecutionException("Error building authorization URL: " + e.getMessage(), e);
        }
    }

    /**
     * Appends additional custom parameters from the context to the URL.
     */
    @SuppressWarnings("unchecked")
    private void appendAdditionalParams(StringBuilder urlBuilder, Map<String, Object> context)
            throws ExecutionException {

        Object additionalParamsObj = context.get(OAuth2DebugConstants.ADDITIONAL_OAUTH_PARAMS);
        if (additionalParamsObj instanceof Map) {
            Map<String, String> additionalParams = (Map<String, String>) additionalParamsObj;
            for (Map.Entry<String, String> entry : additionalParams.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    urlBuilder.append("&").append(entry.getKey()).append("=")
                            .append(encodeParam(entry.getValue()));
                }
            }
        }
    }

    /**
     * URL-encodes a parameter value.
     */
    private String encodeParam(String param) throws ExecutionException {

        try {
            return URLEncoder.encode(param, StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            throw new ExecutionException("Failed to URL-encode parameter: " + e.getMessage(), e);
        }
    }

    /**
     * Gets the default redirect URI for debug callback.
     * Configurable via system property 'debug.oauth2.redirect.uri'.
     */
    private String getDefaultRedirectUri() {

        String customUri = System.getProperty("debug.oauth2.redirect.uri");
        if (StringUtils.isNotEmpty(customUri)) {
            return customUri;
        }

        // Use IdentityUtil to resolve the actual server URL dynamically.
        return IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
    }

    /**
     * Caches the debug context using the standalone DebugSessionCache.
     */
    private void cacheDebugContext(Map<String, Object> context) {

        try {
            String state = (String) context.get(OAuth2DebugConstants.DEBUG_STATE);
            if (state == null) {
                LOG.warn("Cannot cache debug context - state parameter is null");
                return;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Caching debug context with state: " + state +
                        ", TOKEN_ENDPOINT=" +
                        (context.get(OAuth2DebugConstants.TOKEN_ENDPOINT) != null ? "FOUND" : "null") +
                        ", CLIENT_ID=" +
                        (context.get(OAuth2DebugConstants.CLIENT_ID) != null ? "FOUND" : "null"));
            }

            DebugSessionCache.getInstance().put(state, context);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Debug context cached successfully with state: " + state);
            }
        } catch (Exception e) {
            LOG.error("Error caching debug context: " + e.getMessage(), e);
        }
    }
}
