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

package org.wso2.carbon.identity.application.authenticator.oidc.debug;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.debug.framework.cache.DebugSessionCache;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCDebugUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCDebugDiagnosticsUtil;
import org.wso2.carbon.identity.debug.framework.exception.ExecutionException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.model.DebugResult;

import java.util.HashMap;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

/**
 * OIDC debug flow executor.
 * Extends the framework's DebugExecutor to provide OIDC-specific execution
 * logic.
 * Generates OIDC Authorization URLs with PKCE parameters and handles debug
 * state management.
 *
 * PKCE generation is delegated to {@link OIDCDebugUtil} (single source of
 * truth).
 * Session caching is delegated to {@link DebugSessionCache} (standalone class).
 */
public class OIDCDebugExecutor extends DebugExecutor {

    private static final Log LOG = LogFactory.getLog(OIDCDebugExecutor.class);
    private static final String EXECUTOR_NAME = "OIDCExecutor";

    /**
     * Executes OIDC debug flow and generates authorization URL.
     * Reads resolved OIDC parameters from context map (populated by
     * OIDCContextProvider) and generates a complete Authorization URL with PKCE
     * parameters.
     *
     * @param context DebugContext containing debug configuration and state (prepared by
     *                DebugContextProvider).
     * @return DebugResult containing the generated authorization URL and metadata.
     * @throws ExecutionException If execution fails.
     */
    @Override
    public DebugResult execute(DebugContext context) throws ExecutionException {

        DebugResult result = new DebugResult();

        if (context == null) {
            throw new ExecutionException("Context is null");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Executing OIDC authorization URL generation");
        }

        try {
            // Initialize step status.
            context.setProperty(OIDCDebugConstants.STEP_CONNECTION_STATUS, OIDCDebugConstants.STATUS_STARTED);
            context.setProperty(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS, OIDCDebugConstants.STATUS_STARTED);
            context.setProperty(OIDCDebugConstants.STEP_CLAIM_MAPPING_STATUS, OIDCDebugConstants.STATUS_STARTED);
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_STARTED, "Starting OIDC authorization request generation.");

            // Validate required parameters from context (populated by DebugContextProvider).
            String clientId = (String) context.getProperty(OIDCDebugConstants.CLIENT_ID);
            String authzEndpoint = (String) context.getProperty(OIDCDebugConstants.AUTHORIZATION_ENDPOINT);
            String redirectUri = (String) context.getProperty(OIDCDebugConstants.REDIRECT_URI);

            // Use default callback URI if custom one not provided.
            if (StringUtils.isEmpty(redirectUri)) {
                redirectUri = getDefaultRedirectUri();
            }

            validateRequiredParams(context, clientId, authzEndpoint, redirectUri);

            if (LOG.isDebugEnabled()) {
                LOG.debug("OIDC configuration validated from context - ClientId: FOUND, AuthzEndpoint: " +
                        authzEndpoint);
            }

            // Generate PKCE parameters using the single source of truth.
            String codeVerifier = OIDCDebugUtil.generatePKCECodeVerifier();
            String codeChallenge = OIDCDebugUtil.generatePKCECodeChallenge(codeVerifier);

            // Use contextId as the state parameter for consistency between initial response and callback.
            String contextId = (String) context.getProperty(OIDCDebugConstants.DEBUG_CONTEXT_ID);
            if (contextId == null) {
                contextId = "debug-" + UUID.randomUUID().toString();
            }
            String state = contextId;

            context.setProperty(OIDCDebugConstants.DEBUG_CODE_VERIFIER, codeVerifier);
            context.setProperty(OIDCDebugConstants.DEBUG_STATE, state);
            context.setProperty(OIDCDebugConstants.DEBUG_CONTEXT_ID, contextId);

            // Build OIDC Authorization URL.
            String authorizationUrl = buildAuthorizationUrl(authzEndpoint, clientId, redirectUri, state,
                    codeChallenge, context);

            if (authorizationUrl == null) {
                markAllStepsFailed(context);
                throw new ExecutionException("Failed to build authorization URL");
            }

            // Store authorization URL in context.
            context.setProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL, authorizationUrl);
            context.setProperty(OIDCDebugConstants.IS_DEBUG_FLOW, Boolean.TRUE);

            // Update step status.
            context.setProperty(OIDCDebugConstants.STEP_CONNECTION_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
            context.setProperty(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
            context.setProperty(OIDCDebugConstants.STEP_CLAIM_MAPPING_STATUS, "pending");
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_SUCCESS, "Authorization URL generated successfully.",
            buildAuthorizationResultDetails(contextId, state, authorizationUrl));

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
            result.addMetadata("idpName", context.getProperty(OIDCDebugConstants.DEBUG_IDP_NAME));
            result.addResultData(OIDCDebugConstants.DEBUG_DIAGNOSTICS, OIDCDebugDiagnosticsUtil.getDiagnostics(context));
            result.addMetadata(OIDCDebugConstants.DEBUG_DIAGNOSTICS, OIDCDebugDiagnosticsUtil.getDiagnostics(context));

            if (LOG.isDebugEnabled()) {
                LOG.debug("OIDC Authorization URL result: sessionId=" + contextId +
                        ", state=" + state + ", authorizationUrl present: true");
            }

            return result;

        } catch (ExecutionException e) {
            markAllStepsFailed(context);
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_FAILED, e.getMessage());
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error generating OIDC Authorization URL: " + e.getMessage(), e);
            markAllStepsFailed(context);
            OIDCDebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_FAILED, "Error generating authorization URL: " + e.getMessage());
            throw new ExecutionException("Error generating authorization URL: " + e.getMessage(), e);
        }
    }

    /**
     * Executes OIDC debug flow using a map-based context.
     *
     * @param context Map-based debug context.
     * @return DebugResult containing execution output.
     * @throws ExecutionException If execution fails.
     */
    @Override
    public DebugResult execute(Map<String, Object> context) throws ExecutionException {

        return execute(DebugContext.buildFromMap(context));
    }

    /**
     * Checks if this executor can handle the given debug context.
     *
     * @param debugContext The debug context to validate.
     * @return true if this executor can handle the context, false otherwise.
     */
    @Override
    public boolean canExecute(DebugContext debugContext) {

        return debugContext != null &&
                debugContext.getProperty(OIDCDebugConstants.CLIENT_ID) != null &&
                debugContext.getProperty(OIDCDebugConstants.AUTHORIZATION_ENDPOINT) != null &&
                debugContext.getProperty(OIDCDebugConstants.IDP_SCOPE) != null;
    }

    /**
     * Checks if this executor can handle the given map-based context.
     *
     * @param context Map-based debug context.
     * @return true if this executor can handle the context, false otherwise.
     */
    @Override
    public boolean canExecute(Map<String, Object> context) {

        return canExecute(DebugContext.buildFromMap(context));
    }

    /**
     * Gets the executor name.
     *
     * @return Executor name string.
     */
    @Override
    public String getExecutorName() {

        return EXECUTOR_NAME;
    }

    /**
     * Validates required parameters and throws ExecutionException if any are
     * missing.
     */
    private void validateRequiredParams(DebugContext context, String clientId,
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
    private void markAllStepsFailed(DebugContext context) {

        context.setProperty(OIDCDebugConstants.STEP_CONNECTION_STATUS, OIDCDebugConstants.STATUS_FAILED);
        context.setProperty(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS, OIDCDebugConstants.STATUS_FAILED);
        context.setProperty(OIDCDebugConstants.STEP_CLAIM_MAPPING_STATUS, OIDCDebugConstants.STATUS_FAILED);
    }

    /**
     * Builds the complete OIDC Authorization URL with PKCE parameters.
     */
    private String buildAuthorizationUrl(String authzEndpoint, String clientId, String redirectUri,
            String state, String codeChallenge, DebugContext context) throws ExecutionException {

        try {
            StringBuilder urlBuilder = new StringBuilder();
            urlBuilder.append(authzEndpoint);
            urlBuilder.append("?response_type=code");
            urlBuilder.append("&client_id=").append(encodeParam(clientId));
            urlBuilder.append("&redirect_uri=").append(encodeParam(redirectUri));

            String scope = (String) context.getProperty(OIDCDebugConstants.IDP_SCOPE);
            if (StringUtils.isEmpty(scope)) {
                throw new ExecutionException("Scope not found in context");
            }
            urlBuilder.append("&scope=").append(encodeParam(scope));
            urlBuilder.append("&state=").append(encodeParam(state));

            // Add PKCE parameters (always enabled for debug flow).
            urlBuilder.append("&code_challenge=").append(encodeParam(codeChallenge));
            urlBuilder.append("&code_challenge_method=S256");

            // Add optional access_type for refresh token support.
            String accessType = (String) context.getProperty(OIDCDebugConstants.DEBUG_CUSTOM_ACCESS_TYPE);
            if (StringUtils.isNotEmpty(accessType)) {
                urlBuilder.append("&access_type=").append(encodeParam(accessType));
            }

            // Add login_hint if username is available.
            String username = (String) context.getProperty(OIDCDebugConstants.DEBUG_USERNAME);
            if (StringUtils.isNotEmpty(username)) {
                urlBuilder.append("&login_hint=").append(encodeParam(username));
            }

            // Add any additional custom parameters from context.
            appendAdditionalParams(urlBuilder, context);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Generated OIDC Authorization URL with PKCE for IdP: " +
                        context.getProperty(OIDCDebugConstants.DEBUG_IDP_NAME));
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
    private void appendAdditionalParams(StringBuilder urlBuilder, DebugContext context)
            throws ExecutionException {

        Object additionalParamsObj = context.getProperty(OIDCDebugConstants.ADDITIONAL_OIDC_PARAMS);
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
     * Configurable via system property 'debug.OIDC.redirect.uri'.
     */
    private String getDefaultRedirectUri() {

        String customUri = System.getProperty("debug.OIDC.redirect.uri");
        if (StringUtils.isNotEmpty(customUri)) {
            return customUri;
        }

        // Use IdentityUtil to resolve the actual server URL dynamically.
        return IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
    }

    /**
     * Caches the debug context using the standalone DebugSessionCache.
     */
    private void cacheDebugContext(DebugContext context) {

        try {
            String state = (String) context.getProperty(OIDCDebugConstants.DEBUG_STATE);
            if (state == null) {
                LOG.warn("Cannot cache debug context - state parameter is null");
                return;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Caching debug context with state: " + state +
                        ", TOKEN_ENDPOINT=" +
                        (context.getProperty(OIDCDebugConstants.TOKEN_ENDPOINT) != null ? "FOUND" : "null") +
                        ", CLIENT_ID=" +
                        (context.getProperty(OIDCDebugConstants.CLIENT_ID) != null ? "FOUND" : "null"));
            }

            DebugSessionCache.getInstance().put(state, context);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Debug context cached successfully with state: " + state);
            }
        } catch (Exception e) {
            LOG.error("Error caching debug context: " + e.getMessage(), e);
        }
    }

    private Map<String, Object> buildAuthorizationResultDetails(String contextId, String state,
                                                                String authorizationUrl) {

        Map<String, Object> details = new HashMap<>();
        details.put("sessionId", contextId);
        details.put("state", state);
        details.put("authorizationUrlPresent", StringUtils.isNotBlank(authorizationUrl));
        return details;
    }

}
