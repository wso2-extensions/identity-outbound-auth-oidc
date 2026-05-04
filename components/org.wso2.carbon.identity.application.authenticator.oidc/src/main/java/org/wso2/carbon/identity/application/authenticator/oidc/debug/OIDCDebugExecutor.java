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
import org.wso2.carbon.identity.debug.framework.store.DebugSessionStore;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCDebugUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.util.DebugDiagnosticsUtil;
import org.wso2.carbon.identity.debug.framework.exception.ExecutionException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.model.DebugResult;

import java.util.HashMap;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
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
 * Session persistence is delegated to {@link DebugSessionStore}.
 */
public class OIDCDebugExecutor extends DebugExecutor {

    private static final Log LOG = LogFactory.getLog(OIDCDebugExecutor.class);

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

            // Generate cryptographic nonce for ID Token replay mitigation (OIDC Core §3.1.2.1).
            String nonce = generateNonce();

            // Use debugId as the callback state token for consistency between initial response and callback.
            String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_CONTEXT_ID);
            if (debugId == null) {
                debugId = "debug-" + UUID.randomUUID().toString();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No debugId found in context (expected from ContextProvider). " +
                            "Generated fallback debugId: " + debugId);
                }
            }
            String callbackState = debugId;

            context.setProperty(OIDCDebugConstants.DEBUG_CODE_VERIFIER, codeVerifier);
            // Store nonce in context for validation during callback token processing.
            context.setProperty(OIDCDebugConstants.DEBUG_NONCE, nonce);
            context.setProperty(OIDCDebugConstants.DEBUG_CONTEXT_ID, debugId);

            // Build OIDC Authorization URL.
            String authorizationUrl = buildAuthorizationUrl(authzEndpoint, clientId, redirectUri, callbackState,
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
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_SUCCESS, "Configurations validated successfully.");

            // Cache authentication context for retrieval during callback.
            cacheDebugContext(context);

            // Build result.
            result.setSuccessful(true);
            result.setStatus("Configurations validated successfully.");
            result.addResultData("authorizationUrl", authorizationUrl);
            result.addResultData("debugId", debugId);
            result.addMetadata("authorizationUrl", authorizationUrl);
            result.addMetadata("debugId", debugId);
            // Note: codeVerifier is intentionally NOT included in metadata to prevent PKCE bypass.
            // It is stored securely in DebugSessionStore for use during the callback token exchange.
            result.addMetadata("idpName", context.getProperty(OIDCDebugConstants.DEBUG_IDP_NAME));
            result.addResultData(OIDCDebugConstants.DEBUG_DIAGNOSTICS, DebugDiagnosticsUtil.getDiagnostics(context));
            result.addMetadata(OIDCDebugConstants.DEBUG_DIAGNOSTICS, DebugDiagnosticsUtil.getDiagnostics(context));

            if (LOG.isDebugEnabled()) {
                LOG.debug("OIDC Authorization URL result: debugId=" + debugId +
                        ", authorizationUrl present: true");
            }

            return result;

        } catch (ExecutionException e) {
            markAllStepsFailed(context);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_FAILED, e.getMessage());
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error generating OIDC Authorization URL: " + e.getMessage(), e);
            markAllStepsFailed(context);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
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

        return OIDCDebugConstants.DEBUG_EXECUTOR_NAME;
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

            // Add nonce for ID Token replay protection (OIDC Core §3.1.2.1).
            String nonce = (String) context.getProperty(OIDCDebugConstants.DEBUG_NONCE);
            if (StringUtils.isNotEmpty(nonce)) {
                urlBuilder.append("&nonce=").append(encodeParam(nonce));
            }

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
                if (entry.getKey() != null && entry.getValue() != null &&
                        isValidAdditionalParamKey(entry.getKey())) {
                    urlBuilder.append("&").append(entry.getKey()).append("=")
                            .append(encodeParam(entry.getValue()));
                }
            }
        }
    }

    private boolean isValidAdditionalParamKey(String key) {

        return StringUtils.isNotBlank(key) && key.matches("[A-Za-z0-9._-]+");
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
     * Stores the debug context using the shared DebugSessionStore.
     */
    private void cacheDebugContext(DebugContext context) {

        try {
            String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_CONTEXT_ID);
            if (debugId == null) {
                LOG.warn("Cannot cache debug context - debugId is null");
                return;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Caching debug context with debugId: " + debugId +
                        ", TOKEN_ENDPOINT=" +
                        (context.getProperty(OIDCDebugConstants.TOKEN_ENDPOINT) != null ? "FOUND" : "null") +
                        ", CLIENT_ID=" +
                        (context.getProperty(OIDCDebugConstants.CLIENT_ID) != null ? "FOUND" : "null"));
            }

            DebugSessionStore.getInstance().put(debugId, context);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Debug context cached successfully with debugId: " + debugId);
            }
        } catch (Exception e) {
            LOG.error("Error caching debug context: " + e.getMessage(), e);
        }
    }

    /**
     * Generates a cryptographic nonce for OIDC ID Token replay protection.
     * Uses SecureRandom for 32 bytes of entropy, encoded as URL-safe Base64.
     *
     * @return Cryptographically random nonce string.
     */
    private String generateNonce() {

        byte[] nonceBytes = new byte[32];
        new SecureRandom().nextBytes(nonceBytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
    }

}
