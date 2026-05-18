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
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.store.DebugSessionStore;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCDebugUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.util.DebugDiagnosticsUtil;
import org.wso2.carbon.identity.debug.framework.exception.DebugExecutionException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.model.DebugResult;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

/**
 * OIDC debug flow executor.
 * Reads resolved OIDC parameters from the context (populated by OIDCContextProvider) and generates a complete
 * Authorization URL with PKCE and nonce parameters, then persists the context to the session store for callback
 * retrieval.
 */
public class OIDCDebugExecutor extends DebugExecutor {

    private static final Log LOG = LogFactory.getLog(OIDCDebugExecutor.class);
    private static final String RESULT_AUTHORIZATION_URL = "authorizationUrl";

    /**
     * Executes the OIDC debug flow: validates context, generates PKCE and nonce, builds the authorization URL,
     * caches the context, and returns a result containing the URL for the caller to redirect to.
     *
     * @param context DebugContext containing OIDC configuration prepared by OIDCContextProvider.
     * @return DebugResult containing the generated authorization URL and metadata.
     * @throws DebugExecutionException If a required parameter is missing or URL generation fails.
     */
    @Override
    public DebugResult execute(DebugContext context) throws DebugExecutionException {

        if (context == null) {
            throw new DebugExecutionException("Context is null");
        }

        DebugResult result = new DebugResult();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Executing OIDC authorization URL generation");
        }

        try {
            context.setProperty(OIDCDebugConstants.STEP_CONNECTION_STATUS, OIDCDebugConstants.STATUS_STARTED);
            context.setProperty(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS, OIDCDebugConstants.STATUS_STARTED);
            context.setProperty(OIDCDebugConstants.STEP_CLAIM_MAPPING_STATUS, OIDCDebugConstants.STATUS_STARTED);

            String clientId = (String) context.getProperty(OIDCDebugConstants.CLIENT_ID);
            String authzEndpoint = (String) context.getProperty(OIDCDebugConstants.AUTHORIZATION_ENDPOINT);
            String redirectUri = (String) context.getProperty(OIDCDebugConstants.REDIRECT_URI);

            if (StringUtils.isEmpty(redirectUri)) {
                redirectUri = getDefaultRedirectUri();
            }

            validateRequiredParams(context, clientId, authzEndpoint, redirectUri);

            if (LOG.isDebugEnabled()) {
                LOG.debug("OIDC configuration validated from context - ClientId: FOUND, AuthzEndpoint: " +
                        authzEndpoint);
            }

            String codeVerifier = OIDCDebugUtil.generatePKCECodeVerifier();
            String codeChallenge = OIDCDebugUtil.generatePKCECodeChallenge(codeVerifier);

            // Nonce mitigates ID Token replay attacks (OIDC Core §3.1.2.1).
            String nonce = OIDCDebugUtil.generateNonce();

            // debugId doubles as the OAuth state parameter — ties the callback back to this session.
            String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);
            if (debugId == null) {
                debugId = "debug-" + UUID.randomUUID();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No debugId found in context (expected from ContextProvider). " +
                            "Generated fallback debugId: " + debugId);
                }
            }

            context.setProperty(OIDCDebugConstants.DEBUG_CODE_VERIFIER, codeVerifier);
            // Nonce stored here is validated against the id_token nonce claim during callback processing.
            context.setProperty(OIDCDebugConstants.DEBUG_NONCE, nonce);

            String authorizationUrl = buildAuthorizationUrl(authzEndpoint, clientId, redirectUri, debugId,
                    codeChallenge, context);

            if (authorizationUrl == null) {
                markAllStepsFailed(context);
                throw new DebugExecutionException("Failed to build authorization URL");
            }

            context.setProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL, authorizationUrl);
            context.setProperty(OIDCDebugConstants.IS_DEBUG_FLOW, Boolean.TRUE);

            context.setProperty(OIDCDebugConstants.STEP_CONNECTION_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
            context.setProperty(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
            context.setProperty(OIDCDebugConstants.STEP_CLAIM_MAPPING_STATUS, OIDCDebugConstants.STATUS_PENDING);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_SUCCESS, "Configurations validated successfully.");

            cacheDebugContext(context);

            result.setSuccessful(true);
            result.setDebugId(debugId);
            result.setStatus(DebugFrameworkConstants.DEBUG_STATUS_SUCCESS_INCOMPLETE);
            result.addResultData(RESULT_AUTHORIZATION_URL, authorizationUrl);

            if (LOG.isDebugEnabled()) {
                LOG.debug("OIDC Authorization URL result: debugId=" + debugId + ", authorizationUrl present: true");
            }

            return result;

        } catch (DebugExecutionException e) {
            markAllStepsFailed(context);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_FAILED, e.getMessage());
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error generating OIDC Authorization URL: " + e.getMessage(), e);
            markAllStepsFailed(context);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_FAILED, "Error generating authorization URL: " + e.getMessage());
            throw new DebugExecutionException("Error generating authorization URL: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean canExecute(DebugContext debugContext) {

        return debugContext != null &&
                debugContext.getProperty(OIDCDebugConstants.CLIENT_ID) != null &&
                debugContext.getProperty(OIDCDebugConstants.AUTHORIZATION_ENDPOINT) != null &&
                debugContext.getProperty(OIDCDebugConstants.IDP_SCOPE) != null;
    }

    @Override
    public String getExecutorName() {

        return OIDCDebugConstants.DEBUG_EXECUTOR_NAME;
    }

    @Override
    public void cleanup() {

        // No OIDC-specific resources to release; DebugSessionStore entries expire automatically.
    }

    private void validateRequiredParams(DebugContext context, String clientId,
            String authzEndpoint, String redirectUri) throws DebugExecutionException {

        if (StringUtils.isEmpty(clientId)) {
            markAllStepsFailed(context);
            throw new DebugExecutionException("Missing required parameter: CLIENT_ID");
        }
        if (StringUtils.isEmpty(authzEndpoint)) {
            markAllStepsFailed(context);
            throw new DebugExecutionException("Missing required parameter: AUTHORIZATION_ENDPOINT");
        }
        if (StringUtils.isEmpty(redirectUri)) {
            markAllStepsFailed(context);
            throw new DebugExecutionException("Missing required parameter: REDIRECT_URI");
        }
    }

    private void markAllStepsFailed(DebugContext context) {

        context.setProperty(OIDCDebugConstants.STEP_CONNECTION_STATUS, OIDCDebugConstants.STATUS_FAILED);
        context.setProperty(OIDCDebugConstants.STEP_AUTHENTICATION_STATUS, OIDCDebugConstants.STATUS_FAILED);
        context.setProperty(OIDCDebugConstants.STEP_CLAIM_MAPPING_STATUS, OIDCDebugConstants.STATUS_FAILED);
    }

    /**
     * Builds the complete OIDC Authorization URL with required parameters (client_id, redirect_uri, scope, state),
     * PKCE (code_challenge/method), nonce, and any optional context parameters (access_type, login_hint, extras).
     */
    private String buildAuthorizationUrl(String authzEndpoint, String clientId, String redirectUri,
            String state, String codeChallenge, DebugContext context) throws DebugExecutionException {

        try {
            validateAuthorizationEndpoint(authzEndpoint);

            StringBuilder urlBuilder = new StringBuilder();
            urlBuilder.append(authzEndpoint);
            urlBuilder.append("?response_type=code");
            urlBuilder.append("&client_id=").append(encodeParam(clientId));
            urlBuilder.append("&redirect_uri=").append(encodeParam(redirectUri));

            String scope = (String) context.getProperty(OIDCDebugConstants.IDP_SCOPE);
            if (StringUtils.isEmpty(scope)) {
                throw new DebugExecutionException("Scope not found in context");
            }
            urlBuilder.append("&scope=").append(encodeParam(scope));
            urlBuilder.append("&state=").append(encodeParam(state));

            // PKCE is always required for debug flows.
            urlBuilder.append("&code_challenge=").append(encodeParam(codeChallenge));
            urlBuilder.append("&code_challenge_method=S256");

            // Nonce for ID Token replay protection (OIDC Core §3.1.2.1).
            String nonce = (String) context.getProperty(OIDCDebugConstants.DEBUG_NONCE);
            if (StringUtils.isNotEmpty(nonce)) {
                urlBuilder.append("&nonce=").append(encodeParam(nonce));
            }

            // Optional: access_type for refresh token support (Google-specific).
            String accessType = (String) context.getProperty(OIDCDebugConstants.DEBUG_CUSTOM_ACCESS_TYPE);
            if (StringUtils.isNotEmpty(accessType)) {
                urlBuilder.append("&access_type=").append(encodeParam(accessType));
            }

            // Optional: login_hint pre-fills the IdP login form with the known username.
            String username = (String) context.getProperty(OIDCDebugConstants.DEBUG_USERNAME);
            if (StringUtils.isNotEmpty(username)) {
                urlBuilder.append("&login_hint=").append(encodeParam(username));
            }

            appendAdditionalParams(urlBuilder, context);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Generated OIDC Authorization URL with PKCE for IdP: " +
                        context.getProperty(OIDCDebugConstants.DEBUG_IDP_NAME));
            }

            return urlBuilder.toString();
        } catch (DebugExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new DebugExecutionException("Error building authorization URL: " + e.getMessage(), e);
        }
    }

    /**
     * Validates that the authorization endpoint is an absolute HTTPS URL.
     * HTTP is permitted only for localhost, to support local development environments.
     */
    private void validateAuthorizationEndpoint(String authzEndpoint) throws DebugExecutionException {

        try {
            URI endpointUri = new URI(authzEndpoint);
            if (!endpointUri.isAbsolute()) {
                throw new DebugExecutionException(
                        "Authorization endpoint must be an absolute URL: " + authzEndpoint);
            }
            if (!"https".equalsIgnoreCase(endpointUri.getScheme()) && !isLocalhost(endpointUri.getHost())) {
                throw new DebugExecutionException(
                        "Authorization endpoint must use HTTPS: " + authzEndpoint);
            }
        } catch (DebugExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new DebugExecutionException("Invalid authorization endpoint: " + authzEndpoint, e);
        }
    }

    private boolean isLocalhost(String host) {

        return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host);
    }

    // Keys are validated against an allowlist to prevent open-redirect or parameter-injection via arbitrary keys.
    @SuppressWarnings("unchecked")
    private void appendAdditionalParams(StringBuilder urlBuilder, DebugContext context)
            throws DebugExecutionException {

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

    private String encodeParam(String param) throws DebugExecutionException {

        try {
            return URLEncoder.encode(param, StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            throw new DebugExecutionException("Failed to URL-encode parameter: " + e.getMessage(), e);
        }
    }

    private String getDefaultRedirectUri() {

        return IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
    }

    /**
     * Persists a sanitized copy of the context to the session store so it can be retrieved during the OIDC callback.
     * Credentials (clientSecret) and non-serializable objects (idpConfig) are nulled out before storage.
     * The live context's clientSecret is also cleared after the store write to prevent post-call exposure.
     */
    private void cacheDebugContext(DebugContext context) throws DebugExecutionException {

        String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);
        if (debugId == null) {
            throw new DebugExecutionException("Cannot cache debug context - debugId is null");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Caching debug context with debugId: " + debugId +
                    ", TOKEN_ENDPOINT=" +
                    (context.getProperty(OIDCDebugConstants.TOKEN_ENDPOINT) != null ? "FOUND" : "null") +
                    ", CLIENT_ID=" +
                    (context.getProperty(OIDCDebugConstants.CLIENT_ID) != null ? "FOUND" : "null"));
        }

        try {
            DebugContext sanitizedContext = DebugContext.buildFromMap(context.getProperties());
            sanitizedContext.setResourceType(context.getResourceType());
            sanitizedContext.setProperty(OIDCDebugConstants.CLIENT_SECRET, null);
            sanitizedContext.setProperty(OIDCDebugConstants.IDP_CONFIG, null);
            DebugSessionStore.getInstance().put(debugId, sanitizedContext);
        } catch (Exception e) {
            LOG.error("Error caching debug context: " + e.getMessage(), e);
            throw new DebugExecutionException("Failed to cache debug context for debugId: " + debugId, e);
        }

        // Clear from live context too — prevents exposure if caller code logs or inspects context after this call.
        context.setProperty(OIDCDebugConstants.CLIENT_SECRET, null);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Debug context cached successfully with debugId: " + debugId);
        }
    }
}
