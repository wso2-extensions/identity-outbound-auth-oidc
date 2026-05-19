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
import java.util.UUID;

/**
 * OIDC debug flow executor.
 * Reads resolved OIDC parameters from the context (populated by OIDCContextProvider) and generates a complete
 * Authorization URL with PKCE and nonce parameters, then persists the context to the session store for callback
 * retrieval.
 */
public class OIDCDebugExecutor extends DebugExecutor {

    private static final Log LOG = LogFactory.getLog(OIDCDebugExecutor.class);

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
            String clientId = (String) context.getProperty(OIDCDebugConstants.CLIENT_ID);
            String authzEndpoint = (String) context.getProperty(OIDCDebugConstants.AUTHORIZATION_ENDPOINT);
            String redirectUri = (String) context.getProperty(OIDCDebugConstants.REDIRECT_URI);

            if (StringUtils.isEmpty(redirectUri)) {
                redirectUri = getDefaultRedirectUri();
            }

            validateRequiredParams(clientId, authzEndpoint, redirectUri);

            String codeVerifier = OIDCDebugUtil.generatePKCECodeVerifier();
            String codeChallenge = OIDCDebugUtil.generatePKCECodeChallenge(codeVerifier);

            // Nonce mitigates ID Token replay attacks.
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
            context.setProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL, authorizationUrl);

            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_SUCCESS, "Configurations validated successfully.");

            cacheDebugContext(context);

            result.setSuccessful(true);
            result.setDebugId(debugId);
            result.setStatus(DebugFrameworkConstants.DEBUG_STATUS_SUCCESS_INCOMPLETE);
            result.addResultData(OIDCDebugConstants.RESULT_AUTHORIZATION_URL, authorizationUrl);

            if (LOG.isDebugEnabled()) {
                LOG.debug("OIDC Authorization URL result: debugId=" + debugId + ", authorizationUrl present: true");
            }

            return result;

        } catch (DebugExecutionException e) {
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_FAILED, e.getMessage());
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error generating OIDC Authorization URL: " + e.getMessage(), e);
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

    private void validateRequiredParams(String clientId,
            String authzEndpoint, String redirectUri) throws DebugExecutionException {

        if (StringUtils.isEmpty(clientId)) {
            throw new DebugExecutionException("Missing required parameter: CLIENT_ID");
        }
        if (StringUtils.isEmpty(authzEndpoint)) {
            throw new DebugExecutionException("Missing required parameter: AUTHORIZATION_ENDPOINT");
        }
        if (StringUtils.isEmpty(redirectUri)) {
            throw new DebugExecutionException("Missing required parameter: REDIRECT_URI");
        }
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
            // Use & if the endpoint already contains query parameters, otherwise start with ?.
            urlBuilder.append(authzEndpoint.contains("?") ? "&" : "?").append("response_type=code");
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
     * Validates that the authorization endpoint is an absolute URL using HTTPS.
     * HTTP is permitted for loopback addresses (localhost, 127.0.0.1, ::1) to support local development.
     */
    private void validateAuthorizationEndpoint(String authzEndpoint) throws DebugExecutionException {

        try {
            URI endpointUri = new URI(authzEndpoint);
            if (!endpointUri.isAbsolute()) {
                throw new DebugExecutionException(
                        "Authorization endpoint must be an absolute URL: " + authzEndpoint);
            }
            String scheme = endpointUri.getScheme();
            if (!"https".equalsIgnoreCase(scheme)) {
                String host = endpointUri.getHost();
                boolean isLoopback = "localhost".equalsIgnoreCase(host)
                        || "127.0.0.1".equals(host)
                        || "::1".equals(host);
                if (!isLoopback) {
                    throw new DebugExecutionException(
                            "Authorization endpoint must use HTTPS: " + authzEndpoint);
                }
            }
        } catch (DebugExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new DebugExecutionException("Invalid authorization endpoint: " + authzEndpoint, e);
        }
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
