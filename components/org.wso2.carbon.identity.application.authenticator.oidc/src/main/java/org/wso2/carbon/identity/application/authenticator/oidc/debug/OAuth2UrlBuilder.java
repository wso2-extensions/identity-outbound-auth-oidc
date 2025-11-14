/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.debug;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.exception.ExecutionException;
import org.wso2.carbon.identity.debug.framework.model.DebugResult;

import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

/**
 * OAuth2 debug flow executor.
 * Extends the framework's DebugExecutor to provide OAuth2-specific execution logic.
 * Generates OAuth2 Authorization URLs with PKCE parameters and handles debug state management.
 */
public class OAuth2UrlBuilder extends DebugExecutor {

    private static final Log LOG = LogFactory.getLog(OAuth2UrlBuilder.class);
    private static final String DEBUG_IDENTIFIER_PARAM = "isDebugFlow";
    private static final String EXECUTOR_NAME = "OAuth2Executor";

    /**
     * Executes OAuth2 debug flow and generates authorization URL.
     * Reads resolved OAuth2 parameters from context map (populated by OAuth2ContextResolver)
     * and generates a complete Authorization URL with PKCE parameters.
     *
     * @param context Map containing debug configuration and state (prepared by DebugContextResolver).
     * @return DebugResult containing the generated authorization URL and metadata.
     * @throws ExecutionException If execution fails.
     */
    @Override
    public DebugResult execute(Map<String, Object> context) throws ExecutionException {
        // Initialize step status.
        DebugResult result = new DebugResult();

        if (context == null) {
            throw new ExecutionException("Context map is null");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Executing OAuth2 authorization URL generation");
        }

        try {
            // Initialize step status.
            context.put("step_connection_status", "started");
            context.put("step_authentication_status", "started");
            context.put("step_claim_mapping_status", "started");

            // Validate required parameters from context (populated by DebugContextResolver).
            String clientId = (String) context.get("DEBUG_CLIENT_ID");
            String authzEndpoint = (String) context.get("DEBUG_AUTHZ_ENDPOINT");

            if (StringUtils.isEmpty(clientId)) {
                LOG.error("DEBUG_CLIENT_ID not found in context");
                context.put("step_connection_status", "failed");
                context.put("step_authentication_status", "failed");
                context.put("step_claim_mapping_status", "failed");
                throw new ExecutionException("Missing required parameter: CLIENT_ID");
            }

            if (StringUtils.isEmpty(authzEndpoint)) {
                LOG.error("DEBUG_AUTHZ_ENDPOINT not found in context");
                context.put("step_connection_status", "failed");
                context.put("step_authentication_status", "failed");
                context.put("step_claim_mapping_status", "failed");
                throw new ExecutionException("Missing required parameter: AUTHORIZATION_ENDPOINT");
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuth2 configuration validated from context - ClientId: FOUND, AuthzEndpoint: " + 
                        authzEndpoint);
            }

            // Generate PKCE parameters.
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = generateCodeChallenge(codeVerifier);
            String state = (String) context.getOrDefault("DEBUG_CONTEXT_ID", generateState());

            context.put("DEBUG_CODE_VERIFIER", codeVerifier);
            context.put("DEBUG_STATE", state);

            // Build redirect URI for debug callback.
            String redirectUri = "https://localhost:9443/commonauth";

            // Build OAuth2 Authorization URL.
            String authorizationUrl = buildAuthorizationUrl(authzEndpoint, clientId, redirectUri, state, 
                    codeChallenge, context);

            if (authorizationUrl == null) {
                LOG.error("Failed to build authorization URL");
                context.put("step_connection_status", "failed");
                context.put("step_authentication_status", "failed");
                context.put("step_claim_mapping_status", "failed");
                throw new ExecutionException("Failed to build authorization URL");
            }

            // Store authorization URL in context.
            context.put("DEBUG_EXTERNAL_REDIRECT_URL", authorizationUrl);
            context.put(DEBUG_IDENTIFIER_PARAM, "true");
            context.put("DEBUG_AUTH_URL_GENERATED", "true");
            context.put("DEBUG_AUTH_URL_TIMESTAMP", System.currentTimeMillis());
            context.put("DEBUG_STEP_AUTH_URL_GENERATED", true);
            context.put("DEBUG_STEP_AUTH_URL", authorizationUrl);

            // Update step status to success.
            context.put("step_connection_status", "success");
            context.put("step_authentication_status", "success");
            context.put("step_claim_mapping_status", "pending");

            // Cache authentication context for framework to retrieve during callback.
            cacheDebugContext(context);

            // Build result with authorization URL.
            result.setSuccessful(true);
            result.setStatus("Authorization URL generated successfully");
            result.addResultData("authorizationUrl", authorizationUrl);
            result.addMetadata("authorizationUrl", authorizationUrl);
            result.addMetadata("state", state);
            result.addMetadata("codeVerifier", codeVerifier);
            result.addMetadata("idpName", context.get("DEBUG_IDP_NAME"));

            LOG.info("OAuth2 Authorization URL generated successfully");
            return result;

        } catch (ExecutionException e) {
            LOG.error("Error generating OAuth2 Authorization URL: " + e.getMessage(), e);
            context.put("step_connection_status", "failed");
            context.put("step_authentication_status", "failed");
            context.put("step_claim_mapping_status", "failed");
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error generating OAuth2 Authorization URL: " + e.getMessage(), e);
            context.put("step_connection_status", "failed");
            context.put("step_authentication_status", "failed");
            context.put("step_claim_mapping_status", "failed");
            throw new ExecutionException("Error generating authorization URL: " + e.getMessage(), e);
        }
    }

    /**
     * Validates if this executor can handle the given context.
     * Returns true if context contains OAuth2-specific parameters.
     *
     * @param context Map to validate.
     * @return true if this executor can handle the context.
     */
    @Override
    public boolean canExecute(Map<String, Object> context) {
        return context != null && context.containsKey("DEBUG_CLIENT_ID") && 
                context.containsKey("DEBUG_AUTHZ_ENDPOINT") && context.containsKey("DEBUG_IDP_SCOPE");
    }

    /**
     * Gets the name/type of this executor.
     *
     * @return Executor name string.
     */
    @Override
    public String getExecutorName() {
        return EXECUTOR_NAME;
    }

    /**
     * Builds the complete OAuth2 Authorization URL with PKCE parameters.
     *
     * @param authzEndpoint Authorization endpoint URL.
     * @param clientId OAuth2 client ID.
     * @param redirectUri Redirect URI for callback.
     * @param state State parameter for CSRF protection.
     * @param codeChallenge PKCE code challenge.
     * @param context Debug context map.
     * @return Complete authorization URL.
     * @throws ExecutionException If URL building fails.
     */
    private String buildAuthorizationUrl(String authzEndpoint, String clientId, String redirectUri, 
                                        String state, String codeChallenge, 
                                        Map<String, Object> context) throws ExecutionException {
        try {
            StringBuilder urlBuilder = new StringBuilder();
            urlBuilder.append(authzEndpoint);
            urlBuilder.append("?response_type=code");
            urlBuilder.append("&client_id=").append(encodeParam(clientId));
            urlBuilder.append("&redirect_uri=").append(encodeParam(redirectUri));

            // Get scope from context (set by DebugContextResolver).
            String scope = (String) context.get("DEBUG_IDP_SCOPE");
            if (StringUtils.isEmpty(scope)) {
                throw new ExecutionException("Scope not found in context");
            }
            urlBuilder.append("&scope=").append(encodeParam(scope));
            urlBuilder.append("&state=").append(encodeParam(state));

            // Add PKCE parameters (PKCE is always enabled for debug flow).
            urlBuilder.append("&code_challenge=").append(encodeParam(codeChallenge));
            urlBuilder.append("&code_challenge_method=S256");

            // Add optional access_type for refresh token support.
            String accessType = (String) context.get("DEBUG_CUSTOM_access_type");
            if (StringUtils.isNotEmpty(accessType)) {
                urlBuilder.append("&access_type=").append(encodeParam(accessType));
            }

            // Add login_hint if username is available.
            String username = (String) context.get("DEBUG_USERNAME");
            if (StringUtils.isNotEmpty(username)) {
                urlBuilder.append("&login_hint=").append(encodeParam(username));
            }

            // Add any additional custom parameters from context.
            @SuppressWarnings("unchecked")
            Map<String, String> additionalParams = (Map<String, String>) context.get("ADDITIONAL_OAUTH_PARAMS");
            if (additionalParams != null) {
                for (Map.Entry<String, String> entry : additionalParams.entrySet()) {
                    urlBuilder.append("&").append(entry.getKey()).append("=")
                            .append(encodeParam(entry.getValue()));
                }
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Generated OAuth2 Authorization URL with PKCE for IdP: " + 
                        context.get("DEBUG_IDP_NAME"));
            }

            return urlBuilder.toString();
        } catch (Exception e) {
            LOG.error("Error building OAuth2 Authorization URL: " + e.getMessage(), e);
            throw new ExecutionException("Error building authorization URL: " + e.getMessage(), e);
        }
    }

    /**
     * Generates a cryptographically secure code verifier for PKCE.
     *
     * @return Base64URL-encoded code verifier.
     */
    private String generateCodeVerifier() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Generates code challenge from code verifier using SHA256.
     *
     * @param codeVerifier The code verifier.
     * @return Base64URL-encoded code challenge.
     * @throws ExecutionException If challenge generation fails.
     */
    private String generateCodeChallenge(String codeVerifier) throws ExecutionException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes("UTF-8"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            LOG.error("Error generating code challenge: " + e.getMessage(), e);
            throw new ExecutionException("Failed to generate PKCE code challenge: " + e.getMessage(), e);
        }
    }

    /**
     * URL-encodes a parameter value.
     *
     * @param param Parameter to encode.
     * @return URL-encoded parameter.
     * @throws ExecutionException If encoding fails.
     */
    private String encodeParam(String param) throws ExecutionException {
        try {
            return URLEncoder.encode(param, "UTF-8");
        } catch (Exception e) {
            LOG.error("Error encoding parameter: " + e.getMessage(), e);
            throw new ExecutionException("Failed to URL-encode parameter: " + e.getMessage(), e);
        }
    }

    /**
     * Generates a random state parameter.
     *
     * @return Random state string.
     */
    private String generateState() {
        return "debug-" + java.util.UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * Caches the debug context using HttpSession.
     * Ensures the context can be retrieved during OAuth2 callback processing.
     * Uses a static session map as fallback if HttpSession is not available.
     *
     * @param context Debug context to cache.
     */
    private void cacheDebugContext(Map<String, Object> context) {
        try {
            // Get the state parameter which will be used as cache key
            String state = (String) context.get("DEBUG_STATE");
            if (state == null) {
                LOG.warn("Cannot cache debug context - state parameter is null");
                return;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Caching debug context with state: " + state + 
                         ", DEBUG_TOKEN_ENDPOINT=" + (context.get("DEBUG_TOKEN_ENDPOINT") != null ? "FOUND" : "null") +
                         ", DEBUG_CLIENT_ID=" + (context.get("DEBUG_CLIENT_ID") != null ? "FOUND" : "null") +
                         ", context keys: " + context.keySet());
            }

            // Try to use static session map for caching
            // This is accessible from both OAuth2UrlBuilder (initiator) and
            // DebugRequestCoordinator (callback handler via OAuth2DebugProcessor)
            DebugSessionCache.getInstance().put(state, context);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Debug context cached successfully with state: " + state);
            }
        } catch (Exception e) {
            LOG.error("Error caching debug context: " + e.getMessage(), e);
            // Non-fatal - log but don't throw
        }
    }

    /**
     * Simple in-memory session cache for debug contexts.
     * Used to pass data from OAuth2UrlBuilder to DebugRequestCoordinator (via OAuth2DebugProcessor).
     * The consolidated DebugRequestCoordinator in the framework module retrieves contexts
     * from this cache for OAuth2 protocol processing.
     */
    public static class DebugSessionCache {
        private static final DebugSessionCache INSTANCE = new DebugSessionCache();
        private final Map<String, Map<String, Object>> cache = new java.util.concurrent.ConcurrentHashMap<>();
        private final int CACHE_TIMEOUT_MINUTES = 60;

        public static DebugSessionCache getInstance() {
            return INSTANCE;
        }

        public synchronized void put(String key, Map<String, Object> value) {
            cache.put(key, value);
            // Schedule removal after timeout
            scheduleRemoval(key);
        }

        public synchronized Map<String, Object> get(String key) {
            return cache.get(key);
        }

        public synchronized Map<String, Object> remove(String key) {
            return cache.remove(key);
        }

        private void scheduleRemoval(String key) {
            java.util.Timer timer = new java.util.Timer(true);
            timer.schedule(new java.util.TimerTask() {
                @Override
                public void run() {
                    cache.remove(key);
                }
            }, CACHE_TIMEOUT_MINUTES * 60 * 1000);
        }
    }
}
