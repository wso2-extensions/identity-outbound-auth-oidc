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
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.exception.ExecutionException;
import org.wso2.carbon.identity.debug.framework.model.DebugResult;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

/**
 * OAuth2 debug flow executor.
 * Extends the framework's DebugExecutor to provide OAuth2-specific execution logic.
 * Generates OAuth2 Authorization URLs with PKCE parameters and handles debug state management.
 */
public class OAuth2Executer extends DebugExecutor {

    private static final Log LOG = LogFactory.getLog(OAuth2Executer.class);
    private static final String EXECUTOR_NAME = "OAuth2Executor";
    private static final java.security.SecureRandom SECURE_RANDOM = new java.security.SecureRandom();

    /**
     * Executes OAuth2 debug flow and generates authorization URL.
     * Reads resolved OAuth2 parameters from context map (populated by OAuth2ContextResolver)
     * and generates a complete Authorization URL with PKCE parameters.
     *
     * @param context Map containing debug configuration and state (prepared by DebugContextProvider).
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
            context.put(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_STARTED);
            context.put(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_STARTED);
            context.put(OAuth2DebugConstants.STEP_CLAIM_MAPPING_STATUS, OAuth2DebugConstants.STATUS_STARTED);

            // Validate required parameters from context (populated by DebugContextProvider).
            String clientId = (String) context.get(OAuth2DebugConstants.CLIENT_ID);
            String authzEndpoint = (String) context.get(OAuth2DebugConstants.AUTHORIZATION_ENDPOINT);
            String redirectUri = (String) context.get(OAuth2DebugConstants.REDIRECT_URI);

            // Use default callback URI if custom one not provided
            if (redirectUri == null || redirectUri.trim().isEmpty()) {
                redirectUri = getDefaultRedirectUri();
            }

            if (StringUtils.isEmpty(clientId)) {
                LOG.error("clientId not found in context");
                context.put(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                context.put(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                context.put(OAuth2DebugConstants.STEP_CLAIM_MAPPING_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                throw new ExecutionException("Missing required parameter: CLIENT_ID");
            }

            if (StringUtils.isEmpty(authzEndpoint)) {
                LOG.error("DEBUG_AUTHZ_ENDPOINT not found in context");
                context.put(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                context.put(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                context.put(OAuth2DebugConstants.STEP_CLAIM_MAPPING_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                throw new ExecutionException("Missing required parameter: AUTHORIZATION_ENDPOINT");
            }

            if (StringUtils.isEmpty(redirectUri)) {
                LOG.error("Redirect URI not configured");
                context.put(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                context.put(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                context.put(OAuth2DebugConstants.STEP_CLAIM_MAPPING_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                throw new ExecutionException("Missing required parameter: REDIRECT_URI");
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("OAuth2 configuration validated from context - ClientId: FOUND, AuthzEndpoint: " + 
                        authzEndpoint);
            }

            // Generate PKCE parameters.
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = generateCodeChallenge(codeVerifier);
            String state = (String) context.getOrDefault("  ", generateState());
            String contextId = (String) context.getOrDefault(OAuth2DebugConstants.DEBUG_CONTEXT_ID, 
                    "debug-" + java.util.UUID.randomUUID().toString());

            context.put(OAuth2DebugConstants.DEBUG_CODE_VERIFIER, codeVerifier);
            context.put(OAuth2DebugConstants.DEBUG_STATE, state);
            context.put(OAuth2DebugConstants.DEBUG_CONTEXT_ID, contextId);

            // Build OAuth2 Authorization URL.
            String authorizationUrl = buildAuthorizationUrl(authzEndpoint, clientId, redirectUri, state, 
                    codeChallenge, context);

            if (authorizationUrl == null) {
                LOG.error("Failed to build authorization URL");
                context.put(OAuth2DebugConstants.STEP_CONNECTION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                context.put(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                context.put(OAuth2DebugConstants.STEP_CLAIM_MAPPING_STATUS, OAuth2DebugConstants.STATUS_FAILED);
                throw new ExecutionException("Failed to build authorization URL");
            }

            // Store authorization URL in context.
            context.put(OAuth2DebugConstants.DEBUG_EXTERNAL_REDIRECT_URL, authorizationUrl);
            context.put("isDebugFlow", "true");
            context.put("DEBUG_AUTH_URL_GENERATED", "true");
            context.put("DEBUG_AUTH_URL_TIMESTAMP", System.currentTimeMillis());
            context.put("DEBUG_STEP_AUTH_URL_GENERATED", true);
            context.put("DEBUG_STEP_AUTH_URL", authorizationUrl);

            // Update step status to success.
            context.put(OAuth2DebugConstants.STEP_CONNECTION_STATUS, "success");
            context.put(OAuth2DebugConstants.STEP_AUTHENTICATION_STATUS, "success");
            context.put(OAuth2DebugConstants.STEP_CLAIM_MAPPING_STATUS, "pending");

            // Cache authentication context for framework to retrieve during callback.
            cacheDebugContext(context);

            // Build result with authorization URL.
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
                         ", state=" + state + ", authorizationUrl present: " + 
                         (authorizationUrl != null && !authorizationUrl.isEmpty()));
            }

            LOG.info("OAuth2 Authorization URL generated successfully");
            return result;

        } catch (ExecutionException e) {
            LOG.error("Error generating OAuth2 Authorization URL: " + e.getMessage(), e);
            context.put("step_connection_status", OAuth2DebugConstants.STATUS_FAILED);
            context.put("step_authentication_status", OAuth2DebugConstants.STATUS_FAILED);
            context.put("step_claim_mapping_status", OAuth2DebugConstants.STATUS_FAILED);
            throw e;
        } catch (Exception e) {
            LOG.error("Unexpected error generating OAuth2 Authorization URL: " + e.getMessage(), e);
            context.put("step_connection_status", OAuth2DebugConstants.STATUS_FAILED);
            context.put("step_authentication_status", OAuth2DebugConstants.STATUS_FAILED);
            context.put("step_claim_mapping_status", OAuth2DebugConstants.STATUS_FAILED);
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

        return context != null && context.containsKey(OAuth2DebugConstants.CLIENT_ID) && 
                context.containsKey(OAuth2DebugConstants.AUTHORIZATION_ENDPOINT) && 
                context.containsKey(OAuth2DebugConstants.IDP_SCOPE);
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
            String state, String codeChallenge, Map<String, Object> context) throws ExecutionException {

        try {
            StringBuilder urlBuilder = new StringBuilder();
            urlBuilder.append(authzEndpoint);
            urlBuilder.append("?response_type=code");
            urlBuilder.append("&client_id=").append(encodeParam(clientId));
            urlBuilder.append("&redirect_uri=").append(encodeParam(redirectUri));

            // Get scope from context (set by DebugContextProvider).
            String scope = (String) context.get(OAuth2DebugConstants.IDP_SCOPE);
            if (StringUtils.isEmpty(scope)) {
                throw new ExecutionException("Scope not found in context");
            }
            urlBuilder.append("&scope=").append(encodeParam(scope));
            urlBuilder.append("&state=").append(encodeParam(state));

            // Add PKCE parameters (PKCE is always enabled for debug flow).
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
            Object additionalParamsObj = context.get(OAuth2DebugConstants.ADDITIONAL_OAUTH_PARAMS);
            if (additionalParamsObj instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, String> additionalParams = (Map<String, String>) additionalParamsObj;
                for (Map.Entry<String, String> entry : additionalParams.entrySet()) {
                    if (entry.getKey() != null && entry.getValue() != null) {
                        urlBuilder.append("&").append(entry.getKey()).append("=")
                                .append(encodeParam(entry.getValue()));
                    }
                }
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Generated OAuth2 Authorization URL with PKCE for IdP: " + 
                        context.get(OAuth2DebugConstants.DEBUG_IDP_NAME));
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
        SECURE_RANDOM.nextBytes(randomBytes);
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
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
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
            return URLEncoder.encode(param, StandardCharsets.UTF_8.name());
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
     * Gets the default redirect URI for debug callback.
     * This method allows the redirect URI to be configurable per deployment.
     * Can be overridden or configured via system properties or configuration files.
     *
     * @return The redirect URI for OAuth2 callback.
     */
    private String getDefaultRedirectUri() {

        // Allow override via system property for different deployments
        String customUri = System.getProperty("debug.oauth2.redirect.uri");
        if (customUri != null && !customUri.trim().isEmpty()) {
            return customUri;
        }
        // Default fallback for development
        return "https://localhost:9443/commonauth";
    }

    /**
     * Caches the debug context using HttpSession.
     * Ensures the context can be retrieved during OAuth2 callback processing.
     * Uses a static session map as fallback if HttpSession is not available.
     * NOTE: Sensitive data (tokens, secrets) are NOT logged.
     *
     * @param context Debug context to cache.
     */
    private void cacheDebugContext(Map<String, Object> context) {
        try {
            // Get the state parameter which will be used as cache key
            String state = (String) context.get(OAuth2DebugConstants.DEBUG_STATE);
            if (state == null) {
                LOG.warn("Cannot cache debug context - state parameter is null");
                return;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Caching debug context with state: " + state + 
                         ", TOKEN_ENDPOINT=" + (context.get(OAuth2DebugConstants.TOKEN_ENDPOINT) != null ? "FOUND" : "null") +
                         ", CLIENT_ID=" + (context.get(OAuth2DebugConstants.CLIENT_ID) != null ? "FOUND" : "null"));
                // NOTE: We do NOT log the actual values of CLIENT_SECRET, ACCESS_TOKEN, ID_TOKEN, etc.
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
     * Thread-safe with ConcurrentHashMap and ScheduledExecutorService.
     */
    public static class DebugSessionCache {
        
        private static final DebugSessionCache INSTANCE = new DebugSessionCache();
        private final Map<String, Map<String, Object>> cache = new java.util.concurrent.ConcurrentHashMap<>();
        private static final int CACHE_TIMEOUT_MINUTES = 60;

        public static DebugSessionCache getInstance() {
            return INSTANCE;
        }

        public void put(String key, Map<String, Object> value) {
            if (key == null || value == null) {
                return;
            }
            cache.put(key, value);
            // Schedule removal after timeout using fine-grained scheduling
            scheduleRemoval(key);
        }

        public Map<String, Object> get(String key) {
            if (key == null) {
                return new java.util.HashMap<>();
            }
            // Atomic get - no race condition here since ConcurrentHashMap is atomic
            return cache.get(key);
        }

        public Map<String, Object> remove(String key) {
            if (key == null) {
                return new java.util.HashMap<>();
            }
            // Atomic remove operation
            return cache.remove(key);
        }

        private void scheduleRemoval(String key) {
            
            try {
                // Use ScheduledExecutorService for better resource management
                // Lazy initialization via static holder class is thread-safe
                java.util.concurrent.ScheduledExecutorService executor = ExecutorHolder.EXECUTOR;
                
                // Schedule removal as a single task
                executor.schedule(() -> cache.remove(key), 
                        CACHE_TIMEOUT_MINUTES, java.util.concurrent.TimeUnit.MINUTES);
            } catch (Exception e) {
                // Log but don't fail - cache will be cleaned up by maintain() scheduler
                LOG.debug("Error scheduling cache entry removal: " + e.getMessage());
            }
        }
        
        /**
         * Static holder for ExecutorService to enable lazy initialization
         * without double-checked locking (which is unsafe with non-volatile fields).
         */
        private static class ExecutorHolder {

            static final java.util.concurrent.ScheduledExecutorService EXECUTOR = 
                java.util.concurrent.Executors.newScheduledThreadPool(1, r -> {
                    Thread t = new Thread(r);
                    t.setName("DebugSessionCache-Cleanup");
                    t.setDaemon(true);
                    return t;
                });
        }        /**
         * Shuts down the cleanup executor gracefully.
         * Called during module unload to free resources.
         */
        public static void shutdown() {
            
            try {
                if (!ExecutorHolder.EXECUTOR.isShutdown()) {
                    ExecutorHolder.EXECUTOR.shutdownNow();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("DebugSessionCache cleanup executor shut down");
                    }
                }
            } catch (Exception e) {
                LOG.warn("Error shutting down DebugSessionCache cleanup executor: " + e.getMessage());
            }
        }
    }
}
