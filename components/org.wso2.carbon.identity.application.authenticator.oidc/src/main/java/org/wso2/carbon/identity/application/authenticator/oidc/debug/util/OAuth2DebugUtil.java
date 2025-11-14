/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.oidc.debug.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for OAuth2 debug operations.
 * Provides utilities for PKCE, URL building, parameter extraction, and state management.
 */
public class OAuth2DebugUtil {

    private static final Log LOG = LogFactory.getLog(OAuth2DebugUtil.class);
    private static final String UTF8 = "UTF-8";
    private static final String SHA256 = "SHA-256";

    private OAuth2DebugUtil() {
    }

    /**
     * Generate PKCE code verifier.
     *
     * @return PKCE code verifier string (43-128 characters).
     */
    public static String generatePKCECodeVerifier() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generating PKCE code verifier.");
        }
        return RandomStringUtils.randomAlphanumeric(128);
    }

    /**
     * Generate PKCE code challenge from verifier using S256 method.
     *
     * @param codeVerifier The PKCE code verifier.
     * @return PKCE code challenge (base64url encoded).
     */
    public static String generatePKCECodeChallenge(String codeVerifier) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generating PKCE code challenge from verifier using S256 method.");
        }

        if (StringUtils.isEmpty(codeVerifier)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Code verifier is empty. Returning null.");
            }
            return null;
        }

        try {
            MessageDigest messageDigest = MessageDigest.getInstance(SHA256);
            byte[] hash = messageDigest.digest(codeVerifier.getBytes(UTF8));
            String challenge = Base64.encodeBase64URLSafeString(hash);
            if (LOG.isDebugEnabled()) {
                LOG.debug("PKCE code challenge generated successfully.");
            }
            return challenge;
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Error generating PKCE code challenge: SHA-256 algorithm not available.", e);
            throw new RuntimeException("SHA-256 algorithm not available for PKCE code challenge generation", e);
        } catch (UnsupportedEncodingException e) {
            LOG.error("Error generating PKCE code challenge: UTF-8 encoding not supported.", e);
            throw new RuntimeException("UTF-8 encoding not supported for PKCE code challenge generation", e);
        }
    }

    /**
     * Generate a random state parameter for OAuth2 flow.
     *
     * @return Random state string.
     */
    public static String generateRandomState() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generating random state parameter.");
        }
        return RandomStringUtils.randomAlphanumeric(32);
    }

    /**
     * Generate a random nonce for OAuth2 flow.
     *
     * @return Random nonce string.
     */
    public static String generateRandomNonce() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generating random nonce.");
        }
        return RandomStringUtils.randomAlphanumeric(32);
    }

    /**
     * Build OAuth2 authorization URL from endpoint and parameters.
     *
     * @param authorizationEndpoint The authorization endpoint URL.
     * @param parameters The OAuth2 parameters map.
     * @return Complete authorization URL.
     */
    public static String buildAuthorizationURL(String authorizationEndpoint, Map<String, String> parameters) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Building authorization URL from endpoint and parameters.");
        }

        if (StringUtils.isEmpty(authorizationEndpoint)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authorization endpoint is empty.");
            }
            return null;
        }

        StringBuilder urlBuilder = new StringBuilder(authorizationEndpoint);
        if (parameters != null && !parameters.isEmpty()) {
            urlBuilder.append("?");
            boolean first = true;
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                if (!first) {
                    urlBuilder.append("&");
                }
                try {
                    String encodedValue = java.net.URLEncoder.encode(entry.getValue(), UTF8);
                    urlBuilder.append(entry.getKey()).append("=").append(encodedValue);
                } catch (UnsupportedEncodingException e) {
                    LOG.warn("Error encoding parameter value: " + entry.getKey(), e);
                    urlBuilder.append(entry.getKey()).append("=").append(entry.getValue());
                }
                first = false;
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authorization URL built successfully.");
        }
        return urlBuilder.toString();
    }

    /**
     * Extract query parameters from URL.
     *
     * @param url The URL to extract parameters from.
     * @return Map of query parameters.
     */
    public static Map<String, String> extractQueryParameters(String url) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Extracting query parameters from URL.");
        }

        Map<String, String> parameters = new HashMap<>();
        if (StringUtils.isEmpty(url)) {
            return parameters;
        }

        int queryIndex = url.indexOf("?");
        if (queryIndex == -1) {
            return parameters;
        }

        String queryString = url.substring(queryIndex + 1);
        String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                try {
                    String key = java.net.URLDecoder.decode(keyValue[0], UTF8);
                    String value = java.net.URLDecoder.decode(keyValue[1], UTF8);
                    parameters.put(key, value);
                } catch (UnsupportedEncodingException e) {
                    LOG.warn("Error decoding query parameter: " + pair, e);
                }
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Query parameters extracted successfully. Count: " + parameters.size());
        }
        return parameters;
    }

    /**
     * Validate state parameter consistency.
     *
     * @param stateFromRequest The state parameter from the request.
     * @param stateFromSession The state parameter stored in session.
     * @return True if states match, false otherwise.
     */
    public static boolean validateStateParameter(String stateFromRequest, String stateFromSession) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Validating state parameter consistency.");
        }

        boolean isValid = StringUtils.equals(stateFromRequest, stateFromSession);
        if (LOG.isDebugEnabled()) {
            LOG.debug("State parameter validation result: " + isValid);
        }
        return isValid;
    }

    /**
     * Check if PKCE is enabled for the OAuth2 flow.
     *
     * @param idpConfig The IdP configuration map.
     * @return True if PKCE is enabled, false otherwise.
     */
    public static boolean isPKCEEnabled(Map<String, Object> idpConfig) {
        if (idpConfig == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("IdP configuration is null. PKCE not enabled.");
            }
            return false;
        }

        Object pkceEnabledObj = idpConfig.get("IsPKCEEnabled");
        boolean isPKCEEnabled = pkceEnabledObj != null && Boolean.parseBoolean(pkceEnabledObj.toString());
        if (LOG.isDebugEnabled()) {
            LOG.debug("PKCE enabled status: " + isPKCEEnabled);
        }
        return isPKCEEnabled;
    }

    /**
     * Create a debug session map with common debug information.
     *
     * @param debugSessionId The debug session ID.
     * @param debugFlowId The debug flow ID.
     * @return Debug session map.
     */
    public static Map<String, Object> createDebugSession(String debugSessionId, String debugFlowId) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating debug session with ID: " + debugSessionId + ", Flow ID: " + debugFlowId);
        }

        Map<String, Object> debugSession = new HashMap<>();
        debugSession.put("debugSessionId", debugSessionId);
        debugSession.put("debugFlowId", debugFlowId);
        debugSession.put("debugTimestamp", System.currentTimeMillis());
        return debugSession;
    }
}
