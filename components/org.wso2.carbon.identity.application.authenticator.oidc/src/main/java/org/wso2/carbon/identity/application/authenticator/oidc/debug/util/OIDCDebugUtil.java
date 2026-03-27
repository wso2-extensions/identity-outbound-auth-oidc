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

package org.wso2.carbon.identity.application.authenticator.oidc.debug.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class for OAuth2 debug operations.
 * Provides utilities for PKCE, URL building, parameter extraction, and state
 * management.
 */
public class OIDCDebugUtil {

    private static final Log LOG = LogFactory.getLog(OIDCDebugUtil.class);
    private static final String SHA256 = "SHA-256";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private OIDCDebugUtil() {

        // Prevent instantiation
    }

    /**
     * Generate PKCE code verifier.
     *
     * @return PKCE code verifier string (43-128 characters).
     */
    public static String generatePKCECodeVerifier() {

        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Generate PKCE code challenge from verifier using S256 method.
     *
     * @param codeVerifier The PKCE code verifier.
     * @return PKCE code challenge (base64url encoded).
     */
    public static String generatePKCECodeChallenge(String codeVerifier) {

        if (StringUtils.isEmpty(codeVerifier)) {
            return null;
        }

        try {
            MessageDigest messageDigest = MessageDigest.getInstance(SHA256);
            byte[] hash = messageDigest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Error generating PKCE code challenge: SHA-256 algorithm not available.", e);
            throw new IllegalStateException("SHA-256 algorithm not available for PKCE code challenge generation", e);
        }
    }
}
