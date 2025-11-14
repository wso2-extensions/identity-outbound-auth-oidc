/*
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

package org.wso2.carbon.identity.application.authenticator.oidc.debug;

/**
 * OAuth2 debug extension constants.
 * Protocol-specific constants for OAuth2 debug operations using the generic debug framework.
 */
public class OAuth2DebugConstants {

    private OAuth2DebugConstants() {
    }

    // OAuth2 Debug Extension Identifiers
    public static final String OAUTH2_DEBUG_EXTENSION = "oauth2.debug.extension";
    public static final String OAUTH2_DEBUG_CONTEXT = "oauth2.debug.context";
    public static final String OAUTH2_DEBUG_EXECUTOR = "oauth2.debug.executor";

    // OAuth2 Configuration Parameters
    public static final String CLIENT_ID = "clientId";
    public static final String CLIENT_SECRET = "clientSecret";
    public static final String AUTHORIZATION_ENDPOINT = "authorizationEndpoint";
    public static final String TOKEN_ENDPOINT = "tokenEndpoint";
    public static final String USERINFO_ENDPOINT = "userinfoEndpoint";
    public static final String REDIRECT_URI = "redirectUri";
    public static final String SCOPES = "scopes";
    public static final String RESPONSE_TYPE = "responseType";

    // OAuth2 Debug Flow Parameters
    public static final String AUTHORIZATION_CODE = "authorizationCode";
    public static final String STATE = "state";
    public static final String NONCE = "nonce";
    public static final String CODE_VERIFIER = "codeVerifier";
    public static final String CODE_CHALLENGE = "codeChallenge";
    public static final String CODE_CHALLENGE_METHOD = "codeChallengeMethod";

    // OAuth2 Response Parameters
    public static final String ACCESS_TOKEN = "accessToken";
    public static final String TOKEN_TYPE = "tokenType";
    public static final String EXPIRES_IN = "expiresIn";
    public static final String REFRESH_TOKEN = "refreshToken";
    public static final String ID_TOKEN = "idToken";
    public static final String USERINFO = "userinfo";

    // OAuth2 Error Codes
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String INVALID_GRANT = "invalid_grant";
    public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String INVALID_SCOPE = "invalid_scope";
    public static final String SERVER_ERROR = "server_error";
    public static final String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";

    // PKCE Parameters
    public static final String PKCE_ENABLED = "pkceEnabled";
    public static final String PKCE_METHOD = "pkceMethod";
    public static final String PKCE_METHOD_S256 = "S256";
    public static final String PKCE_METHOD_PLAIN = "plain";

    // Debug Flow Steps
    public static final String STEP_RESOLVE_CONFIG = "resolveConfig";
    public static final String STEP_GENERATE_AUTH_URL = "generateAuthUrl";
    public static final String STEP_HANDLE_CALLBACK = "handleCallback";
    public static final String STEP_EXCHANGE_CODE = "exchangeCode";
    public static final String STEP_FETCH_USERINFO = "fetchUserinfo";

    // Debug Session Keys
    public static final String DEBUG_SESSION_ID = "debugSessionId";
    public static final String DEBUG_FLOW_ID = "debugFlowId";
    public static final String DEBUG_TIMESTAMP = "debugTimestamp";
}
