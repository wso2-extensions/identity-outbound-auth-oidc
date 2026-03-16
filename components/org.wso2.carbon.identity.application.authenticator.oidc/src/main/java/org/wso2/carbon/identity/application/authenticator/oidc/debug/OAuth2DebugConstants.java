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

import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;

/**
 * OAuth2/OIDC debug extension constants.
 * 
 * This class contains protocol-specific constants for OAuth2 debug operations.
 * For generic debug framework constants, use {@link DebugFrameworkConstants}.
 * 
 * Constants are organized into categories:
 * OAuth2 Configuration Parameters (endpoints, client credentials)
 * OAuth2 Flow Parameters (PKCE, state, nonce)
 * OAuth2 Response Parameters (tokens, userinfo)
 * OAuth2 Error Codes
 * Debug Flow Steps
 * Debug Context Keys
 * 
 * @see DebugFrameworkConstants for generic debug constants
 */
public final class OAuth2DebugConstants {

    private OAuth2DebugConstants() {
        // Prevent instantiation
    }

    // OAuth2 Debug Extension Identifiers

    /** Extension identifier for OAuth2 debug. */
    public static final String OAUTH2_DEBUG_EXTENSION = "oauth2.debug.extension";

    /** Context identifier for OAuth2 debug. */
    public static final String OAUTH2_DEBUG_CONTEXT = "oauth2.debug.context";

    /** Executor identifier for OAuth2 debug. */
    public static final String OAUTH2_DEBUG_EXECUTOR = "oauth2.debug.executor";

    // OAuth2 Configuration Parameters
    public static final String CLIENT_ID = "clientId";
    public static final String CLIENT_SECRET = "clientSecret";
    public static final String AUTHORIZATION_ENDPOINT = "authorizationEndpoint";
    public static final String TOKEN_ENDPOINT = "tokenEndpoint";
    public static final String USERINFO_ENDPOINT = "userinfoEndpoint";
    public static final String REDIRECT_URI = "redirectUri";
    public static final String SCOPES = "scopes";
    public static final String IDP_SCOPE = "idpScope";
    public static final String RESPONSE_TYPE = "responseType";
    public static final String OPENID_CONNECT_AUTHENTICATOR = "OpenIDConnectAuthenticator";
    public static final String OAUTH2_OPENID_CONNECT_AUTHENTICATOR = "OAuth2OpenIDConnectAuthenticator";
    public static final String IDP_CONFIG = "idpConfig";
    public static final String DEBUG_IDP_NAME = "debugIdpName";

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
    public static final String ERROR_CODE_INVALID_REQUEST = "INVALID_REQUEST";

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
    public static final String STEP_CONNECTION_STATUS = "connectionStatus";
    public static final String STEP_AUTHENTICATION_STATUS = "authenticationStatus";
    public static final String STEP_CLAIM_MAPPING_STATUS = "claimMappingStatus";
    public static final String STEP_CLAIM_EXTRACTION_STATUS = "claimExtractionStatus";

    // Status Values
    public static final String STATUS_STARTED = "started";
    public static final String STATUS_SUCCESS = "success";
    public static final String STATUS_FAILED = "failed";
    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_PRESENT = "present";
    public static final String STATUS_ABSENT = "absent";
    public static final String STATUS_FOUND = "found";

    // Debug Session Keys
    public static final String DEBUG_SESSION_ID = "debugSessionId";
    public static final String DEBUG_FLOW_ID = "debugFlowId";
    public static final String DEBUG_TIMESTAMP = "debugTimestamp";
    public static final String DEBUG_TENANT_DOMAIN = "debugTenantDomain";
    public static final String DEBUG_REQUEST_TYPE = "debugRequestType";
    public static final String DEBUG_AUTHENTICATOR_NAME = "debugAuthenticatorName";
    public static final String DEBUG_EXECUTOR_CLASS = "debugExecutorClass";
    public static final String IS_DEBUG_FLOW = "isDebugFlow";
    public static final String ADDITIONAL_OAUTH_PARAMS = "additionalOAuthParams";

    // Auth Status - References to framework-level constants.
    // Use DebugFrameworkConstants directly where possible.

    /** Auth error indicator. Delegates to DebugFrameworkConstants. */
    public static final String DEBUG_AUTH_ERROR = DebugFrameworkConstants.DEBUG_AUTH_ERROR;

    /** Auth success indicator. Delegates to DebugFrameworkConstants. */
    public static final String DEBUG_AUTH_SUCCESS = DebugFrameworkConstants.DEBUG_AUTH_SUCCESS;

    // Debug Context Property Keys
    public static final String DEBUG_STATE = "DEBUG_STATE";
    public static final String DEBUG_ID_TOKEN = "DEBUG_ID_TOKEN";
    public static final String DEBUG_ACCESS_TOKEN = "DEBUG_ACCESS_TOKEN";
    public static final String DEBUG_USERINFO_CALLED = "DEBUG_USERINFO_CALLED";
    public static final String DEBUG_USERINFO_ERROR = "DEBUG_USERINFO_ERROR";
    public static final String DEBUG_INCOMING_CLAIMS = "DEBUG_INCOMING_CLAIMS";
    public static final String DEBUG_USERINFO_ENDPOINT = "DEBUG_USERINFO_ENDPOINT";
    public static final String DEBUG_PROCESSED_CODE_PREFIX = "DEBUG_PROCESSED_CODE_";
    public static final String DEBUG_CONTEXT_ID = "DEBUG_CONTEXT_ID";
    public static final String DEBUG_CODE_VERIFIER = "DEBUG_CODE_VERIFIER";
    public static final String DEBUG_EXTERNAL_REDIRECT_URL = "DEBUG_EXTERNAL_REDIRECT_URL";
    public static final String DEBUG_CUSTOM_ACCESS_TYPE = "DEBUG_CUSTOM_access_type";
    public static final String DEBUG_USERNAME = "DEBUG_USERNAME";

    // Claim Mapping Keys
    public static final String CLAIM_MAPPING_REMOTE = "remote";
    public static final String CLAIM_MAPPING_LOCAL = "local";
    public static final String CLAIM_MAPPING_IDP_CLAIM = "idpClaim";
    public static final String CLAIM_MAPPING_LOCAL_CLAIM = "isClaim";
    public static final String CLAIM_MAPPING_VALUE = "value";
    public static final String CLAIM_MAPPING_STATUS = "status";

    // Debug Result Keys
    public static final String DEBUG_RESULT_SUCCESS = "success";
    public static final String DEBUG_RESULT_IDPNAME = "idpName";
    public static final String DEBUG_RESULT_SESSIONID = "sessionId";

    // JSON/Response Property Keys
    public static final String RESPONSE_SUCCESS = "success";

    // Protocol Type Identifier
    public static final String PROTOCOL_TYPE = "OAuth2/OIDC";
}
