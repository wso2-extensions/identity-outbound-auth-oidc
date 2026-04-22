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

package org.wso2.carbon.identity.application.authenticator.oidc.debug;

import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;

/**
 * OIDC debug extension constants.
 * 
 * This class contains protocol-specific constants for OIDC debug operations.
 * Constants are organized into categories:
 * OIDC Configuration Parameters (endpoints, client credentials)
 * OIDC Flow Parameters (PKCE, state, nonce)
 * OIDC Response Parameters (tokens, userinfo)
 * OIDC Error Codes
 * Debug Flow Steps
 * Debug Context Keys
 * 
 */
public final class OIDCDebugConstants {

    private OIDCDebugConstants() {
        // Prevent instantiation
    }

    // Debug Component Names
    public static final String EXECUTOR_NAME = "OIDCExecutor";
    public static final String DEBUG_EXECUTOR_NAME = "OIDCDebugExecutor";
    public static final String DEBUG_RESULT_CACHE_KEY = "DEBUG_RESULT_CACHE";

    // OIDC Configuration Parameters
    public static final String CLIENT_ID = "clientId";
    public static final String CLIENT_SECRET = "clientSecret";
    public static final String AUTHORIZATION_ENDPOINT = "authorizationEndpoint";
    public static final String TOKEN_ENDPOINT = "tokenEndpoint";
    public static final String REDIRECT_URI = "redirectUri";
    public static final String IDP_SCOPE = "idpScope";
    public static final String RESPONSE_TYPE = "responseType";
    public static final String IDP_CONFIG = "idpConfig";
    public static final String DEBUG_IDP_NAME = "debugIdpName";

    // OIDC Response Parameters
    public static final String ACCESS_TOKEN = "accessToken";
    public static final String TOKEN_TYPE = "tokenType";
    public static final String EXPIRES_IN = "expiresIn";
    public static final String REFRESH_TOKEN = "refreshToken";
    public static final String ID_TOKEN = "idToken";

    // OIDC Error Codes
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

    // Debug Flow Steps
    public static final String STEP_STATUS = "stepStatus";
    public static final String STEP_CONNECTION_STATUS = "connectionCreation";
    public static final String STEP_AUTHENTICATION_STATUS = "authenticationStatus";
    public static final String STEP_CLAIM_MAPPING_STATUS = "claimMappingStatus";
    public static final String STEP_CLAIM_EXTRACTION_STATUS = "claimExtractionStatus";
    public static final String STEP_ACCOUNT_LINKING_STATUS = "accountLinkingStatus";
    public static final String DEBUG_DIAGNOSTICS = DebugFrameworkConstants.DEBUG_DIAGNOSTICS;

    // Diagnostic Stages
    public static final String STAGE_AUTHORIZATION_REQUEST = "authorizationRequest";
    public static final String STAGE_CALLBACK_VALIDATION = "callbackValidation";
    public static final String STAGE_TOKEN_EXCHANGE = "tokenExchange";
    public static final String STAGE_CLAIM_EXTRACTION = "claimExtraction";
    public static final String STAGE_CLAIM_VALIDATION = "claimValidation";
    public static final String STAGE_CLAIM_MAPPING = "claimMapping";
    public static final String STAGE_ACCOUNT_LINKING = "accountLinking";

    // Status Values
    public static final String STATUS_STARTED = "started";
    public static final String STATUS_SUCCESS = "success";
    public static final String STATUS_PARTIAL = "partial";
    public static final String STATUS_FAILED = "failed";
    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_PRESENT = "present";
    public static final String STATUS_ABSENT = "absent";
    public static final String STATUS_FOUND = "found";

    // Debug Session Keys
    public static final String DEBUG_ID = "debugId";
    public static final String DEBUG_FLOW_ID = "debugFlowId";
    public static final String DEBUG_TIMESTAMP = "debugTimestamp";
    public static final String DEBUG_TENANT_DOMAIN = "debugTenantDomain";
    public static final String DEBUG_REQUEST_TYPE = "debugRequestType";
    public static final String DEBUG_AUTHENTICATOR_NAME = "debugAuthenticatorName";
    public static final String DEBUG_EXECUTOR_CLASS = "debugExecutorClass";
    public static final String IS_DEBUG_FLOW = "isDebugFlow";
    public static final String ADDITIONAL_OIDC_PARAMS = "additionalOIDCParams";

    // Auth status keys shared with the debug framework.
    public static final String DEBUG_AUTH_ERROR = "AUTH_ERROR";
    public static final String DEBUG_AUTH_SUCCESS = "AUTH_SUCCESS";

    // Debug Context Property Keys
    public static final String DEBUG_STATE = "DEBUG_STATE";
    public static final String DEBUG_ID_TOKEN = "DEBUG_ID_TOKEN";
    public static final String DEBUG_ACCESS_TOKEN = "DEBUG_ACCESS_TOKEN";
    public static final String DEBUG_INCOMING_CLAIMS = "DEBUG_INCOMING_CLAIMS";
    public static final String DEBUG_CONTEXT_ID = DEBUG_ID;
    public static final String DEBUG_CODE_VERIFIER = "DEBUG_CODE_VERIFIER";
    public static final String DEBUG_NONCE = "DEBUG_NONCE";
    public static final String DEBUG_EXTERNAL_REDIRECT_URL = "DEBUG_EXTERNAL_REDIRECT_URL";
    public static final String DEBUG_CUSTOM_ACCESS_TYPE = "DEBUG_CUSTOM_access_type";
    public static final String DEBUG_USERNAME = "DEBUG_USERNAME";
    public static final String DEBUG_IDP_RESOURCE_ID = "debugIdpResourceId";
    public static final String DEBUG_IDP_DESCRIPTION = "debugIdpDescription";
    public static final String CONTEXT_PROTOCOL = "protocol";
    public static final String CONTEXT_KEY_CONNECTION_ID = "connectionId";
    public static final String CONTEXT_KEY_RESOURCE_NAME = "resourceName";
    public static final String REQUEST_KEY_CONNECTION_ID = "connectionId";
    public static final String REQUEST_KEY_IDP_NAME = "idpName";

    // Claim Mapping Keys
    public static final String CLAIM_MAPPING_REMOTE = "remote";
    public static final String CLAIM_MAPPING_LOCAL = "local";
    public static final String CLAIM_MAPPING_IDP_CLAIM = "idpClaim";
    public static final String CLAIM_MAPPING_LOCAL_CLAIM = "localClaim";
    public static final String CLAIM_MAPPING_VALUE = "value";
    public static final String CLAIM_MAPPING_STATUS = "status";

    // Debug Result Keys
    public static final String DEBUG_RESULT_SUCCESS = "success";
    public static final String DEBUG_RESULT_IDPNAME = "idpName";
    public static final String DEBUG_RESULT_DEBUGID = "debugId";
    public static final String DEBUG_RESULT_ID_TOKEN_PRESENT = "idTokenPresent";
    public static final String CONTEXT_ACCOUNT_LINKING_STATUS = "accountLinkingStatus";
    public static final String CONTEXT_ACCOUNT_LINKING_MESSAGE = "CONTEXT_ACCOUNT_LINKING_MESSAGE";
    public static final String ACCOUNT_LINKING_REASON = "reason";

    // JSON/Response Property Keys
    public static final String RESPONSE_SUCCESS = "success";

    // Protocol Type Identifier
    public static final String PROTOCOL_TYPE = DebugFrameworkConstants.PROTOCOL_TYPE_OIDC;
}
