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
 * Constants for the OIDC debug extension.
 */
public final class OIDCDebugConstants {

    private OIDCDebugConstants() {
    }

    // Protocol type identifier.
    public static final String PROTOCOL_TYPE = "OIDC";

    // Debug component names.
    public static final String DEBUG_EXECUTOR_NAME = "OIDCDebugExecutor";
    public static final String DEBUG_RESULT_CACHE_KEY = "DEBUG_RESULT_CACHE";

    // OIDC configuration parameters.
    public static final String CLIENT_ID = "clientId";
    public static final String CLIENT_SECRET = "clientSecret";
    public static final String AUTHORIZATION_ENDPOINT = "authorizationEndpoint";
    public static final String TOKEN_ENDPOINT = "tokenEndpoint";
    public static final String REDIRECT_URI = "redirectUri";
    public static final String IDP_SCOPE = "idpScope";
    public static final String IDP_CONFIG = "idpConfig";
    public static final String DEBUG_IDP_NAME = "debugIdpName";

    // OIDC callback parameters.
    public static final String OIDC_CODE_PARAM = "code";
    public static final String OIDC_STATE_PARAM = "state";
    public static final String OIDC_ERROR_PARAM = "error";
    public static final String OIDC_ERROR_DESCRIPTION_PARAM = "error_description";

    // OIDC response token fields.
    public static final String ACCESS_TOKEN = "accessToken";
    public static final String TOKEN_TYPE = "tokenType";
    public static final String ID_TOKEN = "idToken";

    // OIDC PKCE parameters.
    public static final String PKCE_METHOD_S256 = "S256";
    public static final String SHA256_ALGORITHM = "SHA-256";

    // Error codes.
    public static final String ERROR_CODE_INVALID_REQUEST = "INVALID_REQUEST";

    public static final String DEBUG_DIAGNOSTICS = DebugFrameworkConstants.DEBUG_DIAGNOSTICS;

    // Diagnostic stage identifiers.
    public static final String STAGE_AUTHORIZATION_REQUEST = "authorizationRequest";
    public static final String STAGE_TOKEN_EXCHANGE = "tokenExchange";
    public static final String STAGE_CLAIM_EXTRACTION = "claimExtraction";
    public static final String STAGE_CLAIM_MAPPING = "claimMapping";
    public static final String STAGE_ACCOUNT_LINKING = "accountLinking";

    // Step status values.
    public static final String STATUS_STARTED = "started";
    public static final String STATUS_SUCCESS = "success";
    public static final String STATUS_PARTIAL = "partial";
    public static final String STATUS_FAILED = "failed";
    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_PRESENT = "present";
    public static final String STATUS_ABSENT = "absent";
    public static final String STATUS_FOUND = "found";

    // Debug context/session property keys.
    public static final String DEBUG_ID = "debugId";
    public static final String CONTEXT_PROTOCOL = "protocol";

    // Debug runtime state keys.
    public static final String DEBUG_AUTH_ERROR = "authError";
    public static final String DEBUG_AUTH_SUCCESS = "authSuccess";
    public static final String DEBUG_INCOMING_CLAIMS = "DEBUG_INCOMING_CLAIMS";
    public static final String DEBUG_CODE_VERIFIER = "DEBUG_CODE_VERIFIER";
    public static final String DEBUG_NONCE = "DEBUG_NONCE";
    public static final String DEBUG_EXTERNAL_REDIRECT_URL = "DEBUG_EXTERNAL_REDIRECT_URL";
    public static final String DEBUG_IDP_RESOURCE_ID = "debugIdpResourceId";

    // Claim mapping field keys.
    public static final String CLAIM_MAPPING_REMOTE = "remote";
    public static final String CLAIM_MAPPING_LOCAL = "local";
    public static final String CLAIM_MAPPING_IDP_CLAIM = "idpClaim";
    public static final String CLAIM_MAPPING_LOCAL_CLAIM = "localClaim";
    public static final String CLAIM_MAPPING_VALUE = "value";
    public static final String CLAIM_MAPPING_STATUS = "status";

    // Debug result keys.
    public static final String DEBUG_RESULT_SUCCESS = "success";
    public static final String DEBUG_SUCCESS_PAGE = "/authenticationendpoint/debugSuccess.jsp";

    // Account linking keys.
    public static final String CONTEXT_ACCOUNT_LINKING_STATUS = "accountLinkingStatus";
    public static final String CONTEXT_ACCOUNT_LINKING_MESSAGE = "CONTEXT_ACCOUNT_LINKING_MESSAGE";
    public static final String ACCOUNT_LINKING_REASON = "reason";

    // Claim status values.
    public static final String CLAIM_STATUS_SUCCESSFUL = "Successful";
    public static final String CLAIM_STATUS_NOT_MAPPED = "Not Mapped";

    // Debug result response keys.
    public static final String RESULT_AUTHORIZATION_URL = "authorizationUrl";
    public static final String RESULT_MAPPED_CLAIMS = "mappedClaims";
    public static final String RESULT_EXTERNAL_REDIRECT_URL = "externalRedirectUrl";
    public static final String RESULT_ERROR_CODE = "error_code";

    // Diagnostic detail keys.
    public static final String DIAG_ERROR_CODE = "errorCode";
    public static final String DIAG_ERROR_DESCRIPTION = "errorDescription";

    // OIDC standard claim names.
    public static final String CLAIM_NONCE = "nonce";
    public static final String CLAIM_ADDRESS = "address";
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_SUB = "sub";
    public static final String CLAIM_USER_ID = "user_id";
    public static final String CLAIM_USER_ID_ALT = "userId";

    // Request parameter names.
    public static final String PARAM_IDP_ID = "idpId";
    public static final String PARAM_AUTHENTICATOR = "authenticator";

    // Authenticator property names.
    public static final String PROP_ADDITIONAL_QUERY_PARAMS = "AdditionalQueryParameters";
    public static final String DEFAULT_SCOPE = "openid";

}
