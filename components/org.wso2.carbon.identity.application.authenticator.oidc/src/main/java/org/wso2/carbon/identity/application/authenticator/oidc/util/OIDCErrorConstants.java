/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.util;

/**
 * This class holds the constants related with oidc authenticator.
 */
public class OIDCErrorConstants {

    /**
     * Relevant error messages and error codes.
     */
    public enum ErrorMessages {

        ACCESS_TOKEN_EMPTY_OR_NULL("OID-60001",
                "Access token is empty or null"),
        ID_TOKEN_MISSED_IN_OIDC_RESPONSE("OID-60002",
                "Id token is required and is missing in OIDC response from token endpoint: %s for clientId: %s"),
        DECODED_JSON_OBJECT_IS_NULL("OID-60003",
                "Decoded json object is null"),
        AUTHENTICATION_PROCESS_FAILED("OID-60004",
                "Authentication process failed"),
        USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP("OID-60005",
                "Cannot find the userId from the id_token sent by the federated IDP."),
        // Federated IdP initiated back-channel logout client errors.
        LOGOUT_TOKEN_EMPTY_OR_NULL("OID-60006",
                "Logout token is empty or null. Pass a valid logout token."),
        LOGOUT_TOKEN_PARSING_FAILURE("OID-60007",
                "Invalid logout token."),
        LOGOUT_TOKEN_IAT_VALIDATION_FAILED("OID-60008",
                "Logout token is used after iat validity time."),
        LOGOUT_TOKEN_SIGNATURE_VALIDATION_FAILED("OID-60009",
                "Error while validating the logout token signature."),
        LOGOUT_TOKEN_AUD_CLAIM_VALIDATION_FAILED("OID-60010",
                "Error while validating the aud claim in the logout token."),
        LOGOUT_TOKEN_EVENT_CLAIM_VALIDATION_FAILED("OID-60011",
                "Error while validating the event claim in the logout token."),
        LOGOUT_TOKEN_NONCE_CLAIM_VALIDATION_FAILED("OID-60012",
                "Error while validating the nonce claim in the logout token."),
        LOGOUT_TOKEN_SUB_CLAIM_VALIDATION_FAILED("OID-60013",
                "Error while validating the sub claim in the logout token."),
        LOGOUT_CLIENT_EXCEPTION("OID-60014", "Back channel logout failed due to client error."),

        RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED("OID-65001",
                "Error while retrieving properties. Authenticator Properties cannot be null"),
        IO_ERROR("OID-65002", "I/O Error"),
        BUILDING_AUTHORIZATION_CODE_REQUEST_FAILED("OID-65003",
                "Exception while building authorization code request"),
        RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED("OID-65004",
                "Error while retrieving multi attribute separator"),
        BUILDING_ACCESS_TOKEN_REQUEST_FAILED("OID-65005",
                "Error while building access token request for token endpoint: %s"),
        REQUESTING_ACCESS_TOKEN_FAILED("OID-65006",
                "Exception while requesting access token"),
        EXECUTING_CLAIM_TRANSFORMATION_FOR_IDP_FAILED("OID-65007",
                "Error while executing claim transformation for IDP: %s"),
        // Federated IdP initiated back-channel logout server errors.
        FEDERATED_SESSION_TERMINATION_FAILED("OID-65008",
                "Unable to terminate session for session Id: %s"),
        RETRIEVING_SESSION_ID_MAPPING_FAILED("OID-65009",
                "Error while retrieving session Id mapping for sid: %s"),
        RETRIEVING_IDENTITY_PROVIDER_FAILED("OID-65010",
                "Error while retrieving the identity provider"),
        NO_REGISTERED_IDP_FOR_ISSUER("OID-65011",
                "No Registered IDP found for the issuer name: %s found in JWT"),
        GETTING_RESIDENT_IDP_FAILED("OID-65012",
                "Error while getting Resident Identity Provider of '%s' tenant."),
        USER_SESSION_TERMINATION_FAILURE("OID-65013",
                "Error while terminating the sessions for the user: %s"),
        RETRIEVING_USER_ID_FAILED("OID-65014",
                "Error while retrieving user Id mapping for sub: %s"),
        LOGOUT_SERVER_EXCEPTION("OID-65015", "Back channel logout failed due to server error.");

        private final String code;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {

            return code;
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return String.format("%s  - %s", code, message);
        }
    }
}
