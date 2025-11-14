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
 * Exception thrown during OAuth2 debug operations.
 * This exception extends the pattern of the generic debug framework exceptions.
 */
public class OAuth2DebugException extends Exception {

    private static final long serialVersionUID = 1L;

    private String errorCode;

    /**
     * Constructs an OAuth2DebugException with a message.
     *
     * @param message The error message.
     */
    public OAuth2DebugException(String message) {
        super(message);
    }

    /**
     * Constructs an OAuth2DebugException with a message and cause.
     *
     * @param message The error message.
     * @param cause The cause of the exception.
     */
    public OAuth2DebugException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs an OAuth2DebugException with error code, message, and cause.
     *
     * @param errorCode The error code.
     * @param message The error message.
     * @param cause The cause of the exception.
     */
    public OAuth2DebugException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * Get the error code.
     *
     * @return The error code.
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Set the error code.
     *
     * @param errorCode The error code to set.
     */
    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }
}
