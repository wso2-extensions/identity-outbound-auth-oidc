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

import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkException;

/**
 * Exception thrown during OIDC debug operations.
 * Extends the framework's base exception to integrate with the exception
 * hierarchy.
 */
public class OIDCDebugException extends DebugFrameworkException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs an OIDCDebugException with a message.
     *
     * @param message The error message.
     */
    public OIDCDebugException(String message) {

        super(message);
    }

    /**
     * Constructs an OIDCDebugException with a message and cause.
     *
     * @param message The error message.
     * @param cause The cause of the exception.
     */
    public OIDCDebugException(String message, Throwable cause) {

        super(message, cause);
    }

    /**
     * Constructs an OIDCDebugException with error code, message, and cause.
     *
     * @param errorCode The error code.
     * @param message The error message.
     * @param cause The cause of the exception.
     */
    public OIDCDebugException(String errorCode, String message, Throwable cause) {

        super(errorCode, message, message, cause);
    }
}
