/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.oidc.model;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

/**
 * Holds the necessary parameters for building the HTTPServletResponse.
 * LogoutResponseBuilder is an inner class of this class and it is responsible
 * or building a concrete instance of OIDC LogoutResponse for the framework when needed.
 */
public class LogoutResponse extends IdentityResponse {

    protected int statusCode;
    protected String message;

    protected LogoutResponse(LogoutResponseBuilder builder) {

        super(builder);
        this.statusCode = builder.statusCode;
        this.message = builder.message;
    }

    /**
     * Retrieve status code.
     *
     * @return
     */
    public int getStatusCode() {

        return this.statusCode;
    }

    /**
     * Retrieve message.
     *
     * @return
     */
    public String getMessage() {

        return message;
    }

    /**
     * OIDC logout response builder.
     */
    public static class LogoutResponseBuilder extends IdentityResponseBuilder {

        protected int statusCode;
        protected String message;

        public LogoutResponseBuilder(int statusCode, String message) {

            this.statusCode = statusCode;
            this.message = message;
        }

        @Override
        public LogoutResponse build() {

            return new LogoutResponse(this);
        }
    }
}
