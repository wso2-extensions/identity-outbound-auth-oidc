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

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class holds the necessary parameters of the HTTPServletRequest.
 * LogoutRequestBuilder is an inner class of this class and it is responsible
 * for building a concrete instance of OIDC LogoutRequest for the framework when needed.
 */
public class LogoutRequest extends IdentityRequest {

    protected LogoutRequest(
            IdentityRequestBuilder builder) throws FrameworkClientException {

        super(builder);
    }

    /**
     * OIDC logout request builder.
     */
    public static class LogoutRequestBuilder extends IdentityRequestBuilder {

        public LogoutRequestBuilder(HttpServletRequest request,
                                    HttpServletResponse response) {

            super(request, response);
        }

        @Override
        public LogoutRequest build() throws FrameworkRuntimeException, FrameworkClientException {

            return new LogoutRequest(this);
        }
    }
}
