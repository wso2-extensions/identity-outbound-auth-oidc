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

package org.wso2.carbon.identity.application.authenticator.oidc.model;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;


public class LogoutResponse extends IdentityResponse {

    protected LogoutResponse(
            LogoutResponseBuilder builder) {

        super(builder);
    }

    /**
     * OIDC logout response builder.
     */
    public static class LogoutResponseBuilder extends IdentityResponseBuilder {

        public LogoutResponseBuilder(
                IdentityMessageContext context) {

            super(context);
        }

        public LogoutResponseBuilder() {

        }

        @Override
        public LogoutResponse build() {

            return new LogoutResponse(this);
        }
    }
}
