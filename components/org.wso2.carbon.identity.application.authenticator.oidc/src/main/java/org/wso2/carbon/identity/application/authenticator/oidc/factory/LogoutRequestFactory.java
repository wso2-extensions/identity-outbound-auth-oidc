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

package org.wso2.carbon.identity.application.authenticator.oidc.factory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authenticator.oidc.model.LogoutRequest;

import java.util.regex.Matcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OIDC_BCLOGOUT_ENDPOINT_URL_PATTERN;

/**
 * This class checks whether requests from the Identity servlet are OIDC Logout Requests and
 * provides a builder to an instance of OIDC LogoutRequest.
 */
public class LogoutRequestFactory extends HttpIdentityRequestFactory {

    private static final Log log = LogFactory.getLog(LogoutRequestFactory.class);

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {

        boolean canHandle = false;
        Matcher registerMatcher =
                OIDC_BCLOGOUT_ENDPOINT_URL_PATTERN.matcher(request.getRequestURI());
        if (registerMatcher.matches()) {
            canHandle = true;
        }
        if (log.isDebugEnabled()) {
            log.debug("canHandle " + canHandle + " by OIDC LogoutRequestFactory.");
        }
        return canHandle;
    }

    @Override
    public LogoutRequest.LogoutRequestBuilder create(HttpServletRequest request,
                                                     HttpServletResponse response)
            throws FrameworkClientException {

        if (log.isDebugEnabled()) {
            log.debug("Create LogoutRequest.LogoutRequestBuilder from HttpServletRequest and HttpServletResponse.");
        }
        LogoutRequest.LogoutRequestBuilder logoutRequestBuilder = new LogoutRequest.
                LogoutRequestBuilder(request, response);
        create(logoutRequestBuilder, request, response);
        return logoutRequestBuilder;

    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response) throws FrameworkClientException {

        LogoutRequest.LogoutRequestBuilder registerRequestBuilder;
        if (builder instanceof LogoutRequest.LogoutRequestBuilder) {
            registerRequestBuilder = (LogoutRequest.LogoutRequestBuilder) builder;
            super.create(registerRequestBuilder, request, response);
        }
    }
}
