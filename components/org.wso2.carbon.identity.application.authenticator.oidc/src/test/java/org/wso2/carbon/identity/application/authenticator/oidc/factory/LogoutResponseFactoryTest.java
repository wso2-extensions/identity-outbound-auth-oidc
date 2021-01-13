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

import org.mockito.Mock;
import org.powermock.modules.testng.PowerMockTestCase;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authenticator.oidc.LogoutClientException;
import org.wso2.carbon.identity.application.authenticator.oidc.LogoutException;
import org.wso2.carbon.identity.application.authenticator.oidc.LogoutServerException;
import org.wso2.carbon.identity.application.authenticator.oidc.model.LogoutResponse;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.LogoutExceptionError.LOGOUT_CLIENT_EXCEPTION;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.LogoutExceptionError.LOGOUT_SERVER_EXCEPTION;

public class LogoutResponseFactoryTest extends PowerMockTestCase {

    @Mock
    LogoutResponse mockLogoutResponse;

    @Mock
    LogoutException mockLogoutException;

    LogoutResponseFactory logoutResponseFactory;

    @BeforeTest
    public void init() {

        logoutResponseFactory = new LogoutResponseFactory();
    }

    @Test
    public void testCanHandle() {

        assertTrue(logoutResponseFactory.canHandle(mockLogoutResponse));
    }

    @Test
    public void testExceptionCanHandle() {

        assertTrue(logoutResponseFactory.canHandle(mockLogoutException));
    }

    @Test
    public void testCreate() {

        assertNotNull(logoutResponseFactory.create(mockLogoutResponse));
    }

    @Test
    public void testHandleServerException() {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder =
                logoutResponseFactory.handleException(new LogoutServerException("Server Error"));
        assertEquals(builder.build().getBody(), LOGOUT_SERVER_EXCEPTION);
        assertEquals(builder.build().getStatusCode(), 500);
    }

    @Test
    public void testHandleClientException() {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder =
                logoutResponseFactory.handleException(new LogoutClientException("Server Error"));
        assertEquals(builder.build().getBody(), LOGOUT_CLIENT_EXCEPTION);
        assertEquals(builder.build().getStatusCode(), 400);
    }
}
