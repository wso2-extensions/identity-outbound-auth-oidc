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

package org.wso2.carbon.identity.application.authenticator.oidc.logout.idpinit.factory;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;

import java.io.BufferedReader;
import java.io.StringReader;
import java.nio.file.Paths;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Unit test class for LogoutRequestFactory.
 */
@PrepareForTest({PrivilegedCarbonContext.class})
@PowerMockIgnore("jdk.internal.reflect.*")
public class LogoutRequestFactoryTest extends PowerMockTestCase {

    @Mock
    HttpServletRequest mockHttpServletRequest;

    @Mock
    HttpServletResponse mockHttpServletResponse;
    
    LogoutRequestFactory logoutRequestFactory;

    private static final String CARBON_HOME =
            Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();

    @BeforeTest
    public void init() {

        System.setProperty(CarbonBaseConstants.CARBON_HOME, CARBON_HOME);
        logoutRequestFactory = new LogoutRequestFactory();
    }

    @DataProvider(name = "canHandleDataProvider")
    public Object[][] getHttpServletRequestURI() {

        return new String[][]{{"http://localhost:9443/identity/oidc/slo", "true"}, {"http://localhost:9443/identity" +
                "/oidc/bclogout", "fasle"}};
    }

    @Test(dataProvider = "canHandleDataProvider")
    public void testCanHandle(String uri, String expectedCanHandle) {

        when(mockHttpServletRequest.getRequestURI()).thenReturn(uri);
        assertEquals(logoutRequestFactory.canHandle(mockHttpServletRequest, mockHttpServletResponse),
                Boolean.parseBoolean(expectedCanHandle));

    }

    @Test
    public void testCreate() throws Exception {

        mockStatic(PrivilegedCarbonContext.class);
        PrivilegedCarbonContext privilegedCarbonContext = Mockito.mock(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(privilegedCarbonContext);
        when(privilegedCarbonContext.getTenantDomain()).thenReturn("carbon.super");

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        String requestReader = "";
        when(mockRequest.getReader()).thenReturn(new BufferedReader(new StringReader(requestReader)));
        when(mockRequest.getHeaderNames()).thenReturn(Collections.<String>emptyEnumeration());
        when(mockRequest.getAttributeNames()).thenReturn(Collections.<String>emptyEnumeration());
        assertNotNull(logoutRequestFactory.create(mockRequest, mockResponse).build());
    }
}
