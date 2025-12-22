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
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
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

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Unit test class for LogoutRequestFactory.
 */
public class LogoutRequestFactoryTest {

    private AutoCloseable openMocks;

    @Mock
    HttpServletRequest mockHttpServletRequest;

    @Mock
    HttpServletResponse mockHttpServletResponse;

    LogoutRequestFactory logoutRequestFactory;

    private static final String CARBON_HOME =
            Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "repository").toString();

    @BeforeMethod
    public void setUp() {
        openMocks = MockitoAnnotations.openMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (openMocks != null) {
            openMocks.close();
        }
    }

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

        Mockito.when(mockHttpServletRequest.getRequestURI()).thenReturn(uri);
        assertEquals(logoutRequestFactory.canHandle(mockHttpServletRequest, mockHttpServletResponse),
                Boolean.parseBoolean(expectedCanHandle));

    }

    @Test
    public void testCreate() throws Exception {

        try (MockedStatic<PrivilegedCarbonContext> pccStatic = Mockito.mockStatic(PrivilegedCarbonContext.class)) {
            PrivilegedCarbonContext privilegedCarbonContext = Mockito.mock(PrivilegedCarbonContext.class);
            pccStatic.when(PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(privilegedCarbonContext);
            Mockito.when(privilegedCarbonContext.getTenantDomain()).thenReturn("carbon.super");

            HttpServletRequest mockRequest = mock(HttpServletRequest.class);
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);
            String requestReader = "";
            Mockito.when(mockRequest.getReader()).thenReturn(new BufferedReader(new StringReader(requestReader)));
            Mockito.when(mockRequest.getHeaderNames()).thenReturn(Collections.<String>emptyEnumeration());
            Mockito.when(mockRequest.getAttributeNames()).thenReturn(Collections.<String>emptyEnumeration());
            assertNotNull(logoutRequestFactory.create(mockRequest, mockResponse).build());
        }
    }
}
