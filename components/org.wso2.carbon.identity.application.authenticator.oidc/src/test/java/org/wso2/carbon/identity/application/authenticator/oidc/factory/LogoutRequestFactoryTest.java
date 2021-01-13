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

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authenticator.oidc.model.LogoutRequest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Collections;
import java.util.HashMap;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class LogoutRequestFactoryTest extends PowerMockTestCase {

    @Mock
    HttpServletRequest mockHttpServletRequest;

    @Mock
    HttpServletResponse mockHttpServletResponse;

    @Mock
    BufferedReader mockReader;

    @Mock
    private JSONParser jsonParser;

    LogoutRequestFactory logoutRequestFactory;

    @BeforeTest
    public void init() {

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

//        String request =
//                "logout_token=eyJ4NXQiOiJPV0psWmpJME5qSTROR0ZpTVRBNU9UZ3dPR00xTTJJeE5UWmpNekk0TldJeE5EY3dOMkV5TVRNNE5HW" +
//                        "mlaVGxoTXpJMFl6aGpaRFJrWXpoaVl6ZGhPQSIsImtpZCI6Ik9XSmxaakkwTmpJNE5HRmlNVEE1T1Rnd09HTTFNMkl4TlR" +
//                        "aak16STROV0l4TkRjd04yRXlNVE00TkdaaVpUbGhNekkwWXpoalpEUmtZemhpWXpkaE9BX1JTMjU2IiwiYWxnIjoiUlMyN" +
//                        "TYifQ.eyJzdWIiOiJhZG1pbiIsImF1ZCI6IndfSHdwMDVkRlJ3Y1JzX1dGSHY5U053cGZsQWEiLCJpc3MiOiJodHRwczpc" +
//                        "L1wvZmVkZXJhdGVkd3NvMi5jb206OTQ0NFwvb2F1dGgyXC90b2tlbiIsImV4cCI6MTYxMDU0NjEyNCwiaWF0IjoxNjEwNT" +
//                        "Q2MDA0LCJqdGkiOiI3NTdiNjgzNy01N2FkLTRkZWEtYWI1NC05OTFhNjYwYTgwMTIiLCJldmVudHMiOnsiaHR0cDpcL1wv" +
//                        "c2NoZW1hcy5vcGVuaWRuZXRcL2V2ZW50XC9iYWNrY2hhbm5lbC1sb2dvdXQiOnt9fSwic2lkIjoiMDIyMDQ5MTQtODI3OC" +
//                        "00ZTQ4LThjNjUtYTEwZjZiZGRmYTgyIn0.LbUho436GNZrZ8662KnTU_MwUvF0K0Mm2ki8Bd1-g6vx2xQhT14RnWDbn678" +
//                        "0zcKzzRYcZH_oNIkXrKSs0pfeKfkE34sBUqcOgW72IqDRDHFy7I2B3Xhz6oYlop6PEeM0qpQ_cc9o6JSm9zQogPeg96-p_" +
//                        "hp97V69tS0ZyFhplUwleEuXsOThTppPYHOjL1DKIghbTNFYSKnDgOXw9FPcD6ubozcjTwUaHh7p0XmiS3D5Sv6_qlN-pSx" +
//                        "D8be-9O4OOKP6Fu1EvhL5eO4jUsqHAmA6QQFRsQwLOhFSfCKDAVJFjz_22hMj448MW0o_1ilU_uGpfSF2XqcHMsQ09mPzA";
//
//        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
//        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
//        when(mockRequest.getReader()).thenReturn(new BufferedReader(new StringReader(request)));
//        when(mockRequest.getHeaderNames()).thenReturn(Collections.<String>emptyEnumeration());
//        when(mockRequest.getAttributeNames()).thenReturn(Collections.<String>emptyEnumeration());
////        when(mockRequest.getRequestURL()).thenReturn(new StringBuffer());
////        when(mockRequest.getServletPath()).thenReturn("");
////        PrivilegedCarbonContext mockPrivilegedCarbonContext = mock(PrivilegedCarbonContext.class);
////        when(mockPrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain()).thenReturn("carbon.super");
//
//        assertNotNull(logoutRequestFactory.create(mockRequest, mockResponse));
    }

}
