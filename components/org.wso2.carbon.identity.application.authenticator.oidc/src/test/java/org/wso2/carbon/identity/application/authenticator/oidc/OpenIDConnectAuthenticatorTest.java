/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc;

import org.apache.axis2.client.Stub;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({LogFactory.class, OAuthClient.class, URL.class, FrameworkUtils.class,
        OAuthAuthzResponse.class, OAuthClientRequest.class})
public class OpenIDConnectAuthenticatorTest {

    @Mock
    private HttpServletRequest mockServletRequest;
    @Mock
    private OAuthClientResponse mockResponse;
    @Mock
    private AuthenticationContext mockAuthenticationContext;
    @Mock
    private HttpURLConnection mockConnection;
    @Mock
    private Log log;
    @InjectMocks
    private OpenIDConnectAuthenticator openIDConnectAuthenticator;

    private static AuthenticationContext context = null;
    private static Map<String, String> authenticatorProperties;
    private static String accessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    private static OAuthClientResponse token;
    private static Map<String, Object> jsonObject;

    @BeforeTest
    public void init() {

        openIDConnectAuthenticator = new OpenIDConnectAuthenticator();
        authenticatorProperties = new HashMap<>();
        authenticatorProperties.put("callbackUrl","http://localhost:8080/playground2/oauth2client");
        authenticatorProperties.put("commonAuthQueryParams", "Show error equals true.");
        authenticatorProperties.put("UserInfoUrl","https://localhost:9443/oauth2/userinfo");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "Q1nGJ8_lO4GGkOIESzEMJZBT39Ma");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "I38YrW1VZabefzcyPkZurenPDV0a");
        authenticatorProperties.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, " https://localhost:9443/oauth2/token");

        jsonObject = new HashMap<>();
        Stub stub = new Stub() {
            @Override
            public int hashCode() {
                return super.hashCode();
            }
        };
        jsonObject.put("stub", stub);
        token = null;

    }

    @Test(priority = 0)
    public void testCanHandle() throws Exception {

        mockServletRequest = mock(HttpServletRequest.class);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn("openid");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn("active,OIDC");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn("BASIC");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn("Error Login.");
        Assert.assertTrue(openIDConnectAuthenticator.canHandle(mockServletRequest), "Invalid can handle response for the request.");
        Assert.assertNotNull(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), "Invalid context identifier.");

        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn("active,OIDC");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn("Error Login.");
        Assert.assertTrue(openIDConnectAuthenticator.canHandle(mockServletRequest), "Invalid can handle response for the request.");
        Assert.assertNotNull(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), "Invalid context identifier.");

        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn(null);
        Assert.assertFalse(openIDConnectAuthenticator.canHandle(mockServletRequest), "Invalid can handle response for the request.");
        Assert.assertNull(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), "Invalid context identifier.");

    }

    @Test(priority = 1)
    public void testGetAuthorizationServerEndpoint() throws Exception {
        Assert.assertNull(openIDConnectAuthenticator.getAuthorizationServerEndpoint(authenticatorProperties),
                "Unable to get the authorization server endpoint.");
    }

    @Test(priority = 1)
    public void testGetCallbackUrl() throws Exception {
        Assert.assertEquals(openIDConnectAuthenticator.getCallBackURL(authenticatorProperties),
                "http://localhost:8080/playground2/oauth2client",
                "Callback URL is not valid.");
    }

    @Test(priority = 1)
    public void testGetTokenEndpoint() throws Exception {
        Assert.assertNull(openIDConnectAuthenticator.getTokenEndpoint(authenticatorProperties),
                "Unable to get the token endpoint.");
    }

    @Test(priority = 1)
    public void testGetState() throws Exception {
        Assert.assertEquals(openIDConnectAuthenticator.getState("OIDC", authenticatorProperties),
                "OIDC", "Unable to get the scope.");
    }

    @Test(priority = 1)
    public void testGetScope() throws Exception {
        Assert.assertEquals(openIDConnectAuthenticator.getScope("openid", authenticatorProperties),
                "openid", "Unable to get the scope.");
    }

    @Test(priority = 1)
    public void testRequiredIDToken() throws Exception {
        Assert.assertTrue(openIDConnectAuthenticator.requiredIDToken(authenticatorProperties),
                "Does not require the ID token.");
    }

    @Test(priority = 1)
    public void testGetAuthenticateUser() throws Exception {
        Assert.assertNull(openIDConnectAuthenticator.getAuthenticateUser(context, jsonObject, token),
                "Unable to get the authenticated user.");
    }

    @Test(priority = 1)
    public void testGetCallBackURL() throws Exception {
        Assert.assertEquals(openIDConnectAuthenticator.getCallBackURL(authenticatorProperties),
                "http://localhost:8080/playground2/oauth2client",
                "Callback URL is not valid.");
    }

    @Test(priority = 1)
    public void testGetUserInfoEndpoint() throws Exception {
        Assert.assertEquals(openIDConnectAuthenticator.getUserInfoEndpoint(token, authenticatorProperties),
                "https://localhost:9443/oauth2/userinfo", "unable to get the user infor endpoint");
    }

    @Test(priority = 2)
    public void testGetSubjectAttributes() throws Exception {
        Map<ClaimMapping, String> result;
        mockResponse = mock(OAuthClientResponse.class);
        when(mockResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN)).thenReturn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        result = openIDConnectAuthenticator.getSubjectAttributes(mockResponse, authenticatorProperties);
        Assert.assertTrue(result.isEmpty(), "result is not Empty.");
    }

    @Test(priority = 3)
    public void testInitiateAuthenticationRequest() throws Exception {


    }

    @Test(priority = 3)
    public void testPassProcessAuthenticationResponse() throws Exception {
    }


    @Test
    public void testBuildClaimMappings() throws Exception {
    }

    @Test(priority = 4)
    public void testGetContextIdentifier() throws Exception {
        mockServletRequest = mock(HttpServletRequest.class);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn("openid");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn("active,OIDC");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn("BASIC");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn("Error Login.");
        Assert.assertNotNull(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), "Invalid context identifier.");

        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn("active,OIDC");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn("Error Login.");
        Assert.assertNotNull(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), "Invalid context identifier.");

        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn(null);
        Assert.assertNull(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), "Invalid context identifier.");
    }

    @Test(priority = 1)
    public void testGetFriendlyName() throws Exception {
        Assert.assertEquals(openIDConnectAuthenticator.getFriendlyName(), "openidconnect",
                "Invalid friendly name.");
    }

    @Test(priority = 1)
    public void testGetName() throws Exception {
        Assert.assertEquals(openIDConnectAuthenticator.getName(), "OpenIDConnectAuthenticator",
                "Invalid authenticator name.");
    }

    @Test(priority = 1)
    public void testGetClaimDialectURI() throws Exception {
        Assert.assertEquals(openIDConnectAuthenticator.getClaimDialectURI(), "http://wso2.org/oidc/claim",
                "Invalid claim dialect uri.");
    }

    @Test
    public void testGetSubjectFromUserIDClaimURI() throws FrameworkException {
        // Subject is null.
        mockAuthenticationContext = mock(AuthenticationContext.class);
        Assert.assertNull(openIDConnectAuthenticator.getSubjectFromUserIDClaimURI(mockAuthenticationContext));

        // Subject is not null.
        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.getFederatedSubjectFromClaims(mockAuthenticationContext, openIDConnectAuthenticator.getClaimDialectURI())).thenReturn("subject");
        Assert.assertNotNull(openIDConnectAuthenticator.getSubjectFromUserIDClaimURI(mockAuthenticationContext));
    }

    @Test(priority = 5)
    public void testSendRequest() throws Exception {
        mockStatic(LogFactory.class);
        when(LogFactory.getLog(any(Class.class))).thenReturn(log);
        Boolean debugEnabled = true;
        when(log.isDebugEnabled()).thenReturn(debugEnabled);
        doNothing().when(log).debug(any());
        doNothing().when(log).debug(any(), any(Throwable.class));

        String result = openIDConnectAuthenticator.sendRequest(null, accessToken);
        Assert.assertTrue(result.isEmpty(), "The send request should be empty.");

        File initialFile = new File(TestUtils.getFilePath("testStream.xml"));
        InputStream stream = new FileInputStream(initialFile);
        URL url = PowerMockito.mock(URL.class);
        PowerMockito.whenNew(URL.class).withParameterTypes(String.class)
                .withArguments(anyString()).thenReturn(url);
        when(url.openConnection()).thenReturn(mockConnection);
        when(mockConnection.getInputStream()).thenReturn(stream);
        result = openIDConnectAuthenticator.sendRequest("https://www.google.com", accessToken);
        Assert.assertTrue(!result.isEmpty(), "The send request should not be empty.");
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

}
