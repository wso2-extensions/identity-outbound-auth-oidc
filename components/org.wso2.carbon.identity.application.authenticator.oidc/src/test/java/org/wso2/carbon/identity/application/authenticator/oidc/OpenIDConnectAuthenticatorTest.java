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

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
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
import org.wso2.carbon.identity.application.authenticator.oidc.internal.OpenIDConnectAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;

@PrepareForTest({LogFactory.class, OAuthClient.class, URL.class, FrameworkUtils.class, OpenIDConnectAuthenticatorServiceComponent.class,
        OAuthAuthzResponse.class, OAuthClientRequest.class, OAuthClientResponse.class, OAuthClientRequest.AuthenticationRequestBuilder.class})
public class OpenIDConnectAuthenticatorTest {

    @Mock
    private HttpServletRequest mockServletRequest;
    @Mock
    private HttpServletResponse mockServletResponse;
    @Mock
    private OAuthClientResponse mockOAuthClientResponse;
    @Mock
    private AuthenticationContext mockAuthenticationContext;
    @Mock
    private HttpURLConnection mockConnection;
    @Mock
    private Log log;

    @InjectMocks
    OpenIDConnectAuthenticator openIDConnectAuthenticator;

    private static AuthenticationContext context = null;
    private static Map<String, String> authenticatorProperties;
    private static String accessToken = "4952b467-86b2-31df-b63c-0bf25cec4f86s";
    private static String idToken = "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5" +
            "sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9" +
            "HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6WyJ1NUZJZkc1eHpMdkJHaWFtb0FZenpjc" +
            "XBCcWdhIl0sImF6cCI6InU1RklmRzV4ekx2QkdpYW1vQVl6emNxcEJxZ2EiLCJhdXRoX3RpbWUiOjE1MDY1NzYwODAsImlzcyI6" +
            "Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTUwNjU3OTY4NCwibm9uY2UiOiI" +
            "wZWQ4ZjFiMy1lODNmLTQ2YzAtOGQ1Mi1mMGQyZTc5MjVmOTgiLCJpYXQiOjE1MDY1NzYwODQsInNpZCI6Ijg3MDZmNWR" +
            "hLTU0ZmMtNGZiMC1iNGUxLTY5MDZmYTRiMDRjMiJ9.HopPYFs4lInXvGztNEkJKh8Kdy52eCGbzYy6PiVuM_BlCcGff3SHO" +
            "oZxDH7JbIkPpKBe0cnYQWBxfHuGTUWhvnu629ek6v2YLkaHlb_Lm04xLD9FNxuZUNQFw83pQtDVpoX5r1V-F0DdUc7gA1RKN3" +
            "xMVYgRyfslRDveGYplxVVNQ1LU3lrZhgaTfcMEsC6rdbd1HjdzG71EPS4674HCSAUelOisNKGa2NgORpldDQsj376QD0G9Mhc8WtW" +
            "oguftrCCGjBy1kKT4VqFLOqlA-8wUhOj_rZT9SUIBQRDPu0RZobvsskqYo40GEZrUoa";
    private static OAuthClientResponse token;
    private Map<String, String> paramValueMap;

    @BeforeTest
    public void init() {
        authenticatorProperties = new HashMap<>();
        authenticatorProperties.put("callbackUrl","http://localhost:8080/playground2/oauth2client");
        authenticatorProperties.put("commonAuthQueryParams", "scope=openid&state=OIDC&loginType=basic");
        authenticatorProperties.put("UserInfoUrl","https://localhost:9443/oauth2/userinfo");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "u5FIfG5xzLvBGiamoAYzzcqpBqga");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "_kLtobqi08GytnypVW_Mmy1niAIa");
        authenticatorProperties.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, "https://localhost:9443/oauth2/token");
        authenticatorProperties.put(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL, "https://localhost:9443/oauth2/authorize");
        token = null;
    }

    @Test(priority = 0)
    public void testCanHandle() throws Exception {

        // When all parameters not null.
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn("openid");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn("active,OIDC");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn("BASIC");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn("Error Login.");
        Assert.assertTrue(openIDConnectAuthenticator.canHandle(mockServletRequest), "Invalid can handle response for the request.");
        Assert.assertNotNull(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), "Invalid context identifier.");

        // When gran_type and login_type are null.
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn("active,OIDC");
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn(null);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn("Error Login.");
        Assert.assertTrue(openIDConnectAuthenticator.canHandle(mockServletRequest), "Invalid can handle response for the request.");
        Assert.assertNotNull(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), "Invalid context identifier.");

        // When all parameters null.
        when(mockServletRequest.getParameter(anyString())).thenReturn(null);
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
        when(mockOAuthClientResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN)).thenReturn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        result = openIDConnectAuthenticator.getSubjectAttributes(mockOAuthClientResponse, authenticatorProperties);
        Assert.assertTrue(result.isEmpty(), "result is not Empty.");
    }

    @Test
    public void testInitiateAuthenticationRequest() throws Exception {
        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(mockServletResponse.encodeRedirectURL(anyString())).thenReturn("https://localhost:9443/redirect");
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn("ContextIdentifier");
        openIDConnectAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse, mockAuthenticationContext);

        authenticatorProperties.put("commonAuthQueryParams", "scope=openid&state=OIDC&loginType=basic&redirect_uri=https://localhost:9443/redirect");
        openIDConnectAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse, mockAuthenticationContext);
        Assert.assertEquals(mockServletResponse.encodeRedirectURL("encodeRedirectUri"),"https://localhost:9443/redirect",
                "The redirect URI is invalid");

        authenticatorProperties.put("commonAuthQueryParams", "state=OIDC&loginType=basic&redirect_uri=https://localhost:9443/redirect");
        openIDConnectAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse, mockAuthenticationContext);
        Assert.assertEquals(mockServletResponse.encodeRedirectURL("encodeRedirectUri"),"https://localhost:9443/redirect",
                "The redirect URI is invalid");

        authenticatorProperties.put("commonAuthQueryParams", "state=OIDC&loginType=basic");
        openIDConnectAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse, mockAuthenticationContext);
        Assert.assertEquals(mockServletResponse.encodeRedirectURL("encodeRedirectUri"),"https://localhost:9443/redirect",
                "The redirect URI is invalid");
    }

    @Test
    public void testPassProcessAuthenticationResponse() throws Exception {
    }

    @Test
    public void testBuildClaimMappings() throws Exception {
    }

    @Test(priority = 4)
    public void testGetContextIdentifier() throws Exception {
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

        when(mockServletRequest.getParameter(anyString())).thenReturn(null);
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

        // InputStream is null.
        String result = openIDConnectAuthenticator.sendRequest(null, accessToken);
        Assert.assertTrue(result.isEmpty(), "The send request should be empty.");

        // InputStream is not null.
        InputStream stream =
                IOUtils.toInputStream("Some test data for my input stream", "UTF-8");
        URL url = PowerMockito.mock(URL.class);
        whenNew(URL.class).withParameterTypes(String.class)
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

    private void createOAuthClientRequest(OAuthClientRequest.TokenRequestBuilder mockTokenRequestBuilder,
                                          OAuthClientRequest mockOAuthClientRequest) throws OAuthSystemException {
        when(OAuthClientRequest.tokenLocation(anyString())).thenReturn(mockTokenRequestBuilder);
        when(mockTokenRequestBuilder.setGrantType(GrantType.AUTHORIZATION_CODE)).thenReturn(mockTokenRequestBuilder);
        when(mockTokenRequestBuilder.setClientId(anyString())).thenReturn(mockTokenRequestBuilder);
        when(mockTokenRequestBuilder.setClientSecret(anyString())).thenReturn(mockTokenRequestBuilder);
        when(mockTokenRequestBuilder.setRedirectURI(anyString())).thenReturn(mockTokenRequestBuilder);
        when(mockTokenRequestBuilder.setCode(anyString())).thenReturn(mockTokenRequestBuilder);
        when(mockTokenRequestBuilder.buildBodyMessage()).thenReturn(mockOAuthClientRequest);
    }

    private void setParametersForOAuthClientResponse(OAuthClientResponse mockOAuthClientResponse) {
        when(mockOAuthClientResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN)).thenReturn(accessToken);
        when(mockOAuthClientResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN)).thenReturn(idToken);
    }

    private void mockAuthenticationRequestContext(AuthenticationContext mockAuthenticationContext) {
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        paramValueMap = new HashMap<>();
        when(mockAuthenticationContext.getProperty("oidc:param.map")).thenReturn(paramValueMap);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn("");
    }

}
