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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.internal.OpenIDConnectAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.spy;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/***
 * Unit test class for OpenIDConnectAuthenticatorTest class.
 */
@PrepareForTest({LogFactory.class, OAuthClient.class, URL.class, FrameworkUtils.class,
                 OpenIDConnectAuthenticatorDataHolder.class, OAuthAuthzResponse.class, OAuthClientRequest.class,
                 OAuthClientResponse.class, IdentityUtil.class, OpenIDConnectAuthenticator.class})
public class OpenIDConnectAuthenticatorTest extends PowerMockTestCase {

    @Mock
    private HttpServletRequest mockServletRequest;

    @Mock
    private HttpServletResponse mockServletResponse;

    @Mock
    private OAuthClientResponse mockOAuthClientResponse;

    @Mock
    private OAuthClientRequest mockOAuthClientRequest;

    @Mock
    private OAuthJSONAccessTokenResponse mockOAuthJSONAccessTokenResponse;

    @Mock
    private AuthenticationContext mockAuthenticationContext;

    @Mock
    private HttpURLConnection mockConnection;

    @Mock
    private OAuthAuthzResponse mockOAuthzResponse;

    @Mock
    private RealmService mockRealmService;

    @Mock
    private UserRealm mockUserRealm;

    @Mock
    private UserStoreManager mockUserStoreManager;

    @Mock
    private TenantManager mockTenantManger;

    @Mock
    private RealmConfiguration mockRealmConfiguration;

    @Mock
    private OAuthClient mockOAuthClient;

    @Mock
    private ClaimMetadataManagementService claimMetadataManagementService;

    @Mock
    private ExternalIdPConfig externalIdPConfig;

    @Mock
    private OpenIDConnectAuthenticatorDataHolder openIDConnectAuthenticatorDataHolder;

    OpenIDConnectAuthenticator openIDConnectAuthenticator;

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
    private int TENANT_ID = 1234;

    @BeforeTest
    public void init() {
        openIDConnectAuthenticator = new OpenIDConnectAuthenticator();
        authenticatorProperties = new HashMap<>();
        authenticatorProperties.put("callbackUrl", "http://localhost:8080/playground2/oauth2client");
        authenticatorProperties.put("commonAuthQueryParams", "scope=openid&state=OIDC&loginType=basic");
        authenticatorProperties.put("UserInfoUrl", "https://localhost:9443/oauth2/userinfo");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "u5FIfG5xzLvBGiamoAYzzcqpBqga");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "_kLtobqi08GytnypVW_Mmy1niAIa");
        authenticatorProperties.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, "https://localhost:9443/oauth2/token");
        authenticatorProperties.put(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL, "https://localhost:9443/oauth2/authorize");
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_USER_ID_IN_CLAIMS, "true");
        token = null;
    }

    @DataProvider(name = "seperator")
    public Object[][] getSeperator() {

        return new String[][]{
                {","},
                {",,,"}
        };
    }

    @DataProvider(name = "requestDataHandler")
    public Object[][] getRequestStatus() {

        return new String[][]{
                // When all parameters not null.
                {"openid","active,OIDC", "BASIC", "Error Login.",  "true", "active", "Invalid can handle response for the request.", "Invalid context identifier."},
                // When gran_type and login_type are null.
                {null,"active,OIDC", null, "Error Login.", "true", "active", "Invalid can handle response for the request.", "Invalid context identifier."},
                // When all parameters null.
                {null, null, null, null, "false", null, "Invalid can handle response for the request.", "Invalid context identifier."}
        };
    }

    @Test(dataProvider = "requestDataHandler")
    public void testCanHandle(String grantType, String state, String loginType, String error, String expectedCanHandler, String expectedContext, String msgCanHandler, String msgContext) throws IOException {


        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn(grantType);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn(state);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn(loginType);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn(error);

        assertEquals(openIDConnectAuthenticator.canHandle(mockServletRequest), Boolean.parseBoolean(expectedCanHandler), msgCanHandler);
        assertEquals(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), expectedContext, msgContext);

    }

    @Test
    public void testGetAuthorizationServerEndpoint() throws IOException {
        assertNull(openIDConnectAuthenticator.getAuthorizationServerEndpoint(authenticatorProperties),
                "Unable to get the authorization server endpoint.");
    }

    @Test
    public void testGetCallbackUrl() throws IOException {
        assertEquals(openIDConnectAuthenticator.getCallBackURL(authenticatorProperties),
                "http://localhost:8080/playground2/oauth2client",
                "Callback URL is not valid.");
    }

    @Test
    public void testGetTokenEndpoint() throws IOException {
        assertNotNull(openIDConnectAuthenticator.getTokenEndpoint(authenticatorProperties),
                "Unable to get the token endpoint.");
    }

    @Test
    public void testGetState() throws IOException {
        assertEquals(openIDConnectAuthenticator.getState("OIDC", authenticatorProperties),
                "OIDC", "Unable to get the scope.");
    }

    @Test
    public void testGetScope() throws IOException {
        assertEquals(openIDConnectAuthenticator.getScope("openid", authenticatorProperties),
                "openid", "Unable to get the scope.");
    }

    @Test
    public void testRequiredIDToken() throws IOException {
        assertTrue(openIDConnectAuthenticator.requiredIDToken(authenticatorProperties),
                "Does not require the ID token.");
    }

    @Test
    public void testGetCallBackURL() throws IOException {
        assertEquals(openIDConnectAuthenticator.getCallBackURL(authenticatorProperties),
                "http://localhost:8080/playground2/oauth2client",
                "Callback URL is not valid.");
    }

    @Test
    public void testGetUserInfoEndpoint() throws IOException {
        assertEquals(openIDConnectAuthenticator.getUserInfoEndpoint(token, authenticatorProperties),
                "https://localhost:9443/oauth2/userinfo", "unable to get the user infor endpoint");
    }

    @Test
    public void testGetSubjectAttributes() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException, IOException {
        Map<ClaimMapping, String> result;
        // Test with no json response.
        when(mockOAuthClientResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN)).
                thenReturn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        result = openIDConnectAuthenticator.getSubjectAttributes(mockOAuthClientResponse, authenticatorProperties);
        assertTrue(result.isEmpty(), "result is not Empty.");

        // Test with a json response which is not empty.
        Map<String, Object> jsonObject = new HashMap<>();
        jsonObject.put("email", new String("{\"http://www.wso2.org/email\" : \"example@wso2.com\"}"));
        String json = jsonObject.toString();
        openIDConnectAuthenticator = spy(OpenIDConnectAuthenticator.class);
        doReturn(json).when(openIDConnectAuthenticator).sendRequest(any(String.class),
                any(String.class));
        result = openIDConnectAuthenticator.getSubjectAttributes(mockOAuthClientResponse, authenticatorProperties);
        assertTrue(!result.isEmpty(), "result is Empty.");

        // Test with a json response which is empty.
        doReturn(" ").when(openIDConnectAuthenticator).sendRequest(any(String.class),
                any(String.class));
        result = openIDConnectAuthenticator.getSubjectAttributes(mockOAuthClientResponse, authenticatorProperties);
        assertTrue(result.isEmpty(), "result is not Empty.");
    }

    @DataProvider(name = "commonAuthParamProvider")
    public Object[][] getCommonAuthParams() {

        return new String[][]{
                // If condition : queryString != null && queryString.contains("scope=")&& queryString.contains("redirect_uri=").
                {"scope=openid&state=OIDC&loginType=basic&redirect_uri=https://localhost:9443/redirect", "https://localhost:9443/redirect", "The redirect URI is invalid"},
                // If condition : queryString != null && queryString.contains("scope=").
                {"state=OIDC&loginType=basic&redirect_uri=https://localhost:9443/redirect",
                         "https://localhost:9443/redirect", "The redirect URI is invalid"},
                // If condition : queryString != null && queryString.contains("redirect_uri=").
                {"state=OIDC&loginType=basic", "https://localhost:9443/redirect", "The redirect URI is invalid"}
        };
    }

    @Test ( dataProvider = "commonAuthParamProvider")
    public void testInitiateAuthenticationRequest(String authParam, String expectedValue,
                                                  String errorMsg) throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException, UserStoreException {
        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(mockServletResponse.encodeRedirectURL(anyString())).thenReturn("https://localhost:9443/redirect");
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn("ContextIdentifier");
        when(mockServletRequest.getParameter("domain")).thenReturn("carbon_super");
        openIDConnectAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);

        authenticatorProperties.put("commonAuthQueryParams", authParam);
        openIDConnectAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
        assertEquals(mockServletResponse.encodeRedirectURL("encodeRedirectUri"), expectedValue, errorMsg);

    }

    @Test ( expectedExceptions = AuthenticationFailedException.class)
    public void testInitiateAuthenticationRequestNullProperties() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException, UserStoreException {
        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(null);
        openIDConnectAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
    }


    @Test
    public void testPassProcessAuthenticationResponse() throws Exception {
        setupTest();
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(Matchers.<OAuthClientRequest>anyObject()))
                .thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockOAuthJSONAccessTokenResponse.getParam(anyString())).thenReturn(idToken);
        openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);

        assertEquals(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN),
                accessToken, "Invalid access token in the authentication context.");

        assertEquals(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ID_TOKEN), idToken,
                "Invalid Id token in the authentication context.");
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testPassProcessAuthenticationResponseWithoutAccessToken() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException, UserStoreException {
        setupTest();
        // Empty access token and id token
        setParametersForOAuthClientResponse(mockOAuthClientResponse, "", "");
        openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);
    }

    @Test
    public void testPassProcessAuthenticationWithBlankCallBack() throws Exception {
        setupTest();
        authenticatorProperties.put("callbackUrl", " ");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true)).thenReturn("http:/localhost:9443/oauth2/callback");
        setParametersForOAuthClientResponse(mockOAuthClientResponse, accessToken, idToken);
        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(Matchers.<OAuthClientRequest>anyObject())).thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockOAuthJSONAccessTokenResponse.getParam(anyString())).thenReturn(idToken);
        openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);
    }

    @Test
    public void testPassProcessAuthenticationWithParamValue() throws Exception {
        setupTest();
        authenticatorProperties.put("callbackUrl", "http://localhost:8080/playground2/oauth2client");
        Map<String, String> paramMap = new HashMap<>();
        paramMap.put("redirect_uri","http:/localhost:9443/oauth2/redirect");
        when(mockAuthenticationContext.getProperty("oidc:param.map")).thenReturn(paramMap);
        setParametersForOAuthClientResponse(mockOAuthClientResponse, accessToken, idToken);
        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(Matchers.<OAuthClientRequest>anyObject()))
                .thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockOAuthJSONAccessTokenResponse.getParam(anyString())).thenReturn(idToken);
        openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);
    }

    @Test(dataProvider = "seperator")
    public void testBuildClaimMappings(String separator) throws Exception {
        Map<ClaimMapping, String> claims = new HashMap<>();
        Map<String, Object> entries = new HashMap<>();
        entries.put("scope", new Object());

        for (Map.Entry<String, Object> entry : entries.entrySet()) {
            openIDConnectAuthenticator.buildClaimMappings(claims, entry, separator);
            assertTrue(!claims.isEmpty(), "Claims[] is empty.");
        }
        entries = new HashMap<>();
        entries.put("scope", new String("[    \n" +
                "    {\"name\":\"Ram\", \"email\":\"example1@gmail.com\", \"age\":23},    \n" +
                "    {\"name\":\"Shyam\", \"email\":\"example2@gmail.com\", \"age\":28},  \n" +
                "]"));
        for (Map.Entry<String, Object> entry : entries.entrySet()) {
            openIDConnectAuthenticator.buildClaimMappings(claims, entry, separator);
            assertTrue(!claims.isEmpty(), "Claims[] is empty.");
        }
    }

    /**
     * Covers a case that was experienced while mapping claims from Salesforce
     */
    @Test
    public void testClaimMappingWithNullValues() {
        Map<ClaimMapping, String> claims = new HashMap<>();
        Map<String, Object> entries = new HashMap<>();
        entries.put("zoneinfo", "GMT");
        entries.put("email", "test123@test.de");
        entries.put("phone_number", null);

        for (Map.Entry<String, Object> entry : entries.entrySet()) {
            openIDConnectAuthenticator.buildClaimMappings(claims, entry, null);
            assertNotNull(claims.get(
                    ClaimMapping.build(entry.getKey(), entry.getKey(), null, false)),
                    "Claim was not mapped.");
        }
    }

    @Test(dataProvider = "requestDataHandler")
    public void testGetContextIdentifier(String grantType, String state, String loginType, String error, String expectedCanHandler, String expectedContext, String msgCanHandler, String msgContext) throws Exception {
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn(grantType);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn(state);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn(loginType);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn(error);

        assertEquals(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), expectedContext, msgContext);

    }

    @Test
    public void testGetFriendlyName() throws Exception {
        assertEquals(openIDConnectAuthenticator.getFriendlyName(), "openidconnect",
                "Invalid friendly name.");
    }

    @Test
    public void testGetName() throws Exception {
        assertEquals(openIDConnectAuthenticator.getName(), "OpenIDConnectAuthenticator",
                "Invalid authenticator name.");
    }

    @Test
    public void testGetClaimDialectURI() throws Exception {
        assertEquals(openIDConnectAuthenticator.getClaimDialectURI(), "http://wso2.org/oidc/claim",
                "Invalid claim dialect uri.");
    }

    @Test
    public void testGetSubjectFromUserIDClaimURI() throws FrameworkException {
        // Subject is null.
        assertNull(openIDConnectAuthenticator.getSubjectFromUserIDClaimURI(mockAuthenticationContext));

        // Subject is not null.
        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.getFederatedSubjectFromClaims(mockAuthenticationContext,
                openIDConnectAuthenticator.getClaimDialectURI())).thenReturn("subject");
        Assert.assertNotNull(openIDConnectAuthenticator.getSubjectFromUserIDClaimURI(mockAuthenticationContext));
    }

    @Test
    public void testSendRequest() throws Exception {

        // InputStream is null.
        String result = openIDConnectAuthenticator.sendRequest(null, accessToken);
        assertTrue(StringUtils.isBlank(result), "The send request should be empty.");

        // InputStream is not null.
        InputStream stream =
                IOUtils.toInputStream("Some test data for my input stream", "UTF-8");

        URL url = mock(URL.class);
        whenNew(URL.class).withParameterTypes(String.class)
                .withArguments(anyString()).thenReturn(url);
        when(url.openConnection()).thenReturn(mockConnection);
        when(mockConnection.getInputStream()).thenReturn(stream);
        result = openIDConnectAuthenticator.sendRequest("https://www.google.com", accessToken);
        assertTrue(!result.isEmpty(), "The send request should not be empty.");
    }


    @Test
    public void testGetOauthResponseWithoutExceptions() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException {
        when(mockOAuthClient.accessToken(mockOAuthClientRequest)).thenReturn(mockOAuthJSONAccessTokenResponse);
        Assert.assertNotNull(openIDConnectAuthenticator.getOauthResponse(mockOAuthClient, mockOAuthClientRequest));
    }


    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testGetOauthResponseWithExceptions() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException {
        OAuthClientRequest oAuthClientRequest = mock(OAuthClientRequest.class);
        OAuthClient oAuthClient = mock(OAuthClient.class);
        when(oAuthClient.accessToken(oAuthClientRequest)).thenThrow(OAuthSystemException.class);
        openIDConnectAuthenticator.getOauthResponse(oAuthClient, oAuthClientRequest);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testGetOauthResponseWithOAuthProblemExceptions() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException {
        OAuthClientRequest oAuthClientRequest = mock(OAuthClientRequest.class);
        OAuthClient oAuthClient = mock(OAuthClient.class);
        when(oAuthClient.accessToken(oAuthClientRequest)).thenThrow(OAuthProblemException.class);
        openIDConnectAuthenticator.getOauthResponse(oAuthClient, oAuthClientRequest);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    /***
     *  Method which set up background for the process authentication method.
     *
     * @throws OAuthProblemException an instance of OAuthProblemException
     * @throws AuthenticationFailedException an instance of AuthenticationFailedException
     * @throws UserStoreException an instance of UserStoreException
     */
    private void setupTest() throws OAuthSystemException, UserStoreException,
            OAuthProblemException, AuthenticationFailedException {
        mockStatic(OAuthAuthzResponse.class);
        when(OAuthAuthzResponse.oauthCodeAuthzResponse(mockServletRequest)).thenReturn(mockOAuthzResponse);
        when(mockServletRequest.getParameter("domain")).thenReturn("carbon.super");
        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(mockOAuthzResponse.getCode()).thenReturn("200");
        when(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN)).thenReturn(accessToken);
        when(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ID_TOKEN)).thenReturn(idToken);
        setParametersForOAuthClientResponse(mockOAuthClientResponse, accessToken, idToken);
        mockStatic(OpenIDConnectAuthenticatorDataHolder.class);
        when(OpenIDConnectAuthenticatorDataHolder.getInstance()).thenReturn(openIDConnectAuthenticatorDataHolder);
        when(openIDConnectAuthenticatorDataHolder.getRealmService()).thenReturn(mockRealmService);
        when(mockRealmService.getTenantManager()).thenReturn(mockTenantManger);
        when(mockTenantManger.getTenantId(anyString())).thenReturn(TENANT_ID);

        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfiguration);
        when(mockRealmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR))
                .thenReturn(",");
    }

    private void setParametersForOAuthClientResponse(OAuthClientResponse mockOAuthClientResponse,
                                                     String accessToken, String idToken) {
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
