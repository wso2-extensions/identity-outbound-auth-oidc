/*
 * Copyright (c) 2017-2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.application.authenticator.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.FederatedToken;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.internal.OpenIDConnectAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCTokenValidationUtil;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.util.IdPManagementConstants;
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
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.AUTHENTICATOR_OIDC;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.Claim.NONCE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.SHARE_FEDERATED_TOKEN_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OIDC_FEDERATION_NONCE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.SHARE_FEDERATED_TOKEN_PARAM;

/***
 * Unit test class for OpenIDConnectAuthenticator class.
 */
@PrepareForTest({LogFactory.class, OAuthClient.class, URL.class, FrameworkUtils.class,
        OpenIDConnectAuthenticatorDataHolder.class, OAuthAuthzResponse.class, OAuthClientRequest.class,
        OAuthClientResponse.class, IdentityUtil.class, OpenIDConnectAuthenticator.class, ServiceURLBuilder.class,
        LoggerUtils.class, OIDCTokenValidationUtil.class, IdentityProviderManager.class})
@SuppressStaticInitializationFor({"org.wso2.carbon.idp.mgt.IdentityProviderManager",
        "org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException"})
public class OpenIDConnectAuthenticatorTest extends PowerMockTestCase {

    private static final String OIDC_PARAM_MAP_STRING = "oidc:param.map";
    private static final String HTTPS_LOCALHOST_9443 = "https://localhost:9443";
    private static final String COMMA_SEPARATOR = ",";
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
    private IdentityProvider identityProvider;

    @Mock
    private IdentityProviderManager identityProviderManager;

    @Mock
    private OpenIDConnectAuthenticatorDataHolder openIDConnectAuthenticatorDataHolder;

    @Mock
    private ServiceURLBuilder serviceURLBuilder;

    @Mock
    private ServiceURL serviceURL;

    OpenIDConnectAuthenticator openIDConnectAuthenticator;

    private static Map<String, String> authenticatorProperties;
    private static Map<String, String> authenticatorParamProperties;
    private static String clientId = "u5FIfG5xzLvBGiamoAYzzcqpBqga";
    private static String accessToken = "4952b467-86b2-31df-b63c-0bf25cec4f86s";
    private static String refreshToken = "6357238-86b2-31df-b63c-0bf25cec4f86s";
    private static String expiresIn = "3600";
    private String scope = "openid email profile";
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
    private static String invalidIdToken = "invalid_id_token";
    private static String sessionDataKey = "7b1c8131-c6bd-4682-892e-1a948a9e57e8";
    private static String nonce = "0ed8f1b3-e83f-46c0-8d52-f0d2e7925f98";
    private static String invalidNonce = "7ed8f1b3-e83f-46c0-8d52-f0d2e7925f98";
    private static String redirectUrl = "https://accounts.google.com/o/oauth2/v2/auth?scope=openid&" +
            "response_type=code&redirect_uri=https%3A%2F%2Flocalhost%3A9443%2Fcommonauth&" +
            "state=958e9049-8cd2-4580-8745-6679ac8d33f6%2COIDC&nonce=0ed8f1b3-e83f-46c0-8d52-f0d2e7925f98&" +
            "client_id=sample.client-id";
    private static String superTenantDomain = "carbon.super";
    private static OAuthClientResponse token;
    private Map<String, String> paramValueMap;
    private int TENANT_ID = 1234;
    private AuthenticationRequest mockAuthenticationRequest = new AuthenticationRequest();

    @BeforeTest
    public void init() {

        openIDConnectAuthenticator = new OpenIDConnectAuthenticator();
        authenticatorProperties = new HashMap<>();
        authenticatorProperties.put("callbackUrl", "http://localhost:8080/playground2/oauth2client");
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.OIDC.QUERY_PARAMS,
                "scope=openid&state=OIDC&loginType=basic");
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.OIDC.SCOPES, "openid email profile");
        authenticatorProperties.put("UserInfoUrl", "https://localhost:9443/oauth2/userinfo");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, clientId);
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "_kLtobqi08GytnypVW_Mmy1niAIa");
        authenticatorProperties.put(
                OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, "https://localhost:9443/oauth2/token");
        authenticatorProperties.put(
                OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL, "https://localhost:9443/oauth2/authorize");
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_USER_ID_IN_CLAIMS, "true");
        authenticatorParamProperties = new HashMap<>();
        authenticatorParamProperties.put("username", "testUser");
        authenticatorParamProperties.put("fidp", "google");
        token = null;
    }

    @DataProvider(name = "seperator")
    public Object[][] getSeperator() {

        return new String[][]{
                {COMMA_SEPARATOR},
                {",,,"}
        };
    }

    @DataProvider(name = "requestDataHandler")
    public Object[][] getRequestStatus() {

        return new String[][]{
                // When all parameters not null.
                {"openid", "active,OIDC", "BASIC", "Error Login.", "true", "active", "Invalid can handle response for" +
                        " the request.", "Invalid context identifier."},
                // When grant_type and login_type are null.
                {null, "active,OIDC", null, "Error Login.", "true", "active", "Invalid can handle response for the " +
                        "request.", "Invalid context identifier."},
                // When all parameters null.
                {null, null, null, null, "false", null, "Invalid can handle response for the request.", "Invalid " +
                        "context identifier."}
        };
    }

    @Test(dataProvider = "requestDataHandler")
    public void testCanHandle(String grantType, String state, String loginType, String error, String expectedCanHandler,
                              String expectedContext, String msgCanHandler, String msgContext) throws IOException {

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn(grantType);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn(state);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn(loginType);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn(error);

        assertEquals(openIDConnectAuthenticator.canHandle(mockServletRequest),
                Boolean.parseBoolean(expectedCanHandler), msgCanHandler);
        assertEquals(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), expectedContext, msgContext);

    }

    @Test
    public void testCanHandleForNativeSDKBasedFederation() throws Exception {

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.ACCESS_TOKEN_PARAM)).thenReturn(accessToken);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.ID_TOKEN_PARAM)).thenReturn(idToken);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.SESSION_DATA_KEY_PARAM))
                .thenReturn(sessionDataKey);
        when(mockServletRequest.getAttribute(FrameworkConstants.IS_API_BASED_AUTH_FLOW)).thenReturn(true);

        assertTrue(openIDConnectAuthenticator.canHandle(mockServletRequest));
        assertEquals(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), sessionDataKey);
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
    public void testGetScopePrimary() throws IOException {

        assertEquals(openIDConnectAuthenticator.getScope(authenticatorProperties),
                "openid email profile", "Unable to get the scope.");
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
                // If condition :
                // queryString != null && queryString.contains("scope=") && queryString.contains("redirect_uri=").
                {"scope=openid&state=OIDC&loginType=basic&redirect_uri=https://localhost:9443/redirect",
                        "https://localhost:9443/redirect", "The redirect URI is invalid"},
                // If condition : queryString != null && queryString.contains("scope=").
                {"state=OIDC&loginType=basic&redirect_uri=https://localhost:9443/redirect",
                        "https://localhost:9443/redirect", "The redirect URI is invalid"},
                // If condition : queryString != null && queryString.contains("redirect_uri=").
                {"state=OIDC&loginType=basic", "https://localhost:9443/redirect", "The redirect URI is invalid"},
                {"login_hint=$authparam{username}", "https://localhost:9443/redirect", "The redirect URI is invalid"},
                {"login_hint=$authparam{username}&domain=$authparam{fidp}", "https://localhost:9443/redirect",
                        "The redirect URI is invalid"}
        };
    }

    @Test(dataProvider = "commonAuthParamProvider")
    public void testInitiateAuthenticationRequest(String authParam, String expectedValue,
                                                  String errorMsg) throws Exception {

        setupTest();
        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(mockServletResponse.encodeRedirectURL(anyString())).thenReturn("https://localhost:9443/redirect");
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn("ContextIdentifier");
        when(mockServletRequest.getParameter("domain")).thenReturn("carbon_super");
        openIDConnectAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);

        authenticatorProperties.put("commonAuthQueryParams", authParam);
        when(openIDConnectAuthenticator.getRuntimeParams(mockAuthenticationContext)).
                thenReturn(authenticatorParamProperties);
        openIDConnectAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                mockAuthenticationContext);
        assertEquals(mockServletResponse.encodeRedirectURL("encodeRedirectUri"), expectedValue, errorMsg);

    }

    @Test
    public void testGetQueryStringWithAuthenticatorParam() throws Exception {

        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(openIDConnectAuthenticator.getRuntimeParams(mockAuthenticationContext)).
                thenReturn(authenticatorParamProperties);
        assertEquals(Whitebox.invokeMethod(openIDConnectAuthenticator,
                "getQueryStringWithAuthenticatorParam", mockAuthenticationContext,
                "login_hint=$authparam{username}"), "login_hint=testUser");
    }

    @Test
    public void testGetQueryStringWithMultipleAuthenticatorParam() throws Exception {

        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(openIDConnectAuthenticator.getRuntimeParams(mockAuthenticationContext)).
                thenReturn(authenticatorParamProperties);
        assertEquals(Whitebox.invokeMethod(openIDConnectAuthenticator,
                "getQueryStringWithAuthenticatorParam", mockAuthenticationContext,
                "login_hint=$authparam{username}&domain=$authparam{fidp}"), "login_hint=testUser&domain=google");
    }

    @Test
    public void testInitiateAuthenticationRequestNullProperties() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException, UserStoreException {

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(null);

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> openIDConnectAuthenticator.initiateAuthenticationRequest(mockServletRequest, mockServletResponse,
                        mockAuthenticationContext)
        );
    }

    @Test
    public void testPassProcessAuthenticationResponse() throws Exception {

        setupTest();

        IdentityProviderProperty property = new IdentityProviderProperty();
        property.setName(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        property.setValue("false");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        identityProviderProperties[0] = property;

        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(identityProvider.getIdpProperties()).thenReturn(identityProviderProperties);
        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(Matchers.<OAuthClientRequest>anyObject()))
                .thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockOAuthJSONAccessTokenResponse.getParam(anyString())).thenReturn(idToken);
        authenticatorProperties.put(OIDCAuthenticatorConstants.IS_PKCE_ENABLED, "false");
        openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);

        assertEquals(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN),
                accessToken, "Invalid access token in the authentication context.");

        assertEquals(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ID_TOKEN), idToken,
                "Invalid Id token in the authentication context.");
    }

    @Test
    public void testPassProcessAuthenticationResponseWithNonce() throws Exception {

        setupTest();

        IdentityProviderProperty property = new IdentityProviderProperty();
        property.setName(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        property.setValue("false");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        identityProviderProperties[0] = property;

        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(identityProvider.getIdpProperties()).thenReturn(identityProviderProperties);
        authenticatorProperties.put(OIDCAuthenticatorConstants.IS_PKCE_ENABLED, "false");
        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(Matchers.<OAuthClientRequest>anyObject()))
                .thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockAuthenticationContext.getProperty(OIDC_FEDERATION_NONCE)).thenReturn(nonce);
        when(mockOAuthJSONAccessTokenResponse.getParam(anyString())).thenReturn(idToken);
        openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);

        assertEquals(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN),
                accessToken, "Invalid access token in the authentication context.");

        assertEquals(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ID_TOKEN), idToken,
                "Invalid Id token in the authentication context.");
    }

//    /**
//     * Test whether the token request contains the code verifier when PKCE is enabled.
//     *
//     * @throws URLBuilderException
//     * @throws AuthenticationFailedException
//     */
//    @Test()
//    public void testGetAccessTokenRequestWithPKCE() throws URLBuilderException, AuthenticationFailedException {
//        mockAuthenticationRequestContext(mockAuthenticationContext);
//        authenticatorProperties.put(OIDCAuthenticatorConstants.IS_PKCE_ENABLED, "true");
//        when(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.PKCE_CODE_VERIFIER))
//                .thenReturn("sample_code_verifier");
//        when(mockOAuthzResponse.getCode()).thenReturn("abc");
//        mockStatic(ServiceURLBuilder.class);
//        ServiceURLBuilder serviceURLBuilder = mock(ServiceURLBuilder.class);
//        when(ServiceURLBuilder.create()).thenReturn(serviceURLBuilder);
//        when(serviceURLBuilder.build()).thenReturn(serviceURL);
//        when(serviceURL.getAbsolutePublicURL()).thenReturn("http://localhost:9443");
//        OAuthClientRequest request = openIDConnectAuthenticator
//                .getAccessTokenRequest(mockAuthenticationContext, mockOAuthzResponse);
//        assertTrue(request.getBody().contains("code_verifier=sample_code_verifier"));
//    }

    @Test
    public void testPassProcessAuthenticationResponseWithoutAccessToken() throws Exception {

        setupTest();
        // Empty access token and id token
        setParametersForOAuthClientResponse(mockOAuthClientResponse, "", "");

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                        mockServletResponse, mockAuthenticationContext)
        );
    }

    @Test
    public void testPassProcessAuthenticationWithBlankCallBack() throws Exception {

        setupTest();
        authenticatorProperties.put("callbackUrl", " ");
        authenticatorProperties.put(OIDCAuthenticatorConstants.IS_PKCE_ENABLED, "false");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true))
                .thenReturn("http:/localhost:9443/oauth2/callback");
        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        setParametersForOAuthClientResponse(mockOAuthClientResponse, accessToken, idToken);
        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);

        IdentityProviderProperty property = new IdentityProviderProperty();
        property.setName(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        property.setValue("false");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        identityProviderProperties[0] = property;

        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(identityProvider.getIdpProperties()).thenReturn(identityProviderProperties);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(Matchers.<OAuthClientRequest>anyObject())).thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockOAuthJSONAccessTokenResponse.getParam(anyString())).thenReturn(idToken);
        openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);
    }

    @Test
    public void testFailProcessAuthenticationWhenNonceMisMatch() throws Exception {

        setupTest();
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true))
                .thenReturn("http:/localhost:9443/oauth2/callback");

        IdentityProviderProperty property = new IdentityProviderProperty();
        property.setName(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        property.setValue("false");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        identityProviderProperties[0] = property;

        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(identityProvider.getIdpProperties()).thenReturn(identityProviderProperties);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(any())).thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockAuthenticationContext.getProperty(OIDC_FEDERATION_NONCE)).thenReturn(invalidNonce);
        when(mockOAuthJSONAccessTokenResponse.getParam(anyString())).thenReturn(idToken);

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                        mockServletResponse, mockAuthenticationContext)
        );
    }

    @Test
    public void testPassProcessAuthenticationWithParamValue() throws Exception {

        setupTest();
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        authenticatorProperties.put("callbackUrl", "http://localhost:8080/playground2/oauth2client");
        authenticatorProperties.put(OIDCAuthenticatorConstants.IS_PKCE_ENABLED, "false");
        Map<String, String> paramMap = new HashMap<>();
        paramMap.put("redirect_uri", "http:/localhost:9443/oauth2/redirect");
        when(mockAuthenticationContext.getProperty(OIDC_PARAM_MAP_STRING)).thenReturn(paramMap);
        setParametersForOAuthClientResponse(mockOAuthClientResponse, accessToken, idToken);
        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);

        IdentityProviderProperty property = new IdentityProviderProperty();
        property.setName(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        property.setValue("false");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        identityProviderProperties[0] = property;

        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(identityProvider.getIdpProperties()).thenReturn(identityProviderProperties);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(Matchers.<OAuthClientRequest>anyObject()))
                .thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockOAuthJSONAccessTokenResponse.getParam(anyString())).thenReturn(idToken);
        openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);
    }

    @Test
    public void testPassProcessAuthenticationResponseWithNativeSDKBaseFederation() throws Exception {

        setupTest();

        IdentityProviderProperty property = new IdentityProviderProperty();
        property.setName(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        property.setValue("true");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        identityProviderProperties[0] = property;
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(identityProvider.getIdpProperties()).thenReturn(identityProviderProperties);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.ID_TOKEN_PARAM))
                .thenReturn(idToken);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.ACCESS_TOKEN_PARAM))
                .thenReturn(accessToken);

        mockStatic(OIDCTokenValidationUtil.class);
        doNothing().when(OIDCTokenValidationUtil.class, "validateIssuerClaim", any(JWTClaimsSet.class));
        when(mockAuthenticationContext.getTenantDomain()).thenReturn(superTenantDomain);
        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getIdPByMetadataProperty(
                eq(IdentityApplicationConstants.IDP_ISSUER_NAME), anyString(), eq(superTenantDomain), eq(false)))
                .thenReturn(identityProvider);
        doNothing().when(OIDCTokenValidationUtil.class, "validateSignature", any(SignedJWT.class),
                any(IdentityProvider.class));
        doNothing().when(OIDCTokenValidationUtil.class, "validateAudience", any(List.class), any(), anyString());

        when(openIDConnectAuthenticatorDataHolder.getClaimMetadataManagementService()).thenReturn
                (claimMetadataManagementService);
        openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                mockServletResponse, mockAuthenticationContext);

        assertEquals(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN),
                accessToken, "Invalid access token in the authentication context.");

        assertEquals(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ID_TOKEN), idToken,
                "Invalid Id token in the authentication context.");
    }

    @Test
    public void testFailProcessAuthenticationResponseWithNativeSDKBaseFederation() throws Exception {

        setupTest();

        IdentityProviderProperty property = new IdentityProviderProperty();
        property.setName(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        property.setValue("true");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        identityProviderProperties[0] = property;
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(identityProvider.getIdpProperties()).thenReturn(identityProviderProperties);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.ID_TOKEN_PARAM))
                .thenReturn(idToken);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.ACCESS_TOKEN_PARAM))
                .thenReturn(accessToken);

        mockStatic(OIDCTokenValidationUtil.class);
        doNothing().when(OIDCTokenValidationUtil.class, "validateIssuerClaim", any(JWTClaimsSet.class));
        when(mockAuthenticationContext.getTenantDomain()).thenReturn(superTenantDomain);
        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getIdPByMetadataProperty(
                eq(IdentityApplicationConstants.IDP_ISSUER_NAME), anyString(), eq(superTenantDomain), eq(false)))
                .thenReturn(identityProvider);
        doNothing().when(OIDCTokenValidationUtil.class, "validateSignature", any(SignedJWT.class),
                any(IdentityProvider.class));

        // If none of the audience values matched the token endpoint alias
        doThrow(mock(AuthenticationFailedException.class))
                .when(OIDCTokenValidationUtil.class, "validateAudience", any(List.class),
                        any(), eq(superTenantDomain));

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                        mockServletResponse, mockAuthenticationContext)
        );

        // If signature validation fails.
        doThrow(mock(AuthenticationFailedException.class))
                .when(OIDCTokenValidationUtil.class, "validateSignature", any(SignedJWT.class),
                        any(IdentityProvider.class));

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                        mockServletResponse, mockAuthenticationContext)
        );

        // If there is an issue while validating the signature.
        doThrow(mock(IdentityOAuth2Exception.class))
                .when(OIDCTokenValidationUtil.class, "validateSignature", any(SignedJWT.class),
                        any(IdentityProvider.class));

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                        mockServletResponse, mockAuthenticationContext)
        );

        // If there is an issue while verifying the singed JWT.
        doThrow(mock(JOSEException.class))
                .when(OIDCTokenValidationUtil.class, "validateSignature", any(SignedJWT.class),
                        any(IdentityProvider.class));

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                        mockServletResponse, mockAuthenticationContext)
        );

        // If there is an issue while validating the issuer.
        mockStatic(OIDCTokenValidationUtil.class);
        doThrow(mock(AuthenticationFailedException.class))
                .when(OIDCTokenValidationUtil.class, "validateIssuerClaim", any(JWTClaimsSet.class));

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                        mockServletResponse, mockAuthenticationContext)
        );

        // If the sent id token is invalid.
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.ID_TOKEN_PARAM))
                .thenReturn(invalidIdToken);

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest,
                        mockServletResponse, mockAuthenticationContext)
        );
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
                    "Claim value is null.");
        }
    }

    @Test(dataProvider = "requestDataHandler")
    public void testGetContextIdentifier(String grantType, String state, String loginType, String error,
                                         String expectedCanHandler, String expectedContext, String msgCanHandler,
                                         String msgContext) throws Exception {

        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)).thenReturn(grantType);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn(state);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.LOGIN_TYPE)).thenReturn(loginType);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn(error);

        assertEquals(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), expectedContext, msgContext);

    }

    @Test
    public void testGetContextIdentifierForNativeSDKBasedFederation() throws Exception {

        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.ACCESS_TOKEN_PARAM)).thenReturn(accessToken);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.ID_TOKEN_PARAM)).thenReturn(idToken);
        when(mockServletRequest.getParameter(OIDCAuthenticatorConstants.SESSION_DATA_KEY_PARAM))
                .thenReturn(sessionDataKey);
        when(mockServletRequest.getAttribute(FrameworkConstants.IS_API_BASED_AUTH_FLOW)).thenReturn(true);

        assertEquals(openIDConnectAuthenticator.getContextIdentifier(mockServletRequest), sessionDataKey);
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

    @Test
    public void testGetOauthResponseWithExceptions() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException {

        OAuthClientRequest oAuthClientRequest = mock(OAuthClientRequest.class);
        OAuthClient oAuthClient = mock(OAuthClient.class);
        when(oAuthClient.accessToken(oAuthClientRequest)).thenThrow(OAuthSystemException.class);

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> openIDConnectAuthenticator.getOauthResponse(oAuthClient, oAuthClientRequest)
        );
    }

    @Test
    public void testGetOauthResponseWithOAuthProblemExceptions() throws OAuthSystemException,
            OAuthProblemException, AuthenticationFailedException {

        OAuthClientRequest oAuthClientRequest = mock(OAuthClientRequest.class);
        OAuthClient oAuthClient = mock(OAuthClient.class);
        when(oAuthClient.accessToken(oAuthClientRequest)).thenThrow(OAuthProblemException.class);

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> openIDConnectAuthenticator.getOauthResponse(oAuthClient, oAuthClientRequest)
        );
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
    private void setupTest() throws Exception {

        mockStatic(OAuthAuthzResponse.class);
        when(OAuthAuthzResponse.oauthCodeAuthzResponse(mockServletRequest)).thenReturn(mockOAuthzResponse);
        when(mockServletRequest.getParameter("domain")).thenReturn(superTenantDomain);
        mockAuthenticationRequestContext(mockAuthenticationContext);
        when(mockOAuthzResponse.getCode()).thenReturn("200");
        when(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN)).thenReturn(accessToken);
        when(mockAuthenticationContext.getProperty(OIDCAuthenticatorConstants.ID_TOKEN)).thenReturn(idToken);
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(getDummyExternalIdPConfig());
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
                .thenReturn(COMMA_SEPARATOR);
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL("", false, false))
                .thenReturn(HTTPS_LOCALHOST_9443);

        mockStatic(ServiceURLBuilder.class);
        when(ServiceURLBuilder.create()).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addPath(anyString())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addParameter(anyString(), anyString())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.build()).thenReturn(serviceURL);

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
    }

    private void setParametersForOAuthClientResponse(OAuthClientResponse mockOAuthClientResponse,
                                                     String accessToken, String idToken) {

        when(mockOAuthClientResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN)).thenReturn(accessToken);
        when(mockOAuthClientResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN)).thenReturn(idToken);
    }

    private void mockAuthenticationRequestContext(AuthenticationContext mockAuthenticationContext) {

        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        paramValueMap = new HashMap<>();
        when(mockAuthenticationContext.getProperty(OIDC_PARAM_MAP_STRING)).thenReturn(paramValueMap);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn("");
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(getDummyExternalIdPConfig());
        when(mockAuthenticationContext.getAuthenticationRequest()).thenReturn(mockAuthenticationRequest);
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        boolean isAPIBasedAuthenticationSupported = openIDConnectAuthenticator.isAPIBasedAuthenticationSupported();
        Assert.assertTrue(isAPIBasedAuthenticationSupported);
    }

    @Test
    public void testGetAuthInitiationData() {

        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName()).thenReturn("LOCAL");
        when(mockAuthenticationContext.getAuthenticationRequest()).thenReturn(mockAuthenticationRequest);
        when(mockAuthenticationContext.getProperty(
                OIDCAuthenticatorConstants.AUTHENTICATOR_NAME + OIDCAuthenticatorConstants.REDIRECT_URL_SUFFIX))
                .thenReturn(redirectUrl);
        Optional<AuthenticatorData> authenticatorData = openIDConnectAuthenticator.getAuthInitiationData
                (mockAuthenticationContext);

        Assert.assertTrue(authenticatorData.isPresent());
        AuthenticatorData authenticatorDataObj = authenticatorData.get();

        Assert.assertEquals(authenticatorDataObj.getName(), AUTHENTICATOR_NAME);
        Assert.assertEquals(authenticatorDataObj.getI18nKey(), AUTHENTICATOR_OIDC);
        Assert.assertEquals(authenticatorDataObj.getDisplayName(), AUTHENTICATOR_FRIENDLY_NAME);
        Assert.assertEquals(authenticatorDataObj.getRequiredParams().size(),
                2);
        Assert.assertEquals(authenticatorDataObj.getPromptType(),
                FrameworkConstants.AuthenticatorPromptType.REDIRECTION_PROMPT);
        Assert.assertTrue(authenticatorDataObj.getRequiredParams()
                .contains(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE));
        Assert.assertTrue(authenticatorDataObj.getRequiredParams()
                .contains(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE));
        Assert.assertEquals(authenticatorDataObj.getAdditionalData().getRedirectUrl(), redirectUrl);
    }

    @Test
    public void testGetAuthInitiationDataForNativeSDKBasedFederation() {

        IdentityProviderProperty property = new IdentityProviderProperty();
        property.setName(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        property.setValue("true");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        identityProviderProperties[0] = property;

        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName()).thenReturn("LOCAL");
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(identityProvider.getIdpProperties()).thenReturn(identityProviderProperties);
        when(mockAuthenticationContext.getAuthenticationRequest()).thenReturn(mockAuthenticationRequest);
        when(mockAuthenticationContext.getProperty(OIDC_FEDERATION_NONCE)).thenReturn(nonce);
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, clientId);

        Optional<AuthenticatorData> authenticatorData = openIDConnectAuthenticator.getAuthInitiationData
                (mockAuthenticationContext);

        Assert.assertTrue(authenticatorData.isPresent());
        AuthenticatorData authenticatorDataObj = authenticatorData.get();

        Assert.assertEquals(authenticatorDataObj.getName(), AUTHENTICATOR_NAME);
        Assert.assertEquals(authenticatorDataObj.getI18nKey(), AUTHENTICATOR_OIDC);
        Assert.assertEquals(authenticatorDataObj.getDisplayName(), AUTHENTICATOR_FRIENDLY_NAME);
        Assert.assertEquals(authenticatorDataObj.getRequiredParams().size(),
                2);
        Assert.assertEquals(authenticatorDataObj.getPromptType(),
                FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT);
        Assert.assertTrue(authenticatorDataObj.getRequiredParams()
                .contains(OIDCAuthenticatorConstants.ACCESS_TOKEN_PARAM));
        Assert.assertTrue(authenticatorDataObj.getRequiredParams()
                .contains(OIDCAuthenticatorConstants.ID_TOKEN_PARAM));
        Assert.assertEquals(authenticatorDataObj.getAdditionalData()
                .getAdditionalAuthenticationParams().get(NONCE), nonce);
        Assert.assertEquals(authenticatorDataObj.getAdditionalData()
                .getAdditionalAuthenticationParams().get(OIDCAuthenticatorConstants.CLIENT_ID_PARAM), clientId);
    }

    @Test
    public void testGetI18nKey() {

        String oidcI18nKey = openIDConnectAuthenticator.getI18nKey();
        Assert.assertEquals(oidcI18nKey, AUTHENTICATOR_OIDC);
    }

    private ExternalIdPConfig getDummyExternalIdPConfig() {

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setIdentityProviderName("DummyIDPName");
        return new ExternalIdPConfig(identityProvider);
    }

    private ExternalIdPConfig getExternalIdPConfig(String idpName) {

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setIdentityProviderName(idpName);
        return new ExternalIdPConfig(identityProvider);
    }

    /**
     * This method generates test criteria on the query parameter change on sharing the federated token for
     * different combination of the IDP configuration value. The adaptive script parameter values are same
     * to the query parameter values.
     *
     * @return Object[][] The test criteria.
     */
    @DataProvider(name = "shareFederatedTokenParams")
    public Object[][] shareFederatedTokenParams() {

        return new Object[][]{
                {"IDP config is enabled, application requested the federated token, " +
                        "adaptive script requested the federated token", "true", "true", "true"},
                {"IDP config is disabled, application requested the federated token", "false", "true", "true"},
                {"IDP config is enabled, application did not request the federated token", "true", "false", "false"},
                {"IDP config is disabled, application did not request the federated token", "false", "false",
                        "false"},
                {"IDP config is disabled, application did not send the parameter", "true", null, null},
                {"IDP config is disabled, application did not send the parameter", "false", null, null},
                {"No IDP config found, application requested the federated token", null, "true", "true"},
                {"No IDP config found, application did not request the federated token", null, "false", "false"},
                {"No IDP config found, application did not send the parameter", null, null, null}
        };
    }

    /**
     * This method generates test criteria on the adaptive script parameter change on sharing the federated token.
     *
     * @return Object[][] The test criteria.
     */
    @DataProvider(name = "shareFederatedTokenParamsForAdaptiveScriptConfigs")
    public Object[][] shareFederatedTokenParamsForAdaptiveScriptConfigs() {

        return new Object[][]{
                {"IDP config is enabled, authorize call requested the federated token," +
                        " adaptive script requested the federated token", "true", "true", "true"},
                {"IDP config is enabled, authorize call requested the federated token," +
                        " adaptive script did not request the federated token", "true", "true", "false"},
                {"IDP config is enabled, authorize call requested the federated token," +
                        " no adaptive script config found", "true", "true", null},
                {"IDP config is disabled, authorize call requested the federated token", "false", "true", "true"},
                {"IDP config is enabled, authorize call did not request the federated token," +
                        " adaptive script did not request the federated token", "true", "false", "false"},
                {"IDP config is enabled, authorize call did not request the federated token," +
                        " adaptive script requested the federated token", "true", "false", "true"},
                {"IDP config is enabled, authorize call did not request the federated token," +
                        " no adaptive script config found", "true", "false", null},
                {"IDP config is disabled, authorize call did not request the federated token",
                        "false", "false", "false"},
                {"IDP config is disabled, authorize call did not send the parameter," +
                        " no adaptive script config found", "true", null, null},
                {"IDP config is disabled, authorize call did not send the parameter," +
                        " adaptive script requested the federated token", "true", null, "true"},
                {"IDP config is disabled, authorize call did not send the parameter," +
                        " adaptive script did not request the federated token", "true", null, "false"},
                {"IDP config is disabled, authorize call did not send the parameter", "false", null, null},
                {"No IDP config found, authorize call requested the federated token", null, "true", "true"},
                {"No IDP config found, authorize call did not request the federated token", null, "false", "false"},
                {"No IDP config found, authorize call did not send the parameter", null, null, null}
        };
    }

    /**
     * This method generates test criteria on extracting scopes from given URL query parameters.
     *
     * @return Object[][] The test criteria.
     */
    @DataProvider(name = "authorizeUrls")
    public Object[][] authorizeUrls() {

        return new Object[][]{
                {"https://localhost:9443/oauth2/authorize?scope=openid+profile+email&clientID=aishf784hwbf947gfo",
                        "openid profile email"},
                {"https://localhost:9443/oauth2/authorize?scope=openid+profile+email", "openid profile email"},
                {"https://localhost:9443/oauth2/authorize?scope=openid", "openid"},
                {"https://localhost:9443/oauth2/authorize?clientID=aishf784hwbf947gfo", ""},
                {"https://localhost:9443/oauth2/authorize", ""},
                {"", ""}
        };
    }

    @Test(dataProvider = "shareFederatedTokenParamsForAdaptiveScriptConfigs")
    public void testShareFederatedTokenParamsForAdaptiveScriptConfigs(String errorMessage,
                                                                      String enableShareTokenIDPConfig,
                                                                      String shareTokenQueryParameter,
                                                                      String shareTokeAdaptiveScriptParam)
            throws Exception {

        testShareFederatedTokenForIDPConfigAndQueryParameter(errorMessage, enableShareTokenIDPConfig,
                shareTokenQueryParameter, shareTokeAdaptiveScriptParam);
    }

    @Test(dataProvider = "shareFederatedTokenParams")
    public void testShareFederatedTokenForIDPConfigAndQueryParameter(String errorMessage,
                                                                     String enableShareTokenIDPConfig,
                                                                     String shareTokenQueryParameter,
                                                                     String shareTokeAdaptiveScriptParam)
            throws Exception {

        String authenticator = "Google Calender";
        mockStaticClasses();
        mockServiceVariables();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        mapQueryParamsToAuthenticationRequest(authenticationRequest, SHARE_FEDERATED_TOKEN_PARAM,
                shareTokenQueryParameter);
        AuthenticationContext authenticationContext =
                getAuthenticationContext(authenticator, authenticationRequest, enableShareTokenIDPConfig);
        addAdaptiveScriptParams(authenticationContext, SHARE_FEDERATED_TOKEN_PARAM, shareTokeAdaptiveScriptParam);
        mockIDPAuthentication();

        openIDConnectAuthenticator.processAuthenticationResponse(mockServletRequest, mockServletResponse,
                authenticationContext);

        if (Boolean.parseBoolean(enableShareTokenIDPConfig) && ((StringUtils.isBlank(shareTokeAdaptiveScriptParam) &&
                Boolean.parseBoolean(shareTokenQueryParameter)) ||
                Boolean.parseBoolean(shareTokeAdaptiveScriptParam))) {
            assertNotNull(authenticationContext.getProperty(FrameworkConstants.FEDERATED_TOKENS), errorMessage);

            if (authenticationContext.getProperty(FrameworkConstants.FEDERATED_TOKENS) != null &&
                    authenticationContext.getProperty(FrameworkConstants.FEDERATED_TOKENS) instanceof List) {
                List<FederatedToken> federatedToken = (List<FederatedToken>) authenticationContext.getProperty(
                        FrameworkConstants.FEDERATED_TOKENS);
                assertEquals(federatedToken.get(0).getAccessToken(), accessToken, "No access token found");
                assertEquals(federatedToken.get(0).getRefreshToken(), refreshToken, "No refresh token found");
                assertEquals(federatedToken.get(0).getTokenValidityPeriod(), expiresIn, "No expiry time found");
                assertEquals(federatedToken.get(0).getScope(), scope, "No scope found");
            }
        } else {
            assertNull(authenticationContext.getProperty(FrameworkConstants.FEDERATED_TOKENS), errorMessage);
        }
    }

    @Test
    public void testGetApplicationDetails() throws Exception {

        AuthenticationContext mockedAuthenticationContext = mock(AuthenticationContext.class);
        when(mockedAuthenticationContext.getServiceProviderName()).thenReturn("Test App");

        SequenceConfig mockedSequenceConfig = mock(SequenceConfig.class);
        ApplicationConfig mockedApplicationConfig = mock(ApplicationConfig.class);
        ServiceProvider mockedServiceProvider = mock(ServiceProvider.class);
        when(mockedAuthenticationContext.getSequenceConfig()).thenReturn(mockedSequenceConfig);
        when(mockedSequenceConfig.getApplicationConfig()).thenReturn(mockedApplicationConfig);
        when(mockedApplicationConfig.getServiceProvider()).thenReturn(mockedServiceProvider);
        when(mockedServiceProvider.getApplicationResourceId()).thenReturn("test-app-resource-id");

        Map<String, String> applicationDetails =
                openIDConnectAuthenticator.getApplicationDetails(mockedAuthenticationContext);
        assertEquals(applicationDetails.get("application name"), "Test App",
                "Application name is not set properly.");
        assertEquals(applicationDetails.get("app id"), "test-app-resource-id",
                "Application id is not set properly.");
    }

    @Test(dataProvider = "authorizeUrls")
    public void testExtractScopesFromURL(String url, String expectedScopes) throws Exception {

        String scopes = openIDConnectAuthenticator.extractScopesFromURL(url);
        assertEquals(scopes, expectedScopes, "Scopes are not extracted properly.");
    }

    /**
     * This method generates an authentication instance for the federated token sharing.
     *
     * @param authenticator             The federated authenticator name.
     * @param authenticationRequest     The authentication request.
     * @param enableShareTokenIDPConfig The IDP config of the enabling the federated token sharing.
     * @return AuthenticationContext The generated authentication context for the federated token sharing.
     */
    private AuthenticationContext getAuthenticationContext(String authenticator,
                                                           AuthenticationRequest authenticationRequest,
                                                           String enableShareTokenIDPConfig) {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setAuthenticationRequest(authenticationRequest);
        authenticationContext.setExternalIdP(getExternalIdPConfig(authenticator));
        authenticationContext.setProperty(OIDC_PARAM_MAP_STRING, paramValueMap);
        authenticationContext.setContextIdentifier("");

        if (StringUtils.isNotBlank(enableShareTokenIDPConfig)) {
            authenticatorProperties.put(SHARE_FEDERATED_TOKEN_CONFIG, enableShareTokenIDPConfig);
        }
        authenticationContext.setAuthenticatorProperties(authenticatorProperties);

        return authenticationContext;
    }

    /**
     * This method maps the authorize request query parameters for testing.
     *
     * @param authenticationRequest The authentication request to map the query parameters.
     * @param queryParameterName    The query parameter name.
     * @param queryParameterValue   The query parameter value.
     */
    private void mapQueryParamsToAuthenticationRequest(AuthenticationRequest authenticationRequest,
                                                       String queryParameterName, String queryParameterValue) {
        if (StringUtils.isNotBlank(queryParameterValue)) {
            String[] queryParam = new String[]{queryParameterValue};
            authenticationRequest.addRequestQueryParam(queryParameterName, queryParam);
        }
    }

    /**
     * This method mocks the adaptive parameters to the authentication context.
     *
     * @param authenticationContext            The authentication context to be tested.
     * @param shareTokeAdaptiveScriptParamName The adaptive scrip parameter name.
     * @param shareTokeAdaptiveScriptParam     The adaptive script parameter value.
     */
    private void addAdaptiveScriptParams(AuthenticationContext authenticationContext,
                                         String shareTokeAdaptiveScriptParamName, String shareTokeAdaptiveScriptParam) {

        Map<String, String> adaptiveScriptParam = new HashMap<>();
        Map<String, Map<String, String>> runtimeParams = new HashMap<>();
        authenticationContext.addParameter("RUNTIME_PARAMS", runtimeParams);
        runtimeParams.put(OIDCAuthenticatorConstants.AUTHENTICATOR_NAME, adaptiveScriptParam);

        if (StringUtils.isNotBlank(shareTokeAdaptiveScriptParam)) {
            adaptiveScriptParam.put(shareTokeAdaptiveScriptParamName, shareTokeAdaptiveScriptParam);
        }
    }

    /**
     * This method mocks the external IDP authentication flow and the value mappings.
     *
     * @throws Exception Throws the exceptions on error.
     */
    private void mockIDPAuthentication() throws Exception {

        IdentityProviderProperty[] identityProviderProperties = getIdentityProviderProperties();
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);
        when(identityProvider.getIdpProperties()).thenReturn(identityProviderProperties);
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(mockOAuthClient);
        when(mockOAuthClient.accessToken(Matchers.anyObject())).thenReturn(mockOAuthJSONAccessTokenResponse);
        when(mockOAuthJSONAccessTokenResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN)).thenReturn(
                accessToken);
        when(mockOAuthJSONAccessTokenResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN)).thenReturn(idToken);
        when(mockOAuthJSONAccessTokenResponse.getParam(OIDCAuthenticatorConstants.REFRESH_TOKEN)).thenReturn(
                refreshToken);
        when(mockOAuthJSONAccessTokenResponse.getParam(OIDCAuthenticatorConstants.EXPIRES_IN)).thenReturn(expiresIn);
        when(mockOAuthJSONAccessTokenResponse.getParam(OIDCAuthenticatorConstants.SCOPE)).thenReturn(scope);
    }

    /**
     * This method mocks the service variable for the authorization call.
     *
     * @throws OAuthProblemException Throws on the oAuth flow exception.
     * @throws UserStoreException    Throws on the user store exception.
     * @throws URLBuilderException   Throws on the url builder exception.
     */
    private void mockServiceVariables() throws OAuthProblemException, UserStoreException, URLBuilderException {

        when(OAuthAuthzResponse.oauthCodeAuthzResponse(mockServletRequest)).thenReturn(mockOAuthzResponse);
        when(mockServletRequest.getParameter("domain")).thenReturn(superTenantDomain);
        when(mockOAuthzResponse.getCode()).thenReturn("200");
        setParametersForOAuthClientResponse(mockOAuthClientResponse, accessToken, idToken);
        when(OpenIDConnectAuthenticatorDataHolder.getInstance()).thenReturn(openIDConnectAuthenticatorDataHolder);
        when(openIDConnectAuthenticatorDataHolder.getRealmService()).thenReturn(mockRealmService);
        when(mockRealmService.getTenantManager()).thenReturn(mockTenantManger);
        when(mockTenantManger.getTenantId(anyString())).thenReturn(TENANT_ID);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfiguration);
        when(mockRealmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR))
                .thenReturn(COMMA_SEPARATOR);
        when(IdentityUtil.getServerURL("", false, false))
                .thenReturn(HTTPS_LOCALHOST_9443);
        when(ServiceURLBuilder.create()).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addPath(anyString())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addParameter(anyString(), anyString())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.build()).thenReturn(serviceURL);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
    }

    /**
     * This method do all the static level mocks.
     */
    private void mockStaticClasses() {

        mockStatic(OAuthAuthzResponse.class);
        mockStatic(OpenIDConnectAuthenticatorDataHolder.class);
        mockStatic(IdentityUtil.class);
        mockStatic(ServiceURLBuilder.class);
        mockStatic(LoggerUtils.class);
    }

    /**
     * This method creates the external identity provider properties.
     *
     * @return IdentityProviderProperty[] The array of the idp properties.
     */
    private IdentityProviderProperty[] getIdentityProviderProperties() {

        IdentityProviderProperty property = new IdentityProviderProperty();
        property.setName(IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER);
        property.setValue("false");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        identityProviderProperties[0] = property;
        return identityProviderProperties;
    }

}
