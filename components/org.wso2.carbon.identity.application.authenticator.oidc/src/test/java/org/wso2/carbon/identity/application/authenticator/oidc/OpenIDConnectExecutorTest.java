/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.OAuth2.SCOPES;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.REDIRECT_URL;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;

public class OpenIDConnectExecutorTest {

    private static final String REGISTRATION_PORTAL_PATH = "/authenticationendpoint/register.do";
    private static final String REGISTRATION_PORTAL_URL = "https://localhost:9443" + REGISTRATION_PORTAL_PATH;
    private static final String TOKEN_ENDPOINT = "https://localhost:9443/oauth2/token";
    private static final String USER_INFO_ENDPOINT = "https://localhost:9443/oauth2/userinfo";
    private static final String AUTHORIZE_ENDPOINT = "https://localhost:9443/oauth2/authorize";
    private static final String CLIENT_ID = "testClientId";
    private static final String CLIENT_SECRET = "testClientSecret";
    private static final String CODE = "authorizationCode";
    private static final String ACCESS_TOKEN_VALUE = "test-access-token";
    private static final String STATE = "test-state";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String USER_ID = "test-user-id";

    @Mock
    private FlowExecutionContext flowExecutionContext;

    @Mock
    private OAuthJSONAccessTokenResponse oAuthClientResponse;

    private OpenIDConnectExecutor executor;
    private AutoCloseable mocks;
    MockedStatic<LoggerUtils> loggerUtilsStatic;

    @BeforeMethod
    public void setUp() {

        String carbonHome =
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "repository").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        System.setProperty(CarbonBaseConstants.CARBON_CONFIG_DIR_PATH, Paths.get(carbonHome, "conf").toString());

        loggerUtilsStatic = mockStatic(LoggerUtils.class);
        loggerUtilsStatic.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

        mocks = MockitoAnnotations.openMocks(this);
        executor = spy(new OpenIDConnectExecutor());
        when(flowExecutionContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (mocks != null) {
            mocks.close();
        }
        loggerUtilsStatic.close();
    }

    @Test
    public void testExecute_processResponse() throws Exception {

        Map<String, String> userInputs = new HashMap<>();
        userInputs.put(OAUTH2_GRANT_TYPE_CODE, CODE);
        userInputs.put(OAUTH2_PARAM_STATE, STATE);
        when(flowExecutionContext.getUserInputData()).thenReturn(userInputs);
        when(flowExecutionContext.getProperty(OAUTH2_PARAM_STATE)).thenReturn(STATE);

        // Stub resolveUserAttributes to avoid static mocking of various utilities.
        Map<String, Object> claims = new HashMap<>();
        claims.put(USERNAME_CLAIM_URI, USER_ID);
        doReturn(claims).when(executor).resolveUserAttributes(flowExecutionContext, CODE);

        ExecutorResponse response = executor.execute(flowExecutionContext);

        Assert.assertNotNull(response);
        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
        Assert.assertTrue(response.getUpdatedUserClaims().containsKey(USERNAME_CLAIM_URI));
        Assert.assertEquals(response.getUpdatedUserClaims().get(USERNAME_CLAIM_URI), USER_ID);
    }

    @Test
    public void testExecuteInitialRequest() {

        when(flowExecutionContext.getUserInputData()).thenReturn(null);
        // Provide minimal properties to build redirect URL without static mocking.
        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, CLIENT_ID);
        authProperties.put(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL, AUTHORIZE_ENDPOINT);
        authProperties.put(SCOPES, "openid");
        when(flowExecutionContext.getAuthenticatorProperties()).thenReturn(authProperties);
        when(flowExecutionContext.getPortalUrl()).thenReturn(REGISTRATION_PORTAL_URL);

        ExecutorResponse response = executor.execute(flowExecutionContext);

        Assert.assertNotNull(response);
        Assert.assertEquals(response.getResult(), STATUS_EXTERNAL_REDIRECTION);
        Assert.assertTrue(response.getRequiredData().contains(OAUTH2_GRANT_TYPE_CODE));
        Assert.assertTrue(response.getRequiredData().contains(OAUTH2_PARAM_STATE));
        Assert.assertTrue(response.getContextProperties().containsKey(OAUTH2_PARAM_STATE));
        Assert.assertTrue(response.getAdditionalInfo().containsKey(OAUTH2_PARAM_STATE));
        Assert.assertTrue(response.getAdditionalInfo().containsKey(REDIRECT_URL));
    }

    @Test
    public void testExecuteStateMismatch() {

        Map<String, String> userInputs = new HashMap<>();
        userInputs.put(OAUTH2_GRANT_TYPE_CODE, CODE);
        userInputs.put(OAUTH2_PARAM_STATE, STATE);
        when(flowExecutionContext.getUserInputData()).thenReturn(userInputs);
        when(flowExecutionContext.getProperty(OAUTH2_PARAM_STATE)).thenReturn("different-state");

        ExecutorResponse response = executor.execute(flowExecutionContext);
        Assert.assertEquals(response.getResult(), STATUS_ERROR);
    }

    @Test
    public void testGetAuthenticateUser() {

        Map<String, Object> oidcClaims = new HashMap<>();
        oidcClaims.put(OIDCAuthenticatorConstants.Claim.SUB, USER_ID);
        String userId = executor.getAuthenticatedUserIdentifier(oidcClaims);
        Assert.assertEquals(userId, USER_ID);
    }

    @Test
    public void testResolveAccessToken() throws FlowEngineException {

        when(oAuthClientResponse.getParam(ACCESS_TOKEN)).thenReturn(ACCESS_TOKEN_VALUE);
        String accessToken = executor.resolveAccessToken(oAuthClientResponse);
        Assert.assertEquals(accessToken, ACCESS_TOKEN_VALUE);
    }

    @Test(expectedExceptions = FlowEngineException.class)
    public void testResolveAccessTokenWithBlankToken() throws FlowEngineException {

        when(oAuthClientResponse.getParam(ACCESS_TOKEN)).thenReturn("");
        executor.resolveAccessToken(oAuthClientResponse);
    }

    @Test
    public void testGetUserInfoEndpoint() {

        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL, USER_INFO_ENDPOINT);
        String endpoint = executor.getUserInfoEndpoint(authProperties);
        Assert.assertEquals(endpoint, USER_INFO_ENDPOINT);
    }

    @Test
    public void testGetAuthorizationServerEndpoint() {

        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL, AUTHORIZE_ENDPOINT);

        String endpoint = executor.getAuthorizationServerEndpoint(authProperties);

        Assert.assertEquals(endpoint, AUTHORIZE_ENDPOINT);
    }

    @Test
    public void testGetTokenEndpoint() {

        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, TOKEN_ENDPOINT);

        String endpoint = executor.getTokenEndpoint(authProperties);

        Assert.assertEquals(endpoint, TOKEN_ENDPOINT);
    }

    @Test
    public void testGetName() {

        String name = executor.getName();

        Assert.assertEquals(name, "OpenIDConnectExecutor");
    }

    @Test
    public void testGetScopeWithConfiguredScope() {

        Map<String, String> authProperties = new HashMap<>();
        String scope = "openid profile";
        authProperties.put(SCOPES, scope);

        String result = executor.getScope(authProperties);
        Assert.assertEquals(result, scope);
    }

    @Test
    public void testGetScopeWithDefaultScope() {

        Map<String, String> authProperties = new HashMap<>();

        String result = executor.getScope(authProperties);
        Assert.assertEquals(result, OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE);
    }

    @Test
    public void testGetInitiationData() {

        Assert.assertTrue(executor.getInitiationData().isEmpty());
    }

    @Test
    @SuppressWarnings("deprecation")
    public void testGetAccessTokenRequest() throws Exception {
        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, CLIENT_ID);
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, CLIENT_SECRET);
        authProperties.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, TOKEN_ENDPOINT);
        when(flowExecutionContext.getPortalUrl()).thenReturn(REGISTRATION_PORTAL_URL);

        try (MockedStatic<ServiceURLBuilder> svc = Mockito.mockStatic(ServiceURLBuilder.class)) {
            ServiceURLBuilder builder = mock(ServiceURLBuilder.class);
            ServiceURL serviceURL = mock(ServiceURL.class);
            svc.when(ServiceURLBuilder::create).thenReturn(builder);
            when(builder.build()).thenReturn(serviceURL);
            when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443");

            OAuthClientRequest request = executor.getAccessTokenRequest(authProperties, CODE, REGISTRATION_PORTAL_URL);

            Assert.assertNotNull(request);
            Assert.assertEquals(request.getLocationUri(), TOKEN_ENDPOINT);
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    public void testGetAccessTokenRequestWithBasicAuth() throws Exception {

        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, CLIENT_ID);
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, CLIENT_SECRET);
        authProperties.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, TOKEN_ENDPOINT);
        authProperties.put(OIDCAuthenticatorConstants.IS_BASIC_AUTH_ENABLED, "true");

        try (MockedStatic<ServiceURLBuilder> svc = Mockito.mockStatic(ServiceURLBuilder.class)) {
            ServiceURLBuilder builder = mock(ServiceURLBuilder.class);
            ServiceURL serviceURL = mock(ServiceURL.class);
            svc.when(ServiceURLBuilder::create).thenReturn(builder);
            when(builder.build()).thenReturn(serviceURL);
            when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443");

            OAuthClientRequest request = executor.getAccessTokenRequest(authProperties, CODE, REGISTRATION_PORTAL_URL);

            Assert.assertNotNull(request);
            Assert.assertEquals(request.getLocationUri(), TOKEN_ENDPOINT);
            Assert.assertNotNull(request.getHeaders().get("Authorization"));
        }
    }
}
