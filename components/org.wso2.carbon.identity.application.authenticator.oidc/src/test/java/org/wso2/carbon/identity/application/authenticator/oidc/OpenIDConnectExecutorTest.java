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

import org.apache.commons.logging.Log;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCCommonUtil;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.ID_TOKEN;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.OAuth2.SCOPES;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.REDIRECT_URL;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;

@PrepareForTest({ServiceURLBuilder.class, LoggerUtils.class, OIDCCommonUtil.class,
        UUID.class, OAuthClientResponse.class, OAuthClient.class, ClaimMetadataHandler.class})
@PowerMockIgnore({"jdk.internal.reflect.*", "javax.net.ssl.*", "javax.security.*", "javax.crypto.*"})
public class OpenIDConnectExecutorTest extends PowerMockTestCase {

    private static final String REGISTRATION_PORTAL_PATH = "/authenticationendpoint/register.do";
    private static final String REGISTRATION_PORTAL_URL = "https://localhost:9443" + REGISTRATION_PORTAL_PATH;
    private static final String TOKEN_ENDPOINT = "https://localhost:9443/oauth2/token";
    private static final String USER_INFO_ENDPOINT = "https://localhost:9443/oauth2/userinfo";
    private static final String AUTHORIZE_ENDPOINT = "https://localhost:9443/oauth2/authorize";
    private static final String CLIENT_ID = "testClientId";
    private static final String CLIENT_SECRET = "testClientSecret";
    private static final String CODE = "authorizationCode";
    private static final String ACCESS_TOKEN_VALUE = "test-access-token";
    private static final String ID_TOKEN_VALUE = "test-id-token";
    private static final String STATE = "test-state";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String USER_ID = "test-user-id";

    @Mock
    private FlowExecutionContext flowExecutionContext;

    @Mock
    private OAuthJSONAccessTokenResponse oAuthClientResponse;

    @Mock
    private ExternalIdPConfig externalIdPConfig;

    @Mock
    private IdentityProvider identityProvider;

    @Mock
    private ClaimMetadataHandler claimMetadataHandler;

    @Mock
    private OAuthClient oAuthClient;

    private OpenIDConnectExecutor executor;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        executor = spy(new OpenIDConnectExecutor());

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        Log mockedLog = mock(Log.class);
        doReturn(mockedLog).when(LoggerUtils.class, "getLogger", anyString());

        when(flowExecutionContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        mockStatic(ClaimMetadataHandler.class);
        when(ClaimMetadataHandler.getInstance()).thenReturn(claimMetadataHandler);
        Map<String, String> claimMappings = new HashMap<>();
        claimMappings.put(USERNAME_CLAIM_URI, "sub");
        when(claimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                anyString(), anySet(), anyString(), anyBoolean())).thenReturn(claimMappings);
    }

    @Test
    public void testExecute_processResponse() throws Exception {

        Map<String, String> userInputs = new HashMap<>();
        userInputs.put(OAUTH2_GRANT_TYPE_CODE, CODE);
        userInputs.put(OAUTH2_PARAM_STATE, STATE);
        when(flowExecutionContext.getUserInputData()).thenReturn(userInputs);

        when(flowExecutionContext.getProperty(OAUTH2_PARAM_STATE)).thenReturn(STATE);

        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, CLIENT_ID);
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, CLIENT_SECRET);
        authProperties.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, TOKEN_ENDPOINT);
        when(flowExecutionContext.getAuthenticatorProperties()).thenReturn(authProperties);

        when(flowExecutionContext.getExternalIdPConfig()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdentityProvider()).thenReturn(identityProvider);

        doReturn(oAuthClientResponse).when(executor).requestAccessToken(any(), anyString());
        when(oAuthClientResponse.getParam(ACCESS_TOKEN)).thenReturn(ACCESS_TOKEN_VALUE);
        when(oAuthClientResponse.getParam(ID_TOKEN)).thenReturn(ID_TOKEN_VALUE);

        whenNew(OAuthClient.class).withAnyArguments().thenReturn(oAuthClient);
        when(oAuthClient.accessToken(any(OAuthClientRequest.class))).thenReturn(oAuthClientResponse);

        mockStatic(OIDCCommonUtil.class);
        Map<String, Object> jwtClaims = new HashMap<>();
        jwtClaims.put(OIDCAuthenticatorConstants.Claim.SUB, USER_ID);
        Set<Map.Entry<String, Object>> jwtClaimsEntries = new HashSet<>(jwtClaims.entrySet());

        doReturn(jwtClaimsEntries).when(OIDCCommonUtil.class, "decodeIDTokenPayload", anyString());
        doReturn(false).when(OIDCCommonUtil.class, "isUserIdFoundAmongClaims", any(Map.class));
        doReturn("").when(OIDCCommonUtil.class, "getMultiAttributeSeparator", anyString());

        doNothing().when(OIDCCommonUtil.class, "buildClaimMappings", any(Map.class), any(Map.Entry.class), anyString());

        ExecutorResponse response = executor.execute(flowExecutionContext);

        Assert.assertNotNull(response);
        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
        Assert.assertTrue(response.getUpdatedUserClaims().containsKey(USERNAME_CLAIM_URI));
        Assert.assertEquals(response.getUpdatedUserClaims().get(USERNAME_CLAIM_URI), USER_ID);
    }

    @Test
    public void testExecuteInitialRequest() throws FlowEngineException {

        when(flowExecutionContext.getUserInputData()).thenReturn(null);

        mockStatic(UUID.class);
        UUID mockUUID = mock(UUID.class);
        when(UUID.randomUUID()).thenReturn(mockUUID);
        when(mockUUID.toString()).thenReturn("mocked-uuid");

        ExecutorResponse response = executor.execute(flowExecutionContext);

        Assert.assertNotNull(response);
        Assert.assertEquals(response.getResult(), STATUS_EXTERNAL_REDIRECTION);
        Assert.assertTrue(response.getRequiredData().contains(OAUTH2_GRANT_TYPE_CODE));
        Assert.assertTrue(response.getRequiredData().contains(OAUTH2_PARAM_STATE));
        Assert.assertTrue(response.getContextProperties().containsKey(OAUTH2_PARAM_STATE));
        Assert.assertTrue(response.getAdditionalInfo().containsKey(OAUTH2_PARAM_STATE));
        Assert.assertTrue(response.getAdditionalInfo().containsKey(REDIRECT_URL));
    }

    @Test(expectedExceptions = FlowEngineException.class)
    public void testExecuteStateMismatch() throws FlowEngineException {

        Map<String, String> userInputs = new HashMap<>();
        userInputs.put(OAUTH2_GRANT_TYPE_CODE, CODE);
        userInputs.put(OAUTH2_PARAM_STATE, STATE);
        when(flowExecutionContext.getUserInputData()).thenReturn(userInputs);
        when(flowExecutionContext.getProperty(OAUTH2_PARAM_STATE)).thenReturn("different-state");
        executor.execute(flowExecutionContext);
    }

    @Test
    public void testGetAuthenticateUser() {

        Map<String, Object> oidcClaims = new HashMap<>();
        oidcClaims.put(OIDCAuthenticatorConstants.Claim.SUB, USER_ID);
        String userId = executor.getAuthenticatedUserIdentifier(oidcClaims);
        Assert.assertEquals(userId, USER_ID);
    }

    @Test
    public void testGetAccessTokenRequest() throws Exception {

        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, CLIENT_ID);
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, CLIENT_SECRET);
        authProperties.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, TOKEN_ENDPOINT);

        OAuthClientRequest request = executor.getAccessTokenRequest(authProperties, CODE, REGISTRATION_PORTAL_URL);

        Assert.assertNotNull(request);
        Assert.assertEquals(request.getLocationUri(), TOKEN_ENDPOINT);
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
    public void testRequestAccessToken() throws Exception {

        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, CLIENT_ID);
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, CLIENT_SECRET);
        authProperties.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, TOKEN_ENDPOINT);
        when(flowExecutionContext.getAuthenticatorProperties()).thenReturn(authProperties);

        whenNew(URLConnectionClient.class).withNoArguments().thenReturn(mock(URLConnectionClient.class));
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(oAuthClient);
        when(oAuthClient.accessToken(any(OAuthClientRequest.class))).thenReturn(oAuthClientResponse);
        OAuthClientResponse response = executor.requestAccessToken(flowExecutionContext, CODE);
        Assert.assertNotNull(response);
    }

    @Test(expectedExceptions = FlowEngineException.class)
    public void testRequestAccessTokenWithException() throws Exception {

        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, CLIENT_ID);
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, CLIENT_SECRET);
        authProperties.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, TOKEN_ENDPOINT);
        when(flowExecutionContext.getAuthenticatorProperties()).thenReturn(authProperties);

        whenNew(URLConnectionClient.class).withNoArguments().thenReturn(mock(URLConnectionClient.class));
        whenNew(OAuthClient.class).withAnyArguments().thenReturn(oAuthClient);
        when(oAuthClient.accessToken(any(OAuthClientRequest.class)))
                .thenThrow(new OAuthSystemException("Test exception"));

        executor.requestAccessToken(flowExecutionContext, CODE);
    }

    @Test
    public void testGetAccessTokenRequestWithBasicAuth() throws Exception {

        Map<String, String> authProperties = new HashMap<>();
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, CLIENT_ID);
        authProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, CLIENT_SECRET);
        authProperties.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, TOKEN_ENDPOINT);
        authProperties.put(OIDCAuthenticatorConstants.IS_BASIC_AUTH_ENABLED, "true");

        OAuthClientRequest request = executor.getAccessTokenRequest(authProperties, CODE, REGISTRATION_PORTAL_URL);

        Assert.assertNotNull(request);
        Assert.assertEquals(request.getLocationUri(), TOKEN_ENDPOINT);
        Assert.assertNotNull(request.getHeaders().get("Authorization"));
        Assert.assertTrue(request.getHeaders().get("Authorization").toString().startsWith("Basic "));
    }
}
