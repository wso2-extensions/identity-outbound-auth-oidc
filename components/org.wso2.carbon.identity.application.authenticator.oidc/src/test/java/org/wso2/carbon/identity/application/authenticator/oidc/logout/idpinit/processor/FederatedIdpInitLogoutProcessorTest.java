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

package org.wso2.carbon.identity.application.authenticator.oidc.logout.idpinit.processor;

import com.ctc.wstx.stax.WstxInputFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.ServerSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.TestUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.internal.OpenIDConnectAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.oidc.logout.idpinit.exception.LogoutClientException;
import org.wso2.carbon.identity.application.authenticator.oidc.logout.idpinit.model.LogoutRequest;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.JWTSignatureValidationUtils;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.sql.DataSource;
import javax.xml.stream.XMLInputFactory;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_AUD_CLAIM_VALIDATION_FAILED;

/**
 * Unit test class for FederatedIdpInitLogoutProcessor.
 */
@PrepareForTest({SignedJWT.class, IdentityProviderManager.class, JWTSignatureValidationUtils.class,
        IdentityDatabaseUtil.class, FrameworkUtils.class, XMLInputFactory.class, DataSource.class,
        UserSessionManagementService.class, OpenIDConnectAuthenticatorDataHolder.class, IdentityTenantUtil.class,
        UserSessionStore.class, ServerSessionManagementService.class})
@PowerMockIgnore({"jdk.internal.reflect.*"})
@WithH2Database(files = {"dbscripts/h2.sql"})
public class FederatedIdpInitLogoutProcessorTest extends PowerMockTestCase {

    @Mock
    private IdentityRequest mockIdentityRequest;

    @Mock
    private IdentityProvider mockIdentityProvider;

    @Mock
    private LogoutRequest mockLogoutRequest;

    FederatedIdpInitLogoutProcessor logoutProcessor;
    Property[] properties;
    FederatedAuthenticatorConfig federatedAuthenticatorConfig;
    IdentityProvider identityProvider;

    private static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();
    private static final String DB_NAME = "testOIDCSLO";
    private static final String BACK_CHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";
    private static final String logoutToken =
            "eyJ4NXQiOiJPV0psWmpJME5qSTROR0ZpTVRBNU9UZ3dPR00xTTJJeE5UWmpNekk0TldJeE5EY3dOMkV5TVRNNE5HWmlaVGxoTXpJMFl6a" +
                    "GpaRFJrWXpoaVl6ZGhPQSIsImtpZCI6Ik9XSmxaakkwTmpJNE5HRmlNVEE1T1Rnd09HTTFNMkl4TlRaak16STROV0l4TkRjd0" +
                    "4yRXlNVE00TkdaaVpUbGhNekkwWXpoalpEUmtZemhpWXpkaE9BX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJhZG1p" +
                    "biIsImF1ZCI6IndfSHdwMDVkRlJ3Y1JzX1dGSHY5U053cGZsQWEiLCJpc3MiOiJodHRwczpcL1wvZmVkZXJhdGVkd3NvMi5jb" +
                    "206OTQ0NFwvb2F1dGgyXC90b2tlbiIsImV4cCI6MTYwOTkxMTk4OCwiaWF0IjoxNjA5OTExODY4LCJqdGkiOiIxNjE1OWUzZS" +
                    "1jNWZjLTQyZGUtYjkzZi1iMDc4MmFiMzNkNTgiLCJldmVudHMiOnsiaHR0cDpcL1wvc2NoZW1hcy5vcGVuaWRuZXRcL2V2ZW5" +
                    "0XC9iYWNrY2hhbm5lbC1sb2dvdXQiOnt9fSwic2lkIjoiMTUwNDNmZmMtODc3ZC00MjA1LWFmNDEtOWIxMDdmN2RhMzhjIn0." +
                    "MG1DbKb4OOMKJ4eIt9FXi8EsppaZgw-PSTmXTD2_ZmGSyApR723J3LZBpsx9StqMzJBJAlXHp9EjFOSeriZv21TIu9zuxHPpK" +
                    "qEwECJZb21R1Fyeb74O-HEZ0gET3RsuvoIhJk9mXjs7Jcqw0VFfev2bwUSbla5WwwFj3ds7-G31aDew0SDJImiO7MwGdVuQXq" +
                    "EKgyYA0-FHSbFNRtk3-rN25biW3ivU5AWeo9W3dI6epcNSr4pCCvWBIKI-rk01J8kYyu2ZujecyD0yoz420lbZ2c_dMKFpCDH" +
                    "DdYjueK4tYE66jpAzvJEyPs37snH-6ok2YaoYjKudyfCdXni7Bg";

    @BeforeMethod
    public void init() throws Exception {

        logoutProcessor = new FederatedIdpInitLogoutProcessor();
        mockStatic(XMLInputFactory.class);
        when(XMLInputFactory.newInstance()).thenReturn(new WstxInputFactory());
        FileBasedConfigurationBuilder.getInstance(TestUtils.getFilePath("application-authentication.xml"));
        setupIdP();
    }

    @DataProvider(name = "requestDataHandler")
    public Object[][] getRequestURI() {

        return new String[][]{
                // When URI is correct.
                {"http://localhost:9443/identity/oidc/slo", "true"},
                {"http://localhost:9443/t/federated.com/identity/oidc/slo", "true"},
                // When URI is incorrect.
                {"identity/bclogout", "false"},
        };
    }

    @Test(dataProvider = "requestDataHandler")
    public void testCanHandle(String uri, String expectedCanHandlerValue) {

        when(mockIdentityRequest.getRequestURI()).thenReturn(uri);

        assertEquals(logoutProcessor.canHandle(mockIdentityRequest), Boolean.parseBoolean(expectedCanHandlerValue));
    }

    @Test()
    public void testValidAudClaim() throws Exception {

        properties = new Property[1];
        Property property = new Property();
        property.setName("ClientId");
        property.setValue("TcEsA1NxUbphVFFFEQIcUxnvtlka");
        properties[0] = property;
        List<String> auds = Arrays.asList("TcEsA1NxUbphVFFFEQIcUxnvtlka");
        federatedAuthenticatorConfig = new FederatedAuthenticatorConfig();
        federatedAuthenticatorConfig.setProperties(properties);
        when(mockIdentityProvider.getDefaultAuthenticatorConfig()).thenReturn(federatedAuthenticatorConfig);
        try {
            WhiteboxImpl.invokeMethod(logoutProcessor, "validateAudience", auds,
                    mockIdentityProvider);
        } catch (LogoutClientException e) {
            fail();
        }
    }

    @Test()
    public void testInvalidateAud() throws Exception {

        properties = new Property[1];
        Property property = new Property();
        property.setName("ClientId");
        property.setValue("TcEsA1NxUbphVFFFEQIcUxnvtlka");
        properties[0] = property;
        List<String> auds = Arrays.asList("DfGdve1NxafadfdfadadUxnvtada");
        federatedAuthenticatorConfig = new FederatedAuthenticatorConfig();
        federatedAuthenticatorConfig.setProperties(properties);
        when(mockIdentityProvider.getDefaultAuthenticatorConfig()).thenReturn(federatedAuthenticatorConfig);
        try {
            WhiteboxImpl.invokeMethod(logoutProcessor, "validateAudience", auds,
                    mockIdentityProvider);
            fail();
        } catch (LogoutClientException e) {
            assertEquals(e.getMessage(), LOGOUT_TOKEN_AUD_CLAIM_VALIDATION_FAILED.getMessage());
        }
    }

    @DataProvider(name = "sidCliamDataHandler")
    public Object[][] getSidClaim() {

        return new String[][]{
                {"faw4rrga542arwga4awea", "true"},
                {null, "false"}
        };
    }

    @Test(dataProvider = "sidCliamDataHandler")
    public void testValidateSid(String sid, String expectedValidateSId) throws Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim("sid", sid).build();
        boolean validateSId = WhiteboxImpl.invokeMethod(logoutProcessor, "isSidClaimExists", claimsSet);
        assertEquals(validateSId, Boolean.parseBoolean(expectedValidateSId));
    }

    @DataProvider(name = "subCliamDataHandler")
    public Object[][] getSubClaim() {

        return new String[][]{
                {"faw4rrga542arwga4awea", "true"},
                {null, "false"}
        };
    }

    @Test(dataProvider = "sidCliamDataHandler")
    public void testValidateSub(String sub, String expectedValidateSId) throws Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim("sub", sub).build();
        boolean validateSub = WhiteboxImpl.invokeMethod(logoutProcessor, "isSubClaimExists", claimsSet);
        assertEquals(validateSub, Boolean.parseBoolean(expectedValidateSId));
    }

    @DataProvider(name = "eventClaimDataHandler")
    public Object[][] getEventClaim() {

        return new String[][]{
                {BACK_CHANNEL_LOGOUT_EVENT, "{}"},
                {BACK_CHANNEL_LOGOUT_EVENT, "{safbf}"},
                {"", "{}"}
        };
    }

    @Test(dataProvider = "eventClaimDataHandler")
    public void testValidateEvent(String eventName, String eventVal) throws Exception {

        JSONObject jsonObject = new JSONObject();
        jsonObject.appendField(eventName, eventVal);
        try {
            WhiteboxImpl.invokeMethod(logoutProcessor, "validateEventClaim", jsonObject);
            assertTrue(true);
        } catch (LogoutClientException e) {
            assertEquals(e.getMessage(),
                    OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_EVENT_CLAIM_VALIDATION_FAILED.getMessage());
        }

    }

    @DataProvider(name = "validNonceClaimDataHandler")
    public Object[][] getValidNonceClaimData() {

        return new String[][]{
                {null, null},
                {"nonce", null},
        };
    }

    @Test(dataProvider = "validNonceClaimDataHandler")
    public void testValidNonce(String nonceName, String nonceValue) throws Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim(nonceName, nonceValue).build();
        try {
            WhiteboxImpl.invokeMethod(logoutProcessor, "validateNonce", claimsSet);
        } catch (LogoutClientException e) {
            fail();
        }
    }

    @Test()
    public void testInvalidNonce() throws Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim("nonce", "zdfatedf4t").build();
        try {
            WhiteboxImpl.invokeMethod(logoutProcessor, "validateNonce", claimsSet);
            fail();
        } catch (LogoutClientException e) {
            assertEquals(e.getMessage(),
                    OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_NONCE_CLAIM_VALIDATION_FAILED.getMessage());
        }
    }

    @Test()
    public void testValidIat() throws Exception {

        try {
            WhiteboxImpl.invokeMethod(logoutProcessor, "validateIat",
                    new Date());
        } catch (LogoutClientException e) {
            fail();
        }
    }

    @Test()
    public void testInvalidIat() throws Exception {

        try {
            Date currentDate = new Date();
            Date pastTime = new Date(currentDate.getTime() - (40 * 60 * 1000));
            WhiteboxImpl.invokeMethod(logoutProcessor, "validateIat", pastTime);
            fail();
        } catch (LogoutClientException e) {
            assertEquals(e.getMessage(),
                    OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_IAT_VALIDATION_FAILED.getMessage());
        }
    }

    private void setupIdP() {

        identityProvider = new IdentityProvider();
        identityProvider.setIdentityProviderName("Federated-IdP");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        IdentityProviderProperty issuerProperty = new IdentityProviderProperty();
        issuerProperty.setName("idpIssuerName");
        issuerProperty.setValue("https://federatedwso2.com:9444/oauth2/token");
        identityProviderProperties[0] = issuerProperty;
        FederatedAuthenticatorConfig federatedAuthenticatorConfig = new FederatedAuthenticatorConfig();
        Property[] properties = new Property[1];
        Property property = new Property();
        property.setName("ClientId");
        property.setValue("w_Hwp05dFRwcRs_WFHv9SNwpflAa");
        properties[0] = property;
        federatedAuthenticatorConfig.setProperties(properties);
        identityProvider.setDefaultAuthenticatorConfig(federatedAuthenticatorConfig);
        identityProvider.setIdpProperties(identityProviderProperties);
        identityProvider.setId("1");
    }

    private void initiateH2Base(String databaseName, String scriptPath) throws Exception {

        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test" + databaseName);
        try (Connection connection = dataSource.getConnection()) {
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + scriptPath + "'");
        }
        dataSourceMap.put(databaseName, dataSource);
    }

    private static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dbscripts", fileName)
                    .toString();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }

    private static Connection getConnection(String database) throws SQLException {

        if (dataSourceMap.get(database) != null) {
            return dataSourceMap.get(database).getConnection();
        }
        throw new RuntimeException("No datasource initiated for database: " + database);
    }

    private void prepareConnection(Connection connection1, boolean b) {

        mockStatic(IdentityDatabaseUtil.class);
        PowerMockito.when(IdentityDatabaseUtil.getDBConnection(b)).thenReturn(connection1);
    }

    private void setupSessionStore(String USER_ID, String USER_NAME, String SESSION_CONTEXT_KEY,
                                   String IDP_SESSION_INDEX) throws Exception {

        initiateH2Base(DB_NAME, getFilePath("h2.sql"));

        String IDP_NAME = "Federated-IdP";
        String AUTHENTICATOR_ID = "OpenIDConnectAuthenticator";
        String PROTOCOL_TYPE = "oidc";

        int TENANT_ID = -1234;
        String DOMAIN_NAME = "FEDERATED";
        int IDP_ID = 1;

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, false);

            String sql = "INSERT INTO IDN_FED_AUTH_SESSION_MAPPING " +
                    "(IDP_SESSION_ID, SESSION_ID, IDP_NAME,  AUTHENTICATOR_ID, PROTOCOL_TYPE) VALUES ( '" +
                    IDP_SESSION_INDEX + "' , '" + SESSION_CONTEXT_KEY + "' , '" + IDP_NAME + "' , '" +
                    AUTHENTICATOR_ID +
                    "', '" + PROTOCOL_TYPE + "');";

            String sql2 =
                    "INSERT INTO IDN_AUTH_USER (USER_ID,USER_NAME,TENANT_ID,DOMAIN_NAME,IDP_ID) VALUES ('" + USER_ID +
                            "','" + USER_NAME + "','" + TENANT_ID + "','" + DOMAIN_NAME + "','" + IDP_ID + "');";

            PreparedStatement statement = connection1.prepareStatement(sql);
            PreparedStatement statement2 = connection1.prepareStatement(sql2);
            statement.execute();
            statement2.execute();
        }

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, false);
            String query = "SELECT * FROM IDN_FED_AUTH_SESSION_MAPPING WHERE IDP_SESSION_ID=?";
            PreparedStatement statement1 = connection1.prepareStatement(query);
            statement1.setString(1, IDP_SESSION_INDEX);
            ResultSet resultSet1 = statement1.executeQuery();
            String result1 = null;
            if (resultSet1.next()) {
                result1 = resultSet1.getString("SESSION_ID");
            }
            assertEquals(SESSION_CONTEXT_KEY, result1, "Failed add auth session mapping into " +
                    "IDN_FED_AUTH_SESSION_MAPPING table.");

            String query2 = "SELECT * FROM IDN_AUTH_USER WHERE USER_NAME=?";
            PreparedStatement statement2 = connection1.prepareStatement(query2);
            statement2.setString(1, USER_NAME);
            ResultSet resultSet2 = statement2.executeQuery();
            String result2 = null;
            if (resultSet2.next()) {
                result2 = resultSet2.getString("USER_ID");
            }
            assertEquals(USER_ID, result2, "Failed add user info into " +
                    "IDN_AUTH_USER table.");
        }

    }

    private JWTClaimsSet generateLogoutToken(String sub, boolean sidExists, String sid) throws IdentityOAuth2Exception {

        String jti = UUID.randomUUID().toString();
        String iss = "https://federatedwso2.com:9444/oauth2/token";
        List<String> audience = Arrays.asList("w_Hwp05dFRwcRs_WFHv9SNwpflAa");
        long logoutTokenValidityInMillis = 2 * 60 * 1000;
        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();
        Date iat = new Date(currentTimeInMillis);
        JSONObject event = new JSONObject().appendField(BACK_CHANNEL_LOGOUT_EVENT,
                new JSONObject());

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.subject(sub);
        jwtClaimsSetBuilder.issuer(iss);
        jwtClaimsSetBuilder.audience(audience);
        jwtClaimsSetBuilder.claim("jti", jti);
        jwtClaimsSetBuilder.claim("events", event);
        jwtClaimsSetBuilder.expirationTime(new Date(currentTimeInMillis + logoutTokenValidityInMillis));
        jwtClaimsSetBuilder.claim("iat", iat);
        if (sidExists) {
            jwtClaimsSetBuilder.claim("sid", sid);
        }
        return jwtClaimsSetBuilder.build();
    }

    @Test
    public void testOidcFederatedLogout() throws Exception {

        String USER_ID = UUID.randomUUID().toString();
        String USER_NAME = "adminSid";
        String SESSION_CONTEXT_KEY = "02278824dfe9862d265e389365c0a71c365401672491b78c6ee7dd6fc44d8af4";
        String IDP_SESSION_INDEX = "15043ffc-877d-4205-af41-9b107f7da38c";

        JWTClaimsSet jwtClaimsSet = generateLogoutToken(USER_NAME, true, IDP_SESSION_INDEX);

        // Mock the logout token and claims
        mockStatic(SignedJWT.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        when(SignedJWT.parse(logoutToken)).thenReturn(signedJWT);
        when(SignedJWT.parse(logoutToken).getJWTClaimsSet()).thenReturn(jwtClaimsSet);
        when(mockLogoutRequest.getParameter("logout_token")).thenReturn(logoutToken);
        when(mockLogoutRequest.getTenantDomain()).thenReturn("carbon.super");
        mockStatic(IdentityProviderManager.class);
        IdentityProviderManager identityProviderManager = mock(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(IdentityProviderManager.getInstance().getIdPByMetadataProperty(
                IdentityApplicationConstants.IDP_ISSUER_NAME, "https://federatedwso2.com:9444/oauth2/token",
                "carbon.super", false)).thenReturn(identityProvider);

        // Mock the signature validation
        mockStatic(JWTSignatureValidationUtils.class);
        when(JWTSignatureValidationUtils.validateSignature(signedJWT,
                identityProvider)).thenReturn(true);

        // Setup session store
        setupSessionStore(USER_ID, USER_NAME, SESSION_CONTEXT_KEY, IDP_SESSION_INDEX);
        DataSource dataSource = mock(DataSource.class);
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDataSource()).thenReturn(dataSource);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(getConnection(DB_NAME));
        when(dataSource.getConnection()).thenReturn(getConnection(DB_NAME));

        // Mock the server session management service.
        mockStatic(OpenIDConnectAuthenticatorDataHolder.class);
        OpenIDConnectAuthenticatorDataHolder openIDConnectAuthenticatorDataHolder =
                mock(OpenIDConnectAuthenticatorDataHolder.class);
        ServerSessionManagementService serverSessionManagementService = mock(ServerSessionManagementService.class);
        when(OpenIDConnectAuthenticatorDataHolder.getInstance()).thenReturn(openIDConnectAuthenticatorDataHolder);
        when(OpenIDConnectAuthenticatorDataHolder.getInstance().getServerSessionManagementService())
                .thenReturn(serverSessionManagementService);

        // Mock removeSession method.
        when(serverSessionManagementService.removeSession(SESSION_CONTEXT_KEY)).thenReturn(true);

        // Mock tenantID.
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

        assertNotNull(logoutProcessor.handleOIDCFederatedLogoutRequest(mockLogoutRequest));
    }

    @Test
    public void testOidcFederatedLogoutWithoutSid() throws Exception {

        String USER_ID = UUID.randomUUID().toString();
        String USER_NAME = "adminNoSid";
        String SESSION_CONTEXT_KEY = "02278824dfe9862d265e389365c0a71c365401672491b78c6ee7dd6fc44d9854";
        String IDP_SESSION_INDEX = "15043ffc-877d-4205-af41-9b107f7da39c";

        JWTClaimsSet jwtClaimsSet = generateLogoutToken(USER_NAME, false, IDP_SESSION_INDEX);

        // Mock the logout token and claims.
        mockStatic(SignedJWT.class);
        SignedJWT signedJWT = mock(SignedJWT.class);
        when(SignedJWT.parse(logoutToken)).thenReturn(signedJWT);
        when(SignedJWT.parse(logoutToken).getJWTClaimsSet()).thenReturn(jwtClaimsSet);
        when(mockLogoutRequest.getParameter("logout_token")).thenReturn(logoutToken);
        when(mockLogoutRequest.getTenantDomain()).thenReturn("carbon.super");
        mockStatic(IdentityProviderManager.class);
        IdentityProviderManager identityProviderManager = mock(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(IdentityProviderManager.getInstance().getIdPByMetadataProperty(
                IdentityApplicationConstants.IDP_ISSUER_NAME, "https://federatedwso2.com:9444/oauth2/token",
                "carbon.super", false)).thenReturn(identityProvider);

        // Mock the signature validation.
        mockStatic(JWTSignatureValidationUtils.class);
        when(JWTSignatureValidationUtils.validateSignature(signedJWT,
                identityProvider)).thenReturn(true);

        // Setup session store.
        setupSessionStore(USER_ID, USER_NAME, SESSION_CONTEXT_KEY, IDP_SESSION_INDEX);
        DataSource dataSource = mock(DataSource.class);
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDataSource()).thenReturn(dataSource);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(getConnection(DB_NAME));
        when(dataSource.getConnection()).thenReturn(getConnection(DB_NAME));

        // Mock the user session management service.
        UserSessionManagementService userSessionManagementService = mock(UserSessionManagementService.class);
        mockStatic(OpenIDConnectAuthenticatorDataHolder.class);
        OpenIDConnectAuthenticatorDataHolder openIDConnectAuthenticatorDataHolder =
                mock(OpenIDConnectAuthenticatorDataHolder.class);
        when(OpenIDConnectAuthenticatorDataHolder.getInstance()).thenReturn(openIDConnectAuthenticatorDataHolder);
        when(OpenIDConnectAuthenticatorDataHolder.getInstance().getUserSessionManagementService())
                .thenReturn(userSessionManagementService);

        // Mock terminateSessionBySessionId method.
        when(userSessionManagementService.terminateSessionBySessionId(USER_ID, SESSION_CONTEXT_KEY)).thenReturn(true);

        // Mock tenantID.
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

        assertNotNull(logoutProcessor.handleOIDCFederatedLogoutRequest(mockLogoutRequest));
    }
}
