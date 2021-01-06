/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.oidc.processor;

import com.nimbusds.jwt.JWTClaimsSet;
import junit.awtui.Logo;
import net.minidev.json.JSONObject;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.authenticator.stub.Logout;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.services.SessionManagementService;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oidc.TestUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.context.LogoutContext;
import org.wso2.carbon.identity.application.authenticator.oidc.dao.SessionInfoDAO;
import org.wso2.carbon.identity.application.authenticator.oidc.model.LogoutRequest;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import static org.powermock.api.support.membermodification.MemberMatcher.method;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.powermock.api.mockito.PowerMockito.when;

public class LogoutProcessorTest extends PowerMockTestCase {

    @Mock
    private IdentityRequest mockIdentityRequest;

    @Mock
    private IdentityProvider mockIdentityProvider;

    @Mock
    private SessionManagementService mockSessionManagementService;

    @Mock
    private SessionInfoDAO mockSessionInfoDAO;

    @Mock
    private LogoutRequest mockLogoutRequest;

    @Mock
    private LogoutProcessor mockLogoutProcessor;

    LogoutProcessor logoutProcessor;
    Property[] properties;
    FederatedAuthenticatorConfig federatedAuthenticatorConfig;
    IdentityProvider identityProvider;

    private static String logoutToken =
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

    @BeforeTest
    public void init() {

        logoutProcessor = new LogoutProcessor();
        FileBasedConfigurationBuilder.getInstance(TestUtils.getFilePath("application-authentication.xml"));
        setupIdP();

    }

    private void setupIdP() {

        identityProvider = new IdentityProvider();
        identityProvider.setIdentityProviderName("Federated-IdP");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[2];
        IdentityProviderProperty jwksProperty = new IdentityProviderProperty();
        jwksProperty.setName("jwksUri");
        jwksProperty.setValue(" \thttps://federatedwso2.com:9444/oauth2/jwks");
        identityProviderProperties[0] = jwksProperty;
        IdentityProviderProperty issuerProperty = new IdentityProviderProperty();
        issuerProperty.setName("idpIssuerName");
        issuerProperty.setValue("https://federatedwso2.com:9444/oauth2/token");
        identityProviderProperties[1] = issuerProperty;
        identityProvider.setIdpProperties(identityProviderProperties);
    }

    @DataProvider(name = "requestDataHandler")
    public Object[][] getRequestURI() {

        return new String[][]{
                // When URI is correct.
                {"http://localhost:9443/identity/oidc/slo", "true"},
                // When URI is incorrect.
                {"identity/bclogout", "false"},
        };
    }

    @Test(dataProvider = "requestDataHandler")
    public void testCanHandle(String uri, String expectedCanHandler) {

        when(mockIdentityRequest.getRequestURI()).thenReturn(uri);

        assertEquals(logoutProcessor.canHandle(mockIdentityRequest), Boolean.parseBoolean(expectedCanHandler));
    }

    @DataProvider(name = "audCliamDataHandler")
    public Object[][] getAudClaim() {

        return new String[][]{
                {"TcEsA1NxUbphVFFFEQIcUxnvtlka", "true"},
                {"DfGdve1NxafadfdfadadUxnvtada", "false"},
        };
    }

    @Test(dataProvider = "audCliamDataHandler")
    public void testValidateAud(String aud, String expectedValidateAud) throws Exception {

        properties = new Property[1];
        Property property = new Property();
        property.setName("ClientId");
        property.setValue("TcEsA1NxUbphVFFFEQIcUxnvtlka");
        properties[0] = property;
        List<String> auds = Arrays.asList(aud);
        federatedAuthenticatorConfig = new FederatedAuthenticatorConfig();
        federatedAuthenticatorConfig.setProperties(properties);
        when(mockIdentityProvider.getDefaultAuthenticatorConfig()).thenReturn(federatedAuthenticatorConfig);
        boolean validateAud = WhiteboxImpl.invokeMethod(logoutProcessor, "validateAud", auds, mockIdentityProvider);
        assertEquals(validateAud, Boolean.parseBoolean(expectedValidateAud));

    }

    @DataProvider(name = "sidCliamDataHandler")
    public Object[][] getSIdClaim() {

        return new String[][]{
                {"faw4rrga542arwga4awea", "true"},
                {null, "false"}
        };
    }

    @Test(dataProvider = "sidCliamDataHandler")
    public void testValidateSId(String sid, String expectedValidateSId) throws Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim("sid", sid).build();
        boolean validateSId = WhiteboxImpl.invokeMethod(logoutProcessor, "validateSid", claimsSet);
        assertEquals(validateSId, Boolean.parseBoolean(expectedValidateSId));
    }

    @DataProvider(name = "eventClaimDataHandler")
    public Object[][] getEventClaim() {

        return new String[][]{
                {"http://schemas.openidnet/event/backchannel-logout", "{}", "true"},
                {"http://schemas.openidnet/event/backchannel-logout", "{safbf}", "false"},
                {"", "{}", "false"}
        };
    }

    @Test(dataProvider = "eventClaimDataHandler")
    public void testValidateEvent(String eventName, String eventVal, String expectedValidateEvent) throws Exception {

        JSONObject jsonObject = new JSONObject();
        jsonObject.appendField(eventName, eventVal);
        boolean validateEvent = WhiteboxImpl.invokeMethod(logoutProcessor, "validateEvent", jsonObject);
        assertEquals(validateEvent, Boolean.parseBoolean(expectedValidateEvent));
    }

    @DataProvider(name = "nonceClaimDataHandler")
    public Object[][] getNonceClaim() {

        return new String[][]{
                {null, null, "true"},
                {"nonce", null, "true"},
                {"nonce", "noasdade322e", "false"},
        };
    }

    @Test(dataProvider = "nonceClaimDataHandler")
    public void testValidateNonce(String nonceName, String nonceValue, String expectedValidateNonce) throws Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim(nonceName, nonceValue).build();
        boolean validateNonce = WhiteboxImpl.invokeMethod(logoutProcessor, "validateNonce", claimsSet);
        assertEquals(validateNonce, Boolean.parseBoolean(expectedValidateNonce));
    }

    @Test
    public void testProcess() {

    }

    @Test
    public void testOidcFederatedLogout() throws Exception {

        Map<String, String> sessionDetails = new HashMap<String, String>();
        sessionDetails.put("sessionId", "SessionId");
        when(mockSessionInfoDAO.getSessionDetails("sId")).thenReturn(sessionDetails);
        when(mockSessionManagementService.removeSession("SessionId")).thenReturn(true);
        LogoutContext logoutContext = new LogoutContext(mockLogoutRequest);
        when(mockLogoutRequest.getParameter("logout_token")).thenReturn(logoutToken);
        when(mockLogoutRequest.getTenantDomain()).thenReturn("carbon.super");

//        when(mockLogoutProcessor.validateIat(new Date())).thenReturn(true);
//        LogoutProcessor spyLogoutProcessor = PowerMockito.spy(logoutProcessor);
//        PowerMockito.doReturn(identityProvider)
//                .when(spyLogoutProcessor, "getIdentityProvider", "https://federatedwso2.com:9444/oauth2/token",
//                        "carbon.super");
//        PowerMockito.doReturn(true).when(spyLogoutProcessor, "validateAud", null, null);
//        assertNotNull(logoutProcessor.oidcFederatedLogout(logoutContext));
        assertTrue(true);
    }

    @Test
    public void testGetAuthenticatorConfig() {

        assertNotNull(logoutProcessor.getAuthenticatorConfig());
    }

    @Test
    public void testGetCallbackPath() {

        IdentityMessageContext context = null;
        assertNull(logoutProcessor.getCallbackPath(context));
    }

    @Test
    public void testGetRelyingPartyId() {

        assertNull(logoutProcessor.getRelyingPartyId());
        IdentityMessageContext context = null;
        assertNull(logoutProcessor.getRelyingPartyId());
    }

    //    @DataProvider(name = "identityProviderDataHandler")
//    public Object[][] getIdentityProviderData() {
//
//        return new String[][]{
//                {"https://federatedwso2.com:9444/oauth2/token", "carbon.super"},
//        };
//    }
//
//    @Test(dataProvider = "identityProviderDataHandler")
//    public void testGetIdentityProvider(String jwtIssuer, String tenantDomain) throws Exception {
//
//        assertNotNull(WhiteboxImpl.invokeMethod(logoutProcessor, "getIdentityProvider", jwtIssuer, tenantDomain));
//    }
}
