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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import junit.awtui.Logo;
import net.minidev.json.JSONObject;
import org.mockito.Mock;
import org.mockito.Mockito;
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
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import static org.powermock.api.support.membermodification.MemberMatcher.method;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import static org.powermock.api.mockito.PowerMockito.when;

public class FederatedIdpInitLogoutProcessorTest extends PowerMockTestCase {

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
    private FederatedIdpInitLogoutProcessor mockLogoutProcessor;

    FederatedIdpInitLogoutProcessor logoutProcessor;
    Property[] properties;
    FederatedAuthenticatorConfig federatedAuthenticatorConfig;
    IdentityProvider identityProvider;

    private static String BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openidnet/event/backchannel-logout";
    private static String TENANT_DOMAIN = "carbon.super";
    private static String SIGNATURE_ALGORITHM = "SHA256withRSA";

//    private static String logoutToken =
//            "eyJ4NXQiOiJPV0psWmpJME5qSTROR0ZpTVRBNU9UZ3dPR00xTTJJeE5UWmpNekk0TldJeE5EY3dOMkV5TVRNNE5HWmlaVGxoTXpJMFl6a" +
//                    "GpaRFJrWXpoaVl6ZGhPQSIsImtpZCI6Ik9XSmxaakkwTmpJNE5HRmlNVEE1T1Rnd09HTTFNMkl4TlRaak16STROV0l4TkRjd0" +
//                    "4yRXlNVE00TkdaaVpUbGhNekkwWXpoalpEUmtZemhpWXpkaE9BX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJhZG1p" +
//                    "biIsImF1ZCI6IndfSHdwMDVkRlJ3Y1JzX1dGSHY5U053cGZsQWEiLCJpc3MiOiJodHRwczpcL1wvZmVkZXJhdGVkd3NvMi5jb" +
//                    "206OTQ0NFwvb2F1dGgyXC90b2tlbiIsImV4cCI6MTYwOTkxMTk4OCwiaWF0IjoxNjA5OTExODY4LCJqdGkiOiIxNjE1OWUzZS" +
//                    "1jNWZjLTQyZGUtYjkzZi1iMDc4MmFiMzNkNTgiLCJldmVudHMiOnsiaHR0cDpcL1wvc2NoZW1hcy5vcGVuaWRuZXRcL2V2ZW5" +
//                    "0XC9iYWNrY2hhbm5lbC1sb2dvdXQiOnt9fSwic2lkIjoiMTUwNDNmZmMtODc3ZC00MjA1LWFmNDEtOWIxMDdmN2RhMzhjIn0." +
//                    "MG1DbKb4OOMKJ4eIt9FXi8EsppaZgw-PSTmXTD2_ZmGSyApR723J3LZBpsx9StqMzJBJAlXHp9EjFOSeriZv21TIu9zuxHPpK" +
//                    "qEwECJZb21R1Fyeb74O-HEZ0gET3RsuvoIhJk9mXjs7Jcqw0VFfev2bwUSbla5WwwFj3ds7-G31aDew0SDJImiO7MwGdVuQXq" +
//                    "EKgyYA0-FHSbFNRtk3-rN25biW3ivU5AWeo9W3dI6epcNSr4pCCvWBIKI-rk01J8kYyu2ZujecyD0yoz420lbZ2c_dMKFpCDH" +
//                    "DdYjueK4tYE66jpAzvJEyPs37snH-6ok2YaoYjKudyfCdXni7Bg";

    @BeforeTest
    public void init() {

        logoutProcessor = new FederatedIdpInitLogoutProcessor();
        FileBasedConfigurationBuilder.getInstance(TestUtils.getFilePath("application-authentication.xml"));
        setupIdP();

    }

    private void setupIdP() {

        identityProvider = new IdentityProvider();
        identityProvider.setIdentityProviderName("Federated-IdP");
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[1];
        IdentityProviderProperty issuerProperty = new IdentityProviderProperty();
        issuerProperty.setName("idpIssuerName");
        issuerProperty.setValue("https://federatedwso2.com:9444/oauth2/token");
        identityProviderProperties[0] = issuerProperty;
        identityProvider.setCertificate("Owner: CN=federatedwso2.com, OU=is, O=wso2, L=colombo, ST=western, C=SL\n" +
                "Issuer: CN=federatedwso2.com, OU=is, O=wso2, L=colombo, ST=western, C=SL\n" +
                "Serial number: 2b09b96b\n" +
                "Valid from: Tue Dec 15 15:45:03 IST 2020 until: Mon Mar 15 15:45:03 IST 2021\n" +
                "Certificate fingerprints:\n" +
                "\t SHA1: B7:08:30:1A:9F:B1:C1:4C:13:BD:6D:38:35:C4:21:35:E4:C6:27:F6\n" +
                "\t SHA256: 9B:EF:24:62:84:AB:10:99:80:8C:53:B1:56:C3:28:5B:14:70:7A:21:38:4F:BE:9A:32:4C:8C:D4:DC:8B:C7:A8\n" +
                "Signature algorithm name: SHA256withRSA\n" +
                "Subject Public Key Algorithm: 2048-bit RSA key\n" +
                "Version: 3\n" +
                "\n" +
                "Extensions: \n" +
                "\n" +
                "#1: ObjectId: 2.5.29.14 Criticality=false\n" +
                "SubjectKeyIdentifier [\n" +
                "KeyIdentifier [\n" +
                "0000: 5D E9 37 60 3C 1D 4E 93   3C 0E 9B 6F FA 1C F7 B2  ].7`<.N.<..o....\n" +
                "0010: A0 CE 24 3E                                        ..$>\n" +
                "]\n");
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
                {BACKCHANNEL_LOGOUT_EVENT, "{}", "true"},
                {BACKCHANNEL_LOGOUT_EVENT, "{safbf}", "false"},
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

//    private JWTClaimsSet generateLogoutToken() throws IdentityOAuth2Exception {
//
//        String sub = "admin";
//        String jti = UUID.randomUUID().toString();
//        String iss = "https://federatedwso2.com:9444/oauth2/token";
//        List<String> audience = Arrays.asList("w_Hwp05dFRwcRs_WFHv9SNwpflAa");
//        long logoutTokenValidityInMillis = 2 * 60 * 1000;
//        long currentTimeInMillis = Calendar.getInstance().getTimeInMillis();
//        Date iat = new Date(currentTimeInMillis);
//        String sid = "15043ffc-877d-4205-af41-9b107f7da38c";
//        JSONObject event = new JSONObject().appendField(BACKCHANNEL_LOGOUT_EVENT,
//                new JSONObject());
//
//        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
//        jwtClaimsSetBuilder.subject(sub);
//        jwtClaimsSetBuilder.issuer(iss);
//        jwtClaimsSetBuilder.audience(audience);
//        jwtClaimsSetBuilder.claim("jti", jti);
//        jwtClaimsSetBuilder.claim("events", event);
//        jwtClaimsSetBuilder.expirationTime(new Date(currentTimeInMillis + logoutTokenValidityInMillis));
//        jwtClaimsSetBuilder.claim("iat", iat);
//        jwtClaimsSetBuilder.claim("sid", sid);
//
//        return jwtClaimsSetBuilder.build();
//    }
//
//    @Test
//    public void testOidcFederatedLogout() throws Exception {
//
//        Map<String, String> sessionDetails = new HashMap<String, String>();
//        sessionDetails.put("sessionId", "SessionId");
//        when(mockSessionInfoDAO.getSessionDetails("sId")).thenReturn(sessionDetails);
//        when(mockSessionManagementService.removeSession("SessionId")).thenReturn(true);
//        LogoutContext logoutContext = new LogoutContext(mockLogoutRequest);
//        JWTClaimsSet jwtClaimsSet = generateLogoutToken();
//        String logoutToken = OAuth2Util.signJWT(jwtClaimsSet, JWSAlgorithm.parse(SIGNATURE_ALGORITHM),
//                TENANT_DOMAIN).serialize();
//        when(mockLogoutRequest.getParameter("logout_token")).thenReturn(logoutToken);
//        when(mockLogoutRequest.getTenantDomain()).thenReturn("carbon.super");
//
//
//
////        when(mockLogoutProcessor.getIdentityProvider(Mockito.anyString(), Mockito.anyString()))
////                .thenReturn(identityProvider);
////        when(mockLogoutProcessor.validateIat(new Date())).thenReturn(true);
////        LogoutProcessor spyLogoutProcessor = PowerMockito.spy(logoutProcessor);
////        PowerMockito.doReturn(identityProvider)
////                .when(spyLogoutProcessor, "getIdentityProvider", "https://federatedwso2.com:9444/oauth2/token",
////                        "carbon.super");
//
////        PowerMockito.doReturn(true).when(spyLogoutProcessor, "validateAud", null, null);
////        assertNotNull(logoutProcessor.oidcFederatedLogout(logoutContext));
//        assertTrue(true);
//    }

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
