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
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.authenticator.stub.Logout;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import static org.powermock.api.mockito.PowerMockito.when;

public class LogoutProcessorTest extends PowerMockTestCase {

    @Mock
    private IdentityRequest mockIdentityRequest;

    @Mock
    private IdentityProvider mockIdentityProvider;

    LogoutProcessor logoutProcessor;
    Property[] properties;
    FederatedAuthenticatorConfig federatedAuthenticatorConfig;
    IdentityProvider identityProvider;

    private static String logoutToken = "eyJ4NXQiOiJNell4TW1Ga09HWXdNV0kwWldObU5EY3hOR1l3WW1NNFpUQTNNV0kyTkRBelpHUX" +
            "pOR00wWkdSbE5qSmtPREZrWkRSaU9URmtNV0ZoTXpVMlpHVmxOZyIsImtpZCI6Ik16WXhNbUZrT0dZd01XSTBaV05tTkRjeE5HWXdZ" +
            "bU00WlRBM01XSTJOREF6WkdRek5HTTBaR1JsTmpKa09ERmtaRFJpT1RGa01XRmhNelUyWkdWbE5nX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ" +
            ".eyJzdWIiOiJhZG1pbiIsImF1ZCI6IlRjRXNBMU54VWJwaFZGRkZFUUljVXhudnRsa2EiLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob" +
            "3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJldmVudCI6e30sImV4cCI6MTYwODI3ODE5OSwiaWF0IjoxNjA4Mjc4MDc5LCJqdGkiOiJjZG" +
            "RmYTBkYS1lNzliLTQwOTUtYjI1YS0zZjM5ODRiNzhhOTAiLCJzaWQiOiIzMjlhYjhhNS00YmU2LTQxZDItOWEyNS1jMzljZWM4YjY4Mm" +
            "EifQ.hq4F3B1TF3ZkdCUYrbglxl7wXLZX2jlyebCftEHq4JPaTnS_52XVqJ_Xvdw8_bfqOwndAsb3E0pJFD28sAmipTnRnZxG4VRTfmY" +
            "xRyvOYgwdkcKxrxCUEHF_HuHj8g5KjvTCDLOfpTn5zyv2X-OUpSiHQ0Nd9JG_NybV7HYDiByTRi2VMSjMkUiasYXnbZ1EyJxacmijo0u" +
            "SDji5hDB4YyzUghZYA0gIOZyaqTuDPaYvDaTzKVF8gftC3Gx_EXe3eoTZu6Y5pYpzqDsf6BbqqUeD5qHXOEhG5l0uk7IsPSn6MH0hPU8" +
            "ax13M0B_5j80SJ0fRy5ZmMOr2cHeVL5aseA";

    @BeforeTest
    public void init() {

        logoutProcessor = new LogoutProcessor();

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

    private void setupIdP() {

        identityProvider.setIdentityProviderName("Federated-IdP");
        properties = new Property[5];
        federatedAuthenticatorConfig = new FederatedAuthenticatorConfig();
        properties[0].setName("ClientId");
        properties[0].setValue("TcEsA1NxUbphVFFFEQIcUxnvtlka");
        federatedAuthenticatorConfig.setProperties(properties);
        identityProvider.setDefaultAuthenticatorConfig(federatedAuthenticatorConfig);
        IdentityProviderProperty[] identityProviderProperties = new IdentityProviderProperty[2];
        identityProviderProperties[0].setName("jwksUri");
        identityProviderProperties[0].setValue(" \thttps://federatedwso2.com:9444/oauth2/jwks");
        identityProviderProperties[1].setName("idpIssuerName");
        identityProviderProperties[1].setValue("https://federatedwso2.com:9444/oauth2/token");
        identityProvider.setIdpProperties(identityProviderProperties);
    }

    private void setupTest() {

    }

    @Test
    public void testProcess() {

    }

    @Test
    public void testOidcFederatedLogout() {

    }

    @Test
    public void testTestCanHandle() {

    }
}
