/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.oidc.util;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.oauth2.util.JWTSignatureValidationUtils;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/***
 * Unit test class for OIDCTokenValidationUtil class.
 */
@PrepareForTest({
        JWTSignatureValidationUtils.class,
        IdentityProviderManager.class,
        IdentityApplicationManagementUtil.class
})
@SuppressStaticInitializationFor({
        "org.wso2.carbon.idp.mgt.IdentityProviderManager",
        "org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException"
})
public class OIDCTokenValidationUtilTest extends PowerMockTestCase {

    @Mock
    private IdentityProvider identityProvider;

    @Mock
    private IdentityProviderManager identityProviderManager;

    @Mock
    private FederatedAuthenticatorConfig mockedOauthAuthenticatorConfig;

    @Mock
    private Property mockedOauthTokenURL;

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
    private static String invlaidIdToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwI" +
        "iwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    private static String idpIdentifier = "https://localhost:9443/oauth2/token";
    private static String tenantDomain = "carbon.super";
    private static String alias = "https://localhost:9444/oauth2/token";

    @BeforeTest
    public void init() throws Exception {

    }
    @Test
    public void testGetIssuer() throws Exception {

        SignedJWT signedJWT = SignedJWT.parse(idToken);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        Assert.assertEquals(OIDCTokenValidationUtil.getIssuer(claimsSet), idpIdentifier);
    }

    @Test
    public void testPassValidateAudienceResident() throws Exception {

        when(identityProvider.getIdentityProviderName()).thenReturn("LOCAL");

        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(tenantDomain)).thenReturn(identityProvider);
        FederatedAuthenticatorConfig[] fedAuthnConfigs = new FederatedAuthenticatorConfig[1];
        fedAuthnConfigs[0] = mockedOauthAuthenticatorConfig;
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(fedAuthnConfigs);

        mockStatic(IdentityApplicationManagementUtil.class);
        when(IdentityApplicationManagementUtil.class, "getFederatedAuthenticator",
                any(FederatedAuthenticatorConfig[].class),
                eq(IdentityApplicationConstants.Authenticator.OIDC.NAME)).thenReturn(mockedOauthAuthenticatorConfig);
        Property[] properties = new Property[]{new Property()};
        when(mockedOauthAuthenticatorConfig.getProperties()).thenReturn(properties);
        when(IdentityApplicationManagementUtil.getProperty(any(Property[].class),
                eq(IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL))).thenReturn(mockedOauthTokenURL);
        when(mockedOauthTokenURL.getValue()).thenReturn(alias);

        List<String> audienceList = new ArrayList<>();
        audienceList.add(alias);

        OIDCTokenValidationUtil.validateAudience(audienceList, identityProvider, tenantDomain);
    }

    @Test
    public void testPassValidateAudienceExternal() throws Exception {

        when(identityProvider.getIdentityProviderName()).thenReturn("Google");
        when(identityProvider.getAlias()).thenReturn(alias);

        List<String> audienceList = new ArrayList<>();
        audienceList.add(alias);

        OIDCTokenValidationUtil.validateAudience(audienceList, identityProvider, tenantDomain);
    }

    @Test
    public void testFailValidateAudienceResident() throws Exception {

        when(identityProvider.getIdentityProviderName()).thenReturn("LOCAL");

        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(tenantDomain)).thenReturn(identityProvider);
        FederatedAuthenticatorConfig[] fedAuthnConfigs = new FederatedAuthenticatorConfig[1];
        fedAuthnConfigs[0] = mockedOauthAuthenticatorConfig;
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(fedAuthnConfigs);

        mockStatic(IdentityApplicationManagementUtil.class);
        when(IdentityApplicationManagementUtil.class, "getFederatedAuthenticator",
                any(FederatedAuthenticatorConfig[].class),
                eq(IdentityApplicationConstants.Authenticator.OIDC.NAME)).thenReturn(mockedOauthAuthenticatorConfig);
        Property[] properties = new Property[]{new Property()};
        when(mockedOauthAuthenticatorConfig.getProperties()).thenReturn(properties);
        when(IdentityApplicationManagementUtil.getProperty(any(Property[].class),
                eq(IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL))).thenReturn(mockedOauthTokenURL);
        when(mockedOauthTokenURL.getValue()).thenReturn(alias);

        List<String> audienceList = new ArrayList<>();

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> OIDCTokenValidationUtil.validateAudience(audienceList, identityProvider, tenantDomain)
        );
    }

    @Test
    public void testFailValidateAudienceExternal() throws Exception {

        when(identityProvider.getIdentityProviderName()).thenReturn("Google");
        when(identityProvider.getAlias()).thenReturn(alias);

        List<String> audienceList = new ArrayList<>();

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> OIDCTokenValidationUtil.validateAudience(audienceList, identityProvider, tenantDomain)
        );
    }

    @Test
    public void testPassValidateSignature() throws Exception {

        SignedJWT signedJWT = SignedJWT.parse(idToken);
        mockStatic(JWTSignatureValidationUtils.class);
        when(JWTSignatureValidationUtils.class, "validateSignature", signedJWT, identityProvider)
                .thenReturn(true);

        OIDCTokenValidationUtil.validateSignature(signedJWT, identityProvider);
    }

    @Test
    public void testFailValidateSignature() throws Exception {

        SignedJWT signedJWT = SignedJWT.parse(idToken);
        mockStatic(JWTSignatureValidationUtils.class);
        when(JWTSignatureValidationUtils.class, "validateSignature", signedJWT, identityProvider)
                .thenReturn(false);

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> OIDCTokenValidationUtil.validateSignature(signedJWT, identityProvider)
        );
    }

    @Test
    public void testPassValidateIssuerClaim() throws Exception {

        SignedJWT signedJWT = SignedJWT.parse(idToken);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        OIDCTokenValidationUtil.validateIssuerClaim(claimsSet);
    }

    @Test
    public void testFailValidateIssuerClaim() throws Exception {

        SignedJWT signedJWT = SignedJWT.parse(invlaidIdToken);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        Assert.assertThrows(
                AuthenticationFailedException.class,
                () -> OIDCTokenValidationUtil.validateIssuerClaim(claimsSet)
        );
    }
}
