/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.JWTSignatureValidationUtils;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.util.List;

/**
 * This class holds utilities related to OIDC token validation.
 */
public class OIDCTokenValidationUtil {

    private static final Log log = LogFactory.getLog(OIDCTokenValidationUtil.class);

    /**
     * Get unique identifier to identify the identity provider.
     *
     * @param claimsSet claim set available in the logout token.
     * @return unique idp identifier.
     * @throws AuthenticationFailedException if there is an issue while getting the unique identifier.
     */
    public static String getIssuer(JWTClaimsSet claimsSet) throws AuthenticationFailedException {

        return claimsSet.getIssuer();
    }

    /**
     * Do the aud claim validation according to OIDC back-channel logout specification.
     *
     * @param audienceList - list containing audience values.
     * @param idp - identity provider.
     * @Param tenantDomain - the tenant domain
     */
    public static void validateAudience(List<String> audienceList, IdentityProvider idp, String tenantDomain)
            throws AuthenticationFailedException {

        boolean audienceFound = false;
        String tokenEndPointAlias = getTokenEndpointAlias(idp, tenantDomain);
        for (String audience : audienceList) {
            if (StringUtils.equals(tokenEndPointAlias, audience)) {
                if (log.isDebugEnabled()) {
                    log.debug(tokenEndPointAlias + " of IDP was found in the list of audiences.");
                }
                audienceFound = true;
                break;
            }
        }
        if (!audienceFound) {
            throw new AuthenticationFailedException ("None of the audience values matched the tokenEndpoint Alias "
                    + tokenEndPointAlias);
        }
    }

    /**
     * Get token endpoint alias.
     *
     * @param identityProvider Identity provider
     * @return token endpoint alias
     */
    private static String getTokenEndpointAlias(IdentityProvider identityProvider, String tenantDomain) {

        Property oauthTokenURL = null;
        String tokenEndPointAlias = null;
        if (IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME.equals(
                identityProvider.getIdentityProviderName())) {
            try {
                identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
            } catch (IdentityProviderManagementException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting Resident IDP :" + e.getMessage());
                }
            }
            FederatedAuthenticatorConfig[] fedAuthnConfigs =
                    identityProvider.getFederatedAuthenticatorConfigs();
            FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                    IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                            IdentityApplicationConstants.Authenticator.OIDC.NAME);

            if (oauthAuthenticatorConfig != null) {
                oauthTokenURL = IdentityApplicationManagementUtil.getProperty(
                        oauthAuthenticatorConfig.getProperties(),
                        IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
            }
            if (oauthTokenURL != null) {
                tokenEndPointAlias = oauthTokenURL.getValue();
                if (log.isDebugEnabled()) {
                    log.debug("Token End Point Alias of Resident IDP :" + tokenEndPointAlias);
                }
            }
        } else {
            tokenEndPointAlias = identityProvider.getAlias();
            if (log.isDebugEnabled()) {
                log.debug("Token End Point Alias of the Federated IDP: " + tokenEndPointAlias);
            }
        }
        return tokenEndPointAlias;
    }

    /**
     * Validate the JWT signature.
     *
     * @param signedJWT singed JWT.
     * @param identityProvider identity provider.
     * @throws JOSEException if there is an issue while verifying the singed JWT.
     * @throws IdentityOAuth2Exception if there is an issue while validating the signature.
     */
    public static void validateSignature(SignedJWT signedJWT,
                                         IdentityProvider identityProvider) throws JOSEException,
            IdentityOAuth2Exception , AuthenticationFailedException {

        if (!JWTSignatureValidationUtils.validateSignature(signedJWT, identityProvider)) {
            throw new AuthenticationFailedException(OIDCErrorConstants.ErrorMessages.
                    JWT_TOKEN_SIGNATURE_VALIDATION_FAILED.getCode(),
                    OIDCErrorConstants.ErrorMessages.JWT_TOKEN_SIGNATURE_VALIDATION_FAILED.getMessage());
        }
    }

    /**
     * Validate the issuer claim.
     *
     * @param claimsSet JWT claims set
     * @throws AuthenticationFailedException if there is an issue while validating the issuer.
     */
    public static void validateIssuerClaim(JWTClaimsSet claimsSet) throws AuthenticationFailedException {

        if (StringUtils.isBlank(getIssuer(claimsSet))) {
            throw new AuthenticationFailedException(OIDCErrorConstants.ErrorMessages.
                    JWT_TOKEN_ISS_CLAIM_VALIDATION_FAILED.getCode(),
                    OIDCErrorConstants.ErrorMessages.JWT_TOKEN_ISS_CLAIM_VALIDATION_FAILED.getMessage());
        }
    }
}
