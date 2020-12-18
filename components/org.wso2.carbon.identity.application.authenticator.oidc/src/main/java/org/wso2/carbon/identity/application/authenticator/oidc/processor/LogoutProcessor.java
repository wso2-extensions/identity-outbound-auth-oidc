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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.services.SessionManagementService;
import org.wso2.carbon.identity.application.authenticator.oidc.LogoutException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.context.LogoutContext;
import org.wso2.carbon.identity.application.authenticator.oidc.dao.SessionInfoDAO;
import org.wso2.carbon.identity.application.authenticator.oidc.model.LogoutRequest;
import org.wso2.carbon.identity.application.authenticator.oidc.model.LogoutResponse;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.validators.jwt.JWKSBasedJWTValidator;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AnalyticsAttributes.SESSION_ID;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OIDC_BCLOGOUT_ENDPOINT_URL_PATTERN;

public class LogoutProcessor extends IdentityProcessor {

    private static final Log log = LogFactory.getLog(LogoutProcessor.class);
    private SessionManagementService sessionManagementService = new SessionManagementService();

    private String tenantDomain;

    private static final String ENFORCE_CERTIFICATE_VALIDITY
            = "JWTValidatorConfigs.EnforceCertificateExpiryTimeValidity";
    private static final String DEFAULT_IDP_NAME = "default";
    private static final String ERROR_GET_RESIDENT_IDP =
            "Error while getting Resident Identity Provider of '%s' tenant.";
    private static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";
    private static final String BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openidnet/event/backchannel-logout";
    private static final String BACKCHANNEL_LOGOUT_EVENT_CLAIM = "{}";
    private static final String ENABLE_IAT_VALIDATION = "enableIatValidation";
    private static final String IAT_VALIDITY_PERIOD = "iatValidityPeriod";

    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("Request processing started by OIDCFederatedLogoutProcessor.");
        }
        log.info("Backchannel logout request received.");
        LogoutContext logoutContext = new LogoutContext(identityRequest);

        IdentityResponse.IdentityResponseBuilder identityResponseBuilder = null;

        if (identityRequest instanceof LogoutRequest) {
            try {
                identityResponseBuilder = oidcFederatedLogout(logoutContext);
            } catch (Exception e) {
                log.error(e);
            }
        } else {
            log.error("Can't handle the request");
        }

        return identityResponseBuilder;

    }

    protected IdentityResponse.IdentityResponseBuilder oidcFederatedLogout(
            LogoutContext logoutContext) throws LogoutException {

        LogoutResponse.LogoutResponseBuilder logoutResponseBuilder =
                new LogoutResponse.LogoutResponseBuilder();
        LogoutRequest logoutRequest = (LogoutRequest) logoutContext.getIdentityRequest();
        try {
            String logoutToken = logoutRequest.getParameter("logout_token");
            if (StringUtils.isNotBlank(logoutToken)) {
                log.info("Logout Token: " + logoutToken);

                //check for id token encryption
                boolean isEncryptionEnabled = false;

                if (isEncryptionEnabled) {
                    //Do the decryption and validation
                } else {

                    SignedJWT signedJWT = SignedJWT.parse(logoutToken);

                    if (signedJWT != null) {

                        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

                        String idp = claimsSet.getIssuer();
                        String tenetDomain = logoutRequest.getTenantDomain();
                        IdentityProvider identityProvider = getIdentityProvider(idp, tenetDomain);

                        boolean isSignatureValid = validateSignature(signedJWT, identityProvider);

                        List<String> aud = claimsSet.getAudience();
                        boolean isAudValid = validateAud(aud, identityProvider);

                        Date iat = claimsSet.getIssueTime();
                        boolean isIatValid = validateIat(iat);

                        boolean isSidValid = validateSid(claimsSet);

                        JSONObject events = (JSONObject) claimsSet.getClaim("events");
                        boolean isValidEvents = validateEvent(events);

                        boolean isvalidNonce = validateNonce(claimsSet);

                        if (isSignatureValid && isAudValid && isIatValid && isSidValid && isValidEvents &&
                                isvalidNonce) {
                            String sid = (String) claimsSet.getClaim("sid");
                            doLogout(sid);
                        } else {
                            log.error("Logout token signature validation failed !");
                        }
                    }
                }
            } else {
                log.error("Back channel logout failed. Logout token is null");
            }
        } catch (ParseException e) {
            log.error("Error while parsing logout token", e);
        } catch (JOSEException e) {
            log.error("Error while validating the logout token sinature", e);
        } catch (IdentityProviderManagementException e) {
            log.error("Error while retrieving the identity provider", e);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while validating claims", e);
        } catch (Exception e) {
            log.error("Logout Token Error. Rejecting the logout request");
        }
        return logoutResponseBuilder;
    }

    private void doLogout(String sid) throws LogoutException {

        log.info("SId: " + sid);
        //Get the Session Id related to sid claim from database
        SessionInfoDAO sessionInfoDAO = new SessionInfoDAO();
        Map<String, String> sessionDetails = sessionInfoDAO.getSessionDetails(sid);
        String sessionId = sessionDetails.get(SESSION_ID);

        if (StringUtils.isNotBlank(sessionId)) {
            boolean sessionRemoved = sessionManagementService.removeSession(sessionId);
            if (sessionRemoved) {
                log.info("Session terminated for session Id: " + sessionId);
            } else {
                log.error("Unable to terminate session for session Id: " + sessionId);
            }
        } else {
            log.error("Session Id doesn't exist for " + sid);
        }
    }

    //Not necessary as validating signature will also validate this
    private boolean validateIss(SignedJWT jwt) {

        boolean isValid = false;
        return isValid;
    }

    private boolean validateAud(List<String> aud, IdentityProvider idp) {

        boolean isValid = false;
        String clientId = null;
        for (Property property : idp.getDefaultAuthenticatorConfig().getProperties()) {
            String propertyName = (String) property.getName();
            if (propertyName.equals("ClientId")) {
                clientId = property.getValue();
                break;
            }
        }
        if (StringUtils.isNotBlank(clientId)) {
            for (String audience : aud) {
                if (audience.equals(clientId)) {
                    isValid = true;
                    break;
                }
            }
        }
        return isValid;
    }

    private boolean validateIat(Date iat) {

        if (iat != null) {
            boolean enableIatValidation =
                    Boolean.parseBoolean(getAuthenticatorConfig().getParameterMap().get(ENABLE_IAT_VALIDATION));
            if (enableIatValidation) {
                int iatValidtyPeriod =
                        Integer.parseInt(getAuthenticatorConfig().getParameterMap().get(IAT_VALIDITY_PERIOD));
                long issuedAtTimeMillis = iat.getTime();
                long currentTimeInMillis = System.currentTimeMillis();
                if (currentTimeInMillis - issuedAtTimeMillis > iatValidtyPeriod * 60 * 1000) {
                    if (log.isDebugEnabled()) {
                        log.debug("Token is used after iat validity period." +
                                ", iat validity period(m) : " + iatValidtyPeriod +
                                ", Current Time : " + currentTimeInMillis +
                                ". Token Rejected and validation terminated.");
                    }
                    log.error("Token is used after iat validity period.");
                }
                if (log.isDebugEnabled()) {
                    log.debug("iat validity period of Token was validated successfully.");
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("iat validity period is not enabled");
            }
        }
        return true;
    }

    private boolean validateSid(JWTClaimsSet claimsSet) {

        boolean isValid = false;
        String sid = (String) claimsSet.getClaim("sid");
        String sub = (String) claimsSet.getSubject();
        if (StringUtils.isNotBlank(sid)) {
            isValid = true;
        }
        return isValid;
    }

    private boolean validateEvent(JSONObject event) {

        String eventClaim = event.getAsString(BACKCHANNEL_LOGOUT_EVENT);
        if (StringUtils.equals(eventClaim, BACKCHANNEL_LOGOUT_EVENT_CLAIM)) {
            return true;
        }
        return false;
    }

    private boolean validateNonce(JWTClaimsSet claimsSet) {

        boolean isValid = false;
        String nonce = (String) claimsSet.getClaim("nonce");
        if (StringUtils.isBlank(nonce)) {
            isValid = true;
        }
        return isValid;
    }

    protected AuthenticatorConfig getAuthenticatorConfig() {

        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(AUTHENTICATOR_NAME);
        if (authConfig == null) {
            authConfig = new AuthenticatorConfig();
            authConfig.setParameterMap(new HashMap<String, String>());
        }
        return authConfig;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {

        return null;
    }

    @Override
    public String getRelyingPartyId() {

        return null;
    }

    @Override
    public String getRelyingPartyId(IdentityMessageContext context) {

        return null;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {

        boolean canHandle = false;
        if (identityRequest != null) {
            Matcher registerMatcher =
                    OIDC_BCLOGOUT_ENDPOINT_URL_PATTERN.matcher(identityRequest.getRequestURI());
            if (registerMatcher.matches()) {
                canHandle = true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("canHandle " + canHandle + " by OIDCFederatedLogoutProcessor.");
        }
        return canHandle;
    }

    private IdentityProvider getIdentityProvider(String jwtIssuer, String tenantDomain)
            throws IdentityProviderManagementException, IdentityOAuth2Exception {

        IdentityProvider identityProvider = null;
        identityProvider = IdentityProviderManager.getInstance().getIdPByMetadataProperty(
                IdentityApplicationConstants.IDP_ISSUER_NAME, jwtIssuer, tenantDomain, false);

        if (identityProvider == null) {
            if (log.isDebugEnabled()) {
                log.debug("IDP not found when retrieving for IDP using property: " +
                        IdentityApplicationConstants.IDP_ISSUER_NAME + " with value: " + jwtIssuer +
                        ". Attempting to retrieve IDP using IDP Name as issuer.");
            }
            identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);
        }
        if (identityProvider != null) {
            // if no IDPs were found for a given name, the IdentityProviderManager returns a dummy IDP with the
            // name "default". We need to handle this case.
            if (StringUtils.equalsIgnoreCase(identityProvider.getIdentityProviderName(), DEFAULT_IDP_NAME)) {
                //check whether this jwt was issued by the resident identity provider
                identityProvider = getResidentIDPForIssuer(tenantDomain, jwtIssuer);
                if (identityProvider == null) {
                    handleException("No Registered IDP found for the JWT with issuer name : " + jwtIssuer);
                }
            }
        }
        return identityProvider;
    }

    private IdentityProvider getResidentIDPForIssuer(String tenantDomain, String jwtIssuer)
            throws IdentityOAuth2Exception {

        String issuer = StringUtils.EMPTY;
        IdentityProvider residentIdentityProvider;
        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = String.format(ERROR_GET_RESIDENT_IDP, tenantDomain);
            log.error(errorMsg, e);
            return null;
        }
        FederatedAuthenticatorConfig[] fedAuthnConfigs = residentIdentityProvider.getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        if (oauthAuthenticatorConfig != null) {
            issuer = IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                    OIDC_IDP_ENTITY_ID).getValue();
        }
        return jwtIssuer.equals(issuer) ? residentIdentityProvider : null;
    }

    private boolean validateSignature(SignedJWT signedJWT, IdentityProvider idp)
            throws JOSEException, IdentityOAuth2Exception {

        boolean isJWKSEnabled = false;
        boolean hasJWKSUri = false;
        String jwksUri = null;

        String isJWKSEnalbedProperty = IdentityUtil.getProperty(
                OIDCAuthenticatorConstants.JWT.JWKS_VALIDATION_ENABLE_CONFIG);
        isJWKSEnabled = Boolean.parseBoolean(isJWKSEnalbedProperty);
        if (isJWKSEnabled) {
            if (log.isDebugEnabled()) {
                log.debug("JWKS based JWT validation enabled.");
            }
        }

        IdentityProviderProperty[] identityProviderProperties = idp.getIdpProperties();
        if (!ArrayUtils.isEmpty(identityProviderProperties)) {
            for (IdentityProviderProperty identityProviderProperty : identityProviderProperties) {
                if (StringUtils.equals(identityProviderProperty.getName(), OIDCAuthenticatorConstants.JWT.JWKS_URI)) {
                    hasJWKSUri = true;
                    jwksUri = identityProviderProperty.getValue();
                    if (log.isDebugEnabled()) {
                        log.debug("JWKS endpoint set for the identity provider : " + idp.getIdentityProviderName() +
                                ", jwks_uri : " + jwksUri);
                    }
                    break;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("JWKS endpoint not specified for the identity provider : " + idp
                                .getIdentityProviderName());
                    }
                }
            }
        }

        if (isJWKSEnabled && hasJWKSUri) {
            JWKSBasedJWTValidator jwksBasedJWTValidator = new JWKSBasedJWTValidator();
            return jwksBasedJWTValidator.validateSignature(signedJWT.getParsedString(), jwksUri, signedJWT.getHeader
                    ().getAlgorithm().getName(), null);
        } else {
            JWSVerifier verifier = null;
            JWSHeader header = signedJWT.getHeader();
            X509Certificate x509Certificate = resolveSignerCertificate(header, idp);
            if (x509Certificate == null) {
                handleException(
                        "Unable to locate certificate for Identity Provider " + idp.getDisplayName() + "; JWT " +
                                header.toString());
            }

            checkValidity(x509Certificate);

            String alg = signedJWT.getHeader().getAlgorithm().getName();
            if (StringUtils.isEmpty(alg)) {
                handleException("Algorithm must not be null.");
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Algorithm found in the JWT Header: " + alg);
                }
                if (alg.startsWith("RS")) {
                    // At this point 'x509Certificate' will never be null.
                    PublicKey publicKey = x509Certificate.getPublicKey();
                    if (publicKey instanceof RSAPublicKey) {
                        verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                    } else {
                        handleException("Public key is not an RSA public key.");
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Signature Algorithm not supported yet : " + alg);
                    }
                }
                if (verifier == null) {
                    handleException("Could not create a signature verifier for algorithm type: " + alg);
                }
            }

            // At this point 'verifier' will never be null;
            return signedJWT.verify(verifier);
        }
    }

    private void checkValidity(X509Certificate x509Certificate) throws IdentityOAuth2Exception {

        String isEnforceCertificateValidity =
                IdentityUtil.getProperty(ENFORCE_CERTIFICATE_VALIDITY);
        if (StringUtils.isNotEmpty(isEnforceCertificateValidity)
                && !Boolean.parseBoolean(isEnforceCertificateValidity)) {
            if (log.isDebugEnabled()) {
                log.debug("Check for the certificate validity is disabled.");
            }
            return;
        }

        try {
            x509Certificate.checkValidity();
        } catch (CertificateExpiredException e) {
            log.error("X509Certificate has expired.", e);
        } catch (CertificateNotYetValidException e) {
            log.error("X509Certificate is not yet valid.", e);
        }
    }

    protected X509Certificate resolveSignerCertificate(JWSHeader header,
                                                       IdentityProvider idp) throws IdentityOAuth2Exception {

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(idp.getCertificate());
        } catch (CertificateException e) {
            handleException("Error occurred while decoding public certificate of Identity Provider "
                    + idp.getIdentityProviderName() + " for tenant domain " + tenantDomain);
        }
        return x509Certificate;
    }

    private void handleException(String errorMessage) throws IdentityOAuth2Exception {

        log.error(errorMessage);
    }
}
