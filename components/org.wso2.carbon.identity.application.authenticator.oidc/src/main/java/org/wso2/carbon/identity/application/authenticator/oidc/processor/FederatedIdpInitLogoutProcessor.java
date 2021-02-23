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

package org.wso2.carbon.identity.application.authenticator.oidc.processor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.ServerSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.dao.UserSessionDAO;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.UserSessionDAOImpl;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementServerException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.FederatedUserSession;
import org.wso2.carbon.identity.application.authenticator.oidc.LogoutClientException;
import org.wso2.carbon.identity.application.authenticator.oidc.LogoutServerException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.context.LogoutContext;
import org.wso2.carbon.identity.application.authenticator.oidc.dao.FederatedUserDAO;
import org.wso2.carbon.identity.application.authenticator.oidc.dao.impl.FederatedUserDAOImpl;
import org.wso2.carbon.identity.application.authenticator.oidc.internal.OpenIDConnectAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.oidc.model.LogoutRequest;
import org.wso2.carbon.identity.application.authenticator.oidc.model.LogoutResponse;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.JWTSignatureValidationUtils;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;

import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OIDC_BCLOGOUT_ENDPOINT_URL_PATTERN;
import static org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants.ErrorMessages;

/**
 * This class process the OIDC federated idp initiated logout requests
 */
public class FederatedIdpInitLogoutProcessor extends IdentityProcessor {

    private static final Log log = LogFactory.getLog(FederatedIdpInitLogoutProcessor.class);

    private static final String DEFAULT_IDP_NAME = "default";
    private static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";
    private static final String BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";
    private static final String BACKCHANNEL_LOGOUT_EVENT_CLAIM = "{}";
    private static final String ENABLE_IAT_VALIDATION = "enableIatValidation";
    private static final String IAT_VALIDITY_PERIOD = "iatValidityPeriod";

    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("Request processing started by OIDC FederatedIdpInitLogoutProcessor.");
        }
        LogoutContext logoutContext = new LogoutContext(identityRequest);
        return handleOIDCFederatedLogoutRequest(logoutContext);
    }

    /**
     * Handles the logout request according to OIDC Back-channel logout specification
     *
     * @param logoutContext
     * @return IdentityResponse.IdentityResponseBuilder
     * @throws LogoutClientException Exception occurred due to error in the logout request
     * @throws LogoutServerException Exception occurred from IS
     */
    protected IdentityResponse.IdentityResponseBuilder handleOIDCFederatedLogoutRequest(
            LogoutContext logoutContext) throws LogoutClientException, LogoutServerException {

        LogoutResponse.LogoutResponseBuilder logoutResponseBuilder =
                new LogoutResponse.LogoutResponseBuilder();
        LogoutRequest logoutRequest = (LogoutRequest) logoutContext.getIdentityRequest();
        try {
            String logoutToken = logoutRequest.getParameter(OIDCAuthenticatorConstants.Logout.LOGOUT_TOKEN);
            if (StringUtils.isNotBlank(logoutToken)) {
                if (log.isDebugEnabled()) {
                    log.debug("Logout Token: " + logoutToken);
                }
                SignedJWT signedJWT = SignedJWT.parse(logoutToken);
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                boolean isClaimValid;
                isClaimValid = validateClaims(signedJWT, logoutRequest.getTenantDomain());
                if (log.isDebugEnabled()) {
                    log.debug("Claim validation: " + isClaimValid);
                }
                if (isClaimValid) {
                    //check for sid or sub claims in the logout token.
                    if (validateSid(claimsSet)) {
                        //check whether the sid has an entry in the federated authentication session details table.
                        String sid = (String) claimsSet.getClaim(OIDCAuthenticatorConstants.Claim.SID);
                        UserSessionDAO userSessionDAO = new UserSessionDAOImpl();
                        FederatedUserSession federatedUserSession = userSessionDAO.getFederatedAuthSessionDetails(sid);
                        if (federatedUserSession != null) {
                            if (log.isDebugEnabled()) {
                                log.debug("Can terminate the session using sid claim");
                            }
                            logoutUsingSid(sid, federatedUserSession);
                        }
                        //if sid didn't have an entry in the table, then try to terminate the sessions using sub claim.
                        else {
                            if (log.isDebugEnabled()) {
                                log.debug(String.format("No session mapping entry for sid: %s. Trying the logout" +
                                        " using sub claim", sid));
                            }
                            String sub = claimsSet.getSubject();
                            boolean canLogoutUsingSub = canLogoutFromSub(sub);
                            if (log.isDebugEnabled()) {
                                log.debug("Can terminate the sessions using sub claim: " + canLogoutUsingSub);
                            }
                            if (canLogoutUsingSub) {
                                logoutUsingSub(sub);
                            }
                        }
                    }
                    //check whether the sub claim is available in the logout token.
                    if (log.isDebugEnabled()) {
                        log.debug("No sid presented in the logout token. Using sub claim to terminate the sessions.");
                    } else if (validateSub(claimsSet)) {
                        //check whether the sub claim has a valid user in the IS.
                        String sub = claimsSet.getSubject();
                        boolean canLogoutUsingSub = canLogoutFromSub(sub);
                        if (log.isDebugEnabled()) {
                            log.debug("Can terminate the sessions using sub claim: " + canLogoutUsingSub);
                        }
                        if (canLogoutUsingSub) {
                            logoutUsingSub(sub);
                        }
                    }
                } else {
                    throw handleLogoutClientException(ErrorMessages.LOGOUT_TOKEN_CLAIM_VALIDATION_FAILURE, "");
                }
            } else {
                throw handleLogoutClientException(ErrorMessages.LOGOUT_TOKEN_EMPTY_OR_NULL, "");
            }
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessages.LOGOUT_TOKEN_PARSING_FAILURE.getMessage(), e);
            }
            throw handleLogoutClientException(ErrorMessages.LOGOUT_TOKEN_PARSING_FAILURE, "");
        } catch (SessionManagementServerException e) {
            if (log.isDebugEnabled()) {
                log.debug(String.format(ErrorMessages.RETRIEVING_SESSION_ID_MAPPING_FAILED.getMessage(), ""));
            }
            throw handleLogoutServerException(ErrorMessages.RETRIEVING_SESSION_ID_MAPPING_FAILED, "");
        }
        return logoutResponseBuilder;
    }

    /**
     * Terminate the session related to the sid value of the logout token
     *
     * @param sid
     * @throws LogoutServerException
     */
    private void logoutUsingSid(String sid, FederatedUserSession federatedUserSession) throws LogoutServerException {

        if (log.isDebugEnabled()) {
            log.debug("sid: " + sid);
        }
        String sessionId = federatedUserSession.getSessionId();
        if (StringUtils.isNotBlank(sessionId)) {
            if (log.isDebugEnabled()) {
                log.debug("Session id: " + sessionId);
            }
            ServerSessionManagementService serverSessionManagementService =
                    OpenIDConnectAuthenticatorDataHolder.getInstance().getServerSessionManagementService();
            boolean sessionRemoved
                    = serverSessionManagementService.removeSession(sessionId);
            if (sessionRemoved) {
                log.info("Session terminated for session Id: " + sessionId);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(String.format(ErrorMessages.FEDERATED_SESSION_TERMINATION_FAILED.getMessage(),
                            sessionId));
                }
                throw handleLogoutServerException(
                        ErrorMessages.FEDERATED_SESSION_TERMINATION_FAILED, sessionId);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format(ErrorMessages.RETRIEVING_SESSION_ID_MAPPING_FAILED.getMessage(), sid));
            }
            throw handleLogoutServerException(ErrorMessages.RETRIEVING_SESSION_ID_MAPPING_FAILED, sid);
        }
    }

    /**
     * Terminate all the sessions of the user related sub claim.
     *
     * @param sub claim in the logout token.
     * @throws LogoutServerException
     * @throws SessionManagementException
     */
    private void logoutUsingSub(String sub) throws LogoutServerException {

        try {
            FederatedUserDAO federatedUserDAO = new FederatedUserDAOImpl();
            String userId = federatedUserDAO.getUserIdbyUsername(sub);
            if (log.isDebugEnabled()) {
                log.debug("User Id: " + userId);
            }
            if (StringUtils.isNotBlank(userId)) {
                UserSessionManagementService userSessionManagementService =
                        OpenIDConnectAuthenticatorDataHolder.getInstance()
                                .getUserSessionManagementService();
                userSessionManagementService.terminateSessionsByUserId(userId);
                log.info("Sessions terminated for user Id: " + userId);
            }
        } catch (SessionManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessages.USER_SESSION_TERMINATION_FAILURE.getMessage(), e);
            }
            throw handleLogoutServerException(ErrorMessages.USER_SESSION_TERMINATION_FAILURE, sub);
        }
    }

    /**
     * Check whether it is possible to terminate the sessions using the sub claim.
     *
     * @param sub claim in the logout token.
     * @return boolean
     * @throws LogoutServerException
     */
    private boolean canLogoutFromSub(String sub) throws LogoutServerException {

        boolean canLogout = false;
        FederatedUserDAO federatedUserDAO = new FederatedUserDAOImpl();
        String userId = federatedUserDAO.getUserIdbyUsername(sub);
        if (StringUtils.isNotBlank(userId)) {
            canLogout = true;
        }
        return canLogout;
    }

    /**
     * Validate all the claim according to the OIDC specification.
     *
     * @param signedJWT
     * @param tenantDomain
     * @return boolean value
     * @throws LogoutClientException
     * @throws LogoutServerException
     */
    private boolean validateClaims(SignedJWT signedJWT, String tenantDomain)
            throws LogoutClientException, LogoutServerException {

        boolean isValidated = false;

        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            //validate the signature of the logout token.
            String idp = claimsSet.getIssuer();
            IdentityProvider identityProvider = getIdentityProvider(idp, tenantDomain);
            boolean isSignatureValid = JWTSignatureValidationUtils.validateSignature(signedJWT,
                    identityProvider);
            //validate the audience claim.
            List<String> aud = claimsSet.getAudience();
            boolean isAudValid = validateAud(aud, identityProvider);
            //validate the iat claim.
            Date iat = claimsSet.getIssueTime();
            boolean isIatValid = validateIat(iat);
            //validate events claim.
            JSONObject events = (JSONObject) claimsSet.getClaim(OIDCAuthenticatorConstants.Claim.EVENTS);
            boolean isValidEvents = validateEvent(events);
            //validate nonce.
            boolean isValidNonce = validateNonce(claimsSet);
            //validate whether the sid or sub claim is present in the logout token, according the OIDC specification.
            boolean isSidOrSubValid = false;
            if (validateSid(claimsSet) || validateSub(claimsSet)) {
                isSidOrSubValid = true;
            }
            if (isSignatureValid && isAudValid && isIatValid && isValidEvents && isValidNonce && isSidOrSubValid) {
                isValidated = true;
            }
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessages.LOGOUT_TOKEN_PARSING_FAILURE.getMessage(), e);
            }
            throw handleLogoutClientException(ErrorMessages.LOGOUT_TOKEN_PARSING_FAILURE, "");
        } catch (JOSEException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessages.LOGOUT_TOKEN_SIGNATURE_VALIDATION_FAILED.getMessage(), e);
            }
            throw handleLogoutServerException(ErrorMessages.LOGOUT_TOKEN_SIGNATURE_VALIDATION_FAILED, "");
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessages.LOGOUT_TOKEN_SIGNATURE_VALIDATION_FAILED.getMessage(), e);
            }
            throw handleLogoutServerException(ErrorMessages.LOGOUT_TOKEN_SIGNATURE_VALIDATION_FAILED, "");
        }

        return isValidated;
    }

    /**
     * Do the aud claim validation according to OIDC back-channel logout specification
     *
     * @param aud
     * @param idp
     * @return boolean if validation is successful
     */
    private boolean validateAud(List<String> aud, IdentityProvider idp) {

        boolean isValid = false;
        String clientId = null;
        for (Property property : idp.getDefaultAuthenticatorConfig().getProperties()) {
            String propertyName = (String) property.getName();
            if (propertyName.equals(OIDCAuthenticatorConstants.IdPConfParams.CLIENT_ID)) {
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

    /**
     * Do the iat claim validation according to OIDC back-channel logout specification
     * Read the authenticator configs to check whether the iat validation is enabled and if enabled the get the
     * validity period
     *
     * @param iat
     * @return boolean if validation is successful
     * @throws LogoutClientException
     */
    private boolean validateIat(Date iat) throws LogoutClientException {

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
                    throw new LogoutClientException(
                            ErrorMessages.LOGOUT_TOKEN_IAT_VALIDATION_FAILED.getCode(),
                            ErrorMessages.LOGOUT_TOKEN_IAT_VALIDATION_FAILED.getMessage());
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

    /**
     * Do the sid claim validation.
     *
     * @param claimsSet
     * @return boolean if validation is successful
     */
    private boolean validateSid(JWTClaimsSet claimsSet) {

        boolean isValid = false;
        String sid = (String) claimsSet.getClaim(OIDCAuthenticatorConstants.Claim.SID);
        if (StringUtils.isNotBlank(sid)) {
            isValid = true;
        }
        return isValid;
    }

    /**
     * Do the sub claim validation.
     *
     * @param claimsSet
     * @return boolean if validation is successful.
     */
    private boolean validateSub(JWTClaimsSet claimsSet) {

        boolean isValid = false;
        String sub = claimsSet.getSubject();
        if (StringUtils.isNotBlank(sub)) {
            isValid = true;
        }
        return isValid;
    }

    /**
     * Do the event claim validation according to OIDC back-channel logout specification
     *
     * @param event
     * @return boolean if validation is successful
     */
    private boolean validateEvent(JSONObject event) {

        String eventClaim = event.getAsString(BACKCHANNEL_LOGOUT_EVENT);
        if (StringUtils.equals(eventClaim, BACKCHANNEL_LOGOUT_EVENT_CLAIM)) {
            return true;
        }
        return false;
    }

    /**
     * Do the nonce claim validation according to OIDC back-channel logout specification
     *
     * @param claimsSet
     * @return boolean if validation is successful
     */
    private boolean validateNonce(JWTClaimsSet claimsSet) {

        boolean isValid = false;
        String nonce = (String) claimsSet.getClaim(OIDCAuthenticatorConstants.Claim.NONCE);
        if (StringUtils.isBlank(nonce)) {
            isValid = true;
        }
        return isValid;
    }

    /**
     * Get the OIDC authenticator configs from the xml file
     *
     * @return AuthenticatorConfig
     */
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
            log.debug("canHandle " + canHandle + " by OIDC FederatedIdpInitLogoutProcessor.");
        }
        return canHandle;
    }

    /**
     * Handle logout server exceptions.
     *
     * @param error Error description.
     * @param data  relevant data.
     * @return LogoutServerException.
     */
    private LogoutServerException handleLogoutServerException(OIDCErrorConstants.ErrorMessages error, String data) {

        return new LogoutServerException(error.getCode(), String.format(error.getMessage(), data));
    }

    /**
     * Handle logout client exceptions.
     *
     * @param error Error description.
     * @param data  relevant data.
     * @return LogoutClientException.
     */
    private LogoutClientException handleLogoutClientException(OIDCErrorConstants.ErrorMessages error, String data) {

        return new LogoutClientException(error.getCode(), String.format(error.getMessage(), data));
    }

    /**
     * Get the identity provider from issuer and tenant domain
     *
     * @param jwtIssuer
     * @param tenantDomain
     * @return IdentityProvider
     * @throws LogoutServerException
     */
    private IdentityProvider getIdentityProvider(String jwtIssuer, String tenantDomain)
            throws LogoutServerException {

        IdentityProvider identityProvider = null;
        try {
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
                        throw handleLogoutServerException(ErrorMessages.NO_REGISTERED_IDP_FOR_ISSUER, jwtIssuer);
                    }
                }
            }
        } catch (IdentityProviderManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessages.RETRIEVING_IDENTITY_PROVIDER_FAILED.getMessage(), e);
            }
            throw handleLogoutServerException(ErrorMessages.RETRIEVING_IDENTITY_PROVIDER_FAILED, "");
        }
        return identityProvider;
    }

    /**
     * Get the resident identity provider from issuer and tenant domain
     *
     * @param tenantDomain
     * @param jwtIssuer
     * @return
     * @throws IdentityOAuth2Exception
     * @throws LogoutServerException
     */
    private IdentityProvider getResidentIDPForIssuer(String tenantDomain, String jwtIssuer)
            throws LogoutServerException {

        String issuer = StringUtils.EMPTY;
        IdentityProvider residentIdentityProvider;
        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = String.format(ErrorMessages.GETTING_RESIDENT_IDP_FAILED.getMessage(), tenantDomain);
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
            throw handleLogoutServerException(ErrorMessages.GETTING_RESIDENT_IDP_FAILED, tenantDomain);
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

}
