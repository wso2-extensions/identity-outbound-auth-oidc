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
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.dao.UserSessionDAO;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.UserSessionDAOImpl;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementServerException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.FederatedUserSession;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.authenticator.oidc.LogoutClientException;
import org.wso2.carbon.identity.application.authenticator.oidc.LogoutServerException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.internal.OpenIDConnectAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.oidc.model.LogoutResponse;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.JWTSignatureValidationUtils;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;

import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OIDC_BACKCHANNEL_LOGOUT_ENDPOINT_URL_PATTERN;
import static org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants.ErrorMessages;

/**
 * Processes the OIDC federated idp initiated logout requests.
 */
public class FederatedIdpInitLogoutProcessor extends IdentityProcessor {

    private static final Log log = LogFactory.getLog(FederatedIdpInitLogoutProcessor.class);

    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("Request processing started by OIDC FederatedIdpInitLogoutProcessor.");
        }
        return handleOIDCFederatedLogoutRequest(identityRequest);
    }

    /**
     * Handles the logout request according to OIDC Back-channel logout specification.
     *
     * @param logoutRequest
     * @return IdentityResponse.IdentityResponseBuilder.
     * @throws LogoutClientException Exception occurred due to error in the logout request.
     * @throws LogoutServerException Exception occurred from IS.
     */
    protected IdentityResponse.IdentityResponseBuilder handleOIDCFederatedLogoutRequest(
            IdentityRequest logoutRequest) throws LogoutClientException, LogoutServerException {

        String sub = "";
        try {
            String logoutToken = logoutRequest.getParameter(OIDCAuthenticatorConstants.LOGOUT_TOKEN);
            if (StringUtils.isBlank(logoutToken)) {
                throw new LogoutClientException(ErrorMessages.LOGOUT_TOKEN_EMPTY_OR_NULL.getCode(),
                        ErrorMessages.LOGOUT_TOKEN_EMPTY_OR_NULL.getMessage());
            }
            if (log.isDebugEnabled()) {
                log.debug("Started handling the federated IdP Initiated Logout request. Logout Token: " + logoutToken);
            }

            SignedJWT signedJWT = SignedJWT.parse(logoutToken);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            // Get the identity provider for the issuer of the logout token.
            String tenantDomain = logoutRequest.getTenantDomain();
            IdentityProvider identityProvider =
                    getIdentityProvider(claimsSet.getIssuer(), tenantDomain);
            validateLogoutToken(signedJWT, identityProvider);

            sub = claimsSet.getSubject();
            // Retrieve the federated user id from the IDN_AUTH_USER table.
            int tenantId = tenantDomain == null ? -1 : IdentityTenantUtil.getTenantId(tenantDomain);
            String userId = UserSessionStore.getInstance()
                    .getUserId(sub, tenantId, null, Integer.parseInt(identityProvider.getId()));
            if (log.isDebugEnabled()) {
                log.debug("User Id: " + userId);
            }

            // Check for sid or sub claims in the logout token.
            if (isSidExists(claimsSet)) {
                // Check whether the sid has an entry in the federated authentication session details table.
                return logoutUsingSid((String) claimsSet.getClaim(OIDCAuthenticatorConstants.Claim.SID), userId);
            }
            // Check whether the sub claim is available in the logout token.
            if (log.isDebugEnabled()) {
                log.debug("No sid presented in the logout token of the federated idp initiated logout request. Using " +
                        "sub claim to terminate the sessions for tenant domain: ." + tenantDomain);
            }
            // Check whether the sub claim has a valid user in the IS.
            return logoutUsingSub(sub, tenantDomain);

        } catch (ParseException e) {
            throw handleLogoutClientException(ErrorMessages.LOGOUT_TOKEN_PARSING_FAILURE, e);
        } catch (UserSessionException e) {
            throw handleLogoutServerException(ErrorMessages.RETRIEVING_USER_ID_FAILED, e, sub);

        }
    }

    /**
     * Terminate the session related to the sid value of the logout token.
     *
     * @param sid - sid claim included in the logout token.
     * @return
     * @throws LogoutServerException
     */
    private LogoutResponse.LogoutResponseBuilder logoutUsingSid(String sid, String userId)
            throws LogoutServerException {

        if (log.isDebugEnabled()) {
            log.debug("Trying federated IdP initiated logout using sid: " + sid);
        }
        FederatedUserSession federatedUserSession;
        try {
            UserSessionDAO userSessionDAO = new UserSessionDAOImpl();
            federatedUserSession = userSessionDAO.getFederatedAuthSessionDetails(sid);
        } catch (SessionManagementServerException e) {
            throw handleLogoutServerException(ErrorMessages.RETRIEVING_SESSION_ID_MAPPING_FAILED, e);
        }
        if (federatedUserSession == null) {
            return new LogoutResponse.LogoutResponseBuilder(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorMessages.LOGOUT_SERVER_EXCEPTION.getMessage());
        }
        String sessionId = federatedUserSession.getSessionId();
        if (StringUtils.isBlank(sessionId)) {
            throw handleLogoutServerException(ErrorMessages.RETRIEVING_SESSION_ID_MAPPING_FAILED, sid);
        }
        UserSessionManagementService userSessionManagementService = OpenIDConnectAuthenticatorDataHolder.getInstance()
                .getUserSessionManagementService();
        try {
            userSessionManagementService.terminateSessionBySessionId(userId, sessionId);
            log.info("Session terminated for session Id: " + sessionId + " and userId: " + userId);
            return new LogoutResponse.LogoutResponseBuilder(HttpServletResponse.SC_OK,
                    OIDCAuthenticatorConstants.BackchannelLogout.LOGOUT_SUCCESS);
        } catch (SessionManagementException e) {
            throw handleLogoutServerException(
                    ErrorMessages.FEDERATED_SESSION_TERMINATION_FAILED, sessionId);
        }
    }

    /**
     * Terminate all the sessions of the user related sub claim.
     *
     * @param sub claim in the logout token.
     * @throws LogoutServerException
     * @throws SessionManagementException
     */
    private LogoutResponse.LogoutResponseBuilder logoutUsingSub(String sub, String userId)
            throws LogoutServerException {

        try {
            if (StringUtils.isBlank(userId)) {
                return new LogoutResponse.LogoutResponseBuilder(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        ErrorMessages.LOGOUT_SERVER_EXCEPTION.getMessage());
            }
            UserSessionManagementService userSessionManagementService =
                    OpenIDConnectAuthenticatorDataHolder.getInstance()
                            .getUserSessionManagementService();
            userSessionManagementService.terminateSessionsByUserId(userId);
            log.info("Sessions terminated for user Id: " + userId);
            return new LogoutResponse.LogoutResponseBuilder(HttpServletResponse.SC_OK,
                    OIDCAuthenticatorConstants.BackchannelLogout.LOGOUT_SUCCESS);
        } catch (SessionManagementException e) {
            throw handleLogoutServerException(ErrorMessages.USER_SESSION_TERMINATION_FAILURE, e, sub);
        }
    }

    /**
     * Validate the JWT token signature and the mandatory claim according to the OIDC specification.
     *
     * @param signedJWT
     * @param identityProvider
     * @return boolean value
     * @throws LogoutClientException
     * @throws LogoutServerException
     */
    private void validateLogoutToken(SignedJWT signedJWT, IdentityProvider identityProvider)
            throws LogoutClientException, LogoutServerException {

        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            // Validate the signature of the logout token.
            if (!JWTSignatureValidationUtils.validateSignature(signedJWT, identityProvider)) {
                throw new LogoutClientException(ErrorMessages.LOGOUT_TOKEN_SIGNATURE_VALIDATION_FAILED.getCode(),
                        ErrorMessages.LOGOUT_TOKEN_SIGNATURE_VALIDATION_FAILED.getMessage());
            }
            // Validate the audience claim.
            if (!validateAud(claimsSet.getAudience(), identityProvider)) {
                throw new LogoutClientException(ErrorMessages.LOGOUT_TOKEN_AUD_CLAIM_VALIDATION_FAILED.getCode(),
                        ErrorMessages.LOGOUT_TOKEN_AUD_CLAIM_VALIDATION_FAILED.getMessage());
            }
            // Validate the iat claim.
            validateIat(claimsSet.getIssueTime());
            // Validate events claim.
            validateEvent((JSONObject) claimsSet.getClaim(OIDCAuthenticatorConstants.Claim.EVENTS));
            // Validate nonce.
            validateNonce(claimsSet);
            // Validate sub claim.
            if (!isSubExists(claimsSet)) {
                throw new LogoutClientException(ErrorMessages.LOGOUT_TOKEN_SUB_CLAIM_VALIDATION_FAILED.getCode(),
                        ErrorMessages.LOGOUT_TOKEN_SUB_CLAIM_VALIDATION_FAILED.getMessage());
            }
        } catch (ParseException e) {
            throw handleLogoutClientException(ErrorMessages.LOGOUT_TOKEN_PARSING_FAILURE, e);
        } catch (JOSEException | IdentityOAuth2Exception e) {
            throw handleLogoutServerException(ErrorMessages.LOGOUT_TOKEN_SIGNATURE_VALIDATION_FAILED, e);
        }
    }

    /**
     * Do the aud claim validation according to OIDC back-channel logout specification.
     *
     * @param aud
     * @param idp
     * @return boolean if validation is successful.
     */
    private boolean validateAud(List<String> aud, IdentityProvider idp) {

        String clientId = null;
        // Get the client id from the authenticator config.
        for (Property property : idp.getDefaultAuthenticatorConfig().getProperties()) {
            String propertyName = property.getName();
            if (propertyName.equals(OIDCAuthenticatorConstants.IdPConfParams.CLIENT_ID)) {
                clientId = property.getValue();
                break;
            }
        }
        // Check whether the client id exist in the aud claim.
        if (StringUtils.isNotBlank(clientId)) {
            for (String audience : aud) {
                if (audience.equals(clientId)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Do the iat claim validation according to OIDC back-channel logout specification
     * Read the authenticator configs to check whether the iat validation is enabled and if enabled the get the
     * validity period.
     *
     * @param iat
     * @return boolean if validation is successful.
     * @throws LogoutClientException
     */
    private boolean validateIat(Date iat) throws LogoutClientException {

        if (iat == null) {
            throw new LogoutClientException(
                    ErrorMessages.LOGOUT_TOKEN_IAT_VALIDATION_FAILED.getCode(),
                    ErrorMessages.LOGOUT_TOKEN_IAT_VALIDATION_FAILED.getMessage());
        }
        if (Boolean.parseBoolean(getAuthenticatorConfig().getParameterMap()
                .get(OIDCAuthenticatorConstants.BackchannelLogout.ENABLE_IAT_VALIDATION))) {
            int iatValidityPeriod =
                    Integer.parseInt(getAuthenticatorConfig().getParameterMap()
                            .get(OIDCAuthenticatorConstants.BackchannelLogout.IAT_VALIDITY_PERIOD));
            long issuedAtTimeMillis = iat.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            if (currentTimeInMillis - issuedAtTimeMillis > (long) iatValidityPeriod * 60 * 1000) {
                if (log.isDebugEnabled()) {
                    log.debug("Logout token is used after iat validity period." +
                            ", iat validity period(m) : " + iatValidityPeriod +
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
        return true;
    }

    /**
     * Do the sid claim validation.
     *
     * @param claimsSet
     * @return boolean if validation is successful.
     */
    private boolean isSidExists(JWTClaimsSet claimsSet) {

        return StringUtils.isNotBlank((String) claimsSet.getClaim(OIDCAuthenticatorConstants.Claim.SID));
    }

    /**
     * Do the sub claim validation.
     *
     * @param claimsSet
     * @return boolean if validation is successful.
     */
    private boolean isSubExists(JWTClaimsSet claimsSet) {

        return StringUtils.isNotBlank(claimsSet.getSubject());
    }

    /**
     * Do the event claim validation according to OIDC back-channel logout specification.
     *
     * @param event
     * @return boolean if validation is successful.
     * @throws LogoutClientException
     */
    private void validateEvent(JSONObject event) throws LogoutClientException {

        if (event == null ||
                !StringUtils.equals(event.getAsString(OIDCAuthenticatorConstants.Claim.BACKCHANNEL_LOGOUT_EVENT),
                        OIDCAuthenticatorConstants.Claim.BACKCHANNEL_LOGOUT_EVENT_CLAIM)) {
            throw new LogoutClientException(ErrorMessages.LOGOUT_TOKEN_EVENT_CLAIM_VALIDATION_FAILED.getCode(),
                    ErrorMessages.LOGOUT_TOKEN_EVENT_CLAIM_VALIDATION_FAILED.getMessage());
        }
    }

    /**
     * Do the nonce claim validation according to OIDC back-channel logout specification.
     *
     * @param claimsSet
     * @return boolean if validation is successful.
     * @throws LogoutClientException
     */
    private boolean validateNonce(JWTClaimsSet claimsSet) throws LogoutClientException {

        if (StringUtils.isNotBlank((String) claimsSet.getClaim(OIDCAuthenticatorConstants.Claim.NONCE))) {
            throw new LogoutClientException(ErrorMessages.LOGOUT_TOKEN_NONCE_CLAIM_VALIDATION_FAILED.getCode(),
                    ErrorMessages.LOGOUT_TOKEN_NONCE_CLAIM_VALIDATION_FAILED.getMessage());
        }
        return true;
    }

    /**
     * Get the OIDC authenticator configs from the xml file.
     *
     * @return AuthenticatorConfig.
     */
    protected AuthenticatorConfig getAuthenticatorConfig() {

        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(AUTHENTICATOR_NAME);
        if (authConfig == null) {
            authConfig = new AuthenticatorConfig();
            authConfig.setParameterMap(new HashMap<>());
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
                    OIDC_BACKCHANNEL_LOGOUT_ENDPOINT_URL_PATTERN.matcher(identityRequest.getRequestURI());
            if (registerMatcher.matches()) {
                canHandle = true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Can handle: " + canHandle + " by OIDC FederatedIdpInitLogoutProcessor.");
        }
        return canHandle;
    }

    /**
     * Handle logout server exceptions.
     *
     * @param error Error description.
     * @return LogoutServerException.
     */
    private LogoutServerException handleLogoutServerException(OIDCErrorConstants.ErrorMessages error, String data) {

        if (log.isDebugEnabled()) {
            log.debug(error.getMessage() + "Error code:" + error.getCode());
        }
        return new LogoutServerException(error.getCode(), String.format(error.getMessage(), data));
    }

    /**
     * Handle logout server exceptions.
     *
     * @param error Error description.
     * @param data  relevant data.
     * @param e     Throwable.
     * @return LogoutServerException.
     */
    private LogoutServerException handleLogoutServerException(OIDCErrorConstants.ErrorMessages error,
                                                              Throwable e, String data) {

        if (log.isDebugEnabled()) {
            log.debug(String.format(error.getMessage(), data) + "Error code:" + error.getCode());
        }
        return new LogoutServerException(error.getCode(), String.format(error.getMessage(), data), e);
    }

    /**
     * Handle logout server exceptions.
     *
     * @param error Error description.
     * @param e     Throwable.
     * @return LogoutServerException.
     */
    private LogoutServerException handleLogoutServerException(OIDCErrorConstants.ErrorMessages error, Throwable e) {

        if (log.isDebugEnabled()) {
            log.debug(error.getMessage() + "Error code:" + error.getCode());
        }
        return new LogoutServerException(error.getCode(), error.getMessage(), e);
    }

    /**
     * Handle logout client exceptions.
     *
     * @param error Error description.
     * @param e     Throwable.
     * @return LogoutClientException.
     */
    private LogoutClientException handleLogoutClientException(OIDCErrorConstants.ErrorMessages error, Throwable e) {

        if (log.isDebugEnabled()) {
            log.debug(error.getMessage() + "Error code:" + error.getCode());
        }
        return new LogoutClientException(error.getCode(), error.getMessage(), e);
    }

    /**
     * Get the identity provider from issuer and tenant domain.
     *
     * @param jwtIssuer
     * @param tenantDomain
     * @return IdentityProvider.
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
            if ((identityProvider != null) && (StringUtils.equalsIgnoreCase(identityProvider.getIdentityProviderName(),
                    OIDCAuthenticatorConstants.BackchannelLogout.DEFAULT_IDP_NAME))) {
                // Check whether this jwt was issued by the resident identity provider.
                identityProvider = getResidentIDPForIssuer(tenantDomain, jwtIssuer);
                if (identityProvider == null) {
                    throw handleLogoutServerException(ErrorMessages.NO_REGISTERED_IDP_FOR_ISSUER, jwtIssuer);
                }
            }
        } catch (IdentityProviderManagementException e) {
            throw handleLogoutServerException(ErrorMessages.RETRIEVING_IDENTITY_PROVIDER_FAILED, e);
        }
        return identityProvider;
    }

    /**
     * Get the resident identity provider from issuer and tenant domain.
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
            throw handleLogoutServerException(ErrorMessages.GETTING_RESIDENT_IDP_FAILED, tenantDomain);
        }
        FederatedAuthenticatorConfig[] fedAuthnConfigs = residentIdentityProvider.getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        if (oauthAuthenticatorConfig != null) {
            issuer = IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                    OIDCAuthenticatorConstants.BackchannelLogout.OIDC_IDP_ENTITY_ID).getValue();
        }
        return jwtIssuer.equals(issuer) ? residentIdentityProvider : null;
    }

}
