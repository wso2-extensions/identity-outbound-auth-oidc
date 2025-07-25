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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCCommonUtil;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.apache.oltu.oauth2.common.message.types.GrantType.AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.Claim.NONCE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.IS_BASIC_AUTH_ENABLED;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.LogConstants.ActionIDs.INVOKE_TOKEN_ENDPOINT;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.LogConstants.ActionIDs.INVOKE_USER_INFO_ENDPOINT;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.LogConstants.OUTBOUND_AUTH_OIDC_SERVICE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.OAuth2.SCOPES;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ErrorMessages.ERROR_CODE_EXECUTOR_FAILURE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.REDIRECT_URL;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;
import static org.wso2.carbon.utils.DiagnosticLog.ResultStatus.FAILED;
import static org.wso2.carbon.utils.DiagnosticLog.ResultStatus.SUCCESS;

/**
 * OIDC Social Signup Executor.
 */
public class OpenIDConnectExecutor implements Executor {

    private static final Log LOG = LogFactory.getLog(OpenIDConnectExecutor.class);
    private static final String OIDC_SIGNUP_EXECUTOR = "OpenIDConnectExecutor";
    protected static final String[] NON_USER_ATTRIBUTES = new String[]{"at_hash", "iss", "iat", "exp", "aud", "azp",
            "nonce"};
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    private static final String USERNAME_PATTERN_VALIDATION_SKIPPED = "isUsernamePatternValidationSkipped";

    @Override
    public String getName() {

        return OIDC_SIGNUP_EXECUTOR;
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext flowExecutionContext) {

        try {
            if (isInitialRequest(flowExecutionContext)) {
                return initiateSocialSignup(flowExecutionContext);
            }
            return processResponse(flowExecutionContext);
        } catch (FlowEngineException e) {
            LOG.error("Error while executing OpenID Connect executor.", e);
            ExecutorResponse executorResponse = new ExecutorResponse();
            executorResponse.setResult(STATUS_ERROR);
            executorResponse.setErrorMessage("Error while executing " + this.getName() + ": " + e.getDescription());
            return executorResponse;
        }
    }

    @Override
    public List<String> getInitiationData() {

        return Collections.emptyList();
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext flowExecutionContext) {

        return null;
    }

    /**
     * This method is used to throw a Flow engine exception with the given error code and error message.
     *
     * @param errorDescription Error description to be set in the exception.
     * @param exception        Exception
     * @return FlowEngineServerException
     */
    protected static FlowEngineServerException handleFlowEngineServerException(
            String errorDescription, Exception exception) {

        if (exception != null) {
            return new FlowEngineServerException(
                    ERROR_CODE_EXECUTOR_FAILURE.getCode(),
                    ERROR_CODE_EXECUTOR_FAILURE.getMessage(),
                    errorDescription,
                    exception);
        }
        return new FlowEngineServerException(
                ERROR_CODE_EXECUTOR_FAILURE.getCode(),
                ERROR_CODE_EXECUTOR_FAILURE.getMessage(),
                errorDescription);
    }

    public String getUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL);
    }

    public String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
    }

    public String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
    }

    public String getScope(Map<String, String> authenticatorProperties) {

        String scope = authenticatorProperties.get(SCOPES);
        if (scope == null) {
            scope = OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE;
        }
        return scope;
    }

    protected String getAuthenticatedUserIdentifier(Map<String, Object> oidcClaims) {

        return (String) oidcClaims.get(OIDCAuthenticatorConstants.Claim.SUB);
    }

    protected Map<String, String> getAdditionalQueryParams(Map<String, String> authenticatorProperties) {

        return new HashMap<>();
    }

    private boolean isInitialRequest(FlowExecutionContext flowExecutionContext) {

        Map<String, String> userInputs = flowExecutionContext.getUserInputData();
        return userInputs == null || userInputs.isEmpty() || userInputs.get(OAUTH2_GRANT_TYPE_CODE) == null ||
                userInputs.get(OAUTH2_PARAM_STATE) == null;
    }

    private ExecutorResponse processResponse(FlowExecutionContext flowExecutionContext) throws FlowEngineException {

        Map<String, String> userInputs = flowExecutionContext.getUserInputData();

        if (!StringUtils.equals(userInputs.get(OAUTH2_PARAM_STATE),
                flowExecutionContext.getProperty(OAUTH2_PARAM_STATE).toString())) {
            throw handleFlowEngineServerException("State parameter mismatch.", null);
        }

        ExecutorResponse response = new ExecutorResponse(STATUS_COMPLETE);
        response.setUpdatedUserClaims(resolveUserAttributes(flowExecutionContext, userInputs.get(OAUTH2_GRANT_TYPE_CODE)));
        return response;
    }

    private ExecutorResponse initiateSocialSignup(FlowExecutionContext flowExecutionContext)
            throws FlowEngineException {

        ExecutorResponse executorResponse = new ExecutorResponse();
        executorResponse.setResult(STATUS_EXTERNAL_REDIRECTION);
        List<String> requiredData = new ArrayList<>();
        requiredData.add(OAUTH2_GRANT_TYPE_CODE);
        requiredData.add(OAUTH2_PARAM_STATE);
        String state = UUID.randomUUID() + "," + OIDCAuthenticatorConstants.LOGIN_TYPE;
        executorResponse.setRequiredData(requiredData);
        executorResponse.setAdditionalInfo(getAdditionalData(flowExecutionContext.getAuthenticatorProperties(),
                flowExecutionContext.getPortalUrl(), state));

        Map<String, Object> contextProperties = new HashMap<>();
        contextProperties.put(OAUTH2_PARAM_STATE, state);
        executorResponse.setContextProperty(contextProperties);
        return executorResponse;
    }

    private Map<String, String> getAdditionalData(Map<String, String> authenticatorProperties,
                                                  String callbackUrl, String state)
            throws FlowEngineException {

        Map<String, String> additionalData = new HashMap<>();
        additionalData.put(REDIRECT_URL, getRedirectUrl(authenticatorProperties, callbackUrl, state));
        additionalData.put(OAUTH2_PARAM_STATE, state);
        return additionalData;
    }

    private String getRedirectUrl(Map<String, String> authenticatorProperties, String callbackUrl, String state)
            throws FlowEngineException {

        String scopes = getScope(authenticatorProperties);
        Map<String, String> additionalQueryParams = getAdditionalQueryParams(authenticatorProperties);
        String clientId = authenticatorProperties.get(CLIENT_ID);
        String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);
        String nonce = UUID.randomUUID().toString();

        try {
            OAuthClientRequest.AuthenticationRequestBuilder authRequestBuilder =
                    OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                    .setRedirectURI(callbackUrl)
                    .setResponseType(OAUTH2_GRANT_TYPE_CODE)
                    .setScope(scopes)
                    .setState(state)
                    .setParameter(NONCE, nonce);
            for (Map.Entry<String, String> entry : additionalQueryParams.entrySet()) {
                authRequestBuilder.setParameter(entry.getKey(), entry.getValue());
            }
            return authRequestBuilder.buildQueryMessage().getLocationUri();
        } catch (OAuthSystemException exception) {
            throw handleFlowEngineServerException("Error while building the authorization request.", exception);
        }
    }

    protected OAuthClientResponse requestAccessToken(FlowExecutionContext flowExecutionContext, String code)
            throws FlowEngineException {

        OAuthClientRequest accessTokenRequest = getAccessTokenRequest(flowExecutionContext.getAuthenticatorProperties(), code,
                flowExecutionContext.getPortalUrl());

        // Create OAuth client that uses custom http client under the hood.
        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        return getOauthResponse(oAuthClient, accessTokenRequest);
    }

    protected OAuthClientRequest getAccessTokenRequest(Map<String, String> authenticatorProperties, String code,
                                                       String callbackUrl)
            throws FlowEngineException {

        Map<String, Object> loggerInputs = new HashMap<>();
        String clientId = authenticatorProperties.get(CLIENT_ID);
        String clientSecret = authenticatorProperties.get(CLIENT_SECRET);
        String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
        loggerInputs.put("clientId", clientId);
        loggerInputs.put("endpoint", tokenEndPoint);
        loggerInputs.put("redirect url", callbackUrl);

        boolean isHTTPBasicAuth = Boolean.parseBoolean(authenticatorProperties.get(IS_BASIC_AUTH_ENABLED));
        OAuthClientRequest accessTokenRequest;
        try {
            if (isHTTPBasicAuth) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authenticating to token endpoint: " + tokenEndPoint + " with HTTP basic " +
                            "authentication scheme.");
                }
                OAuthClientRequest.TokenRequestBuilder tokenRequestBuilder = OAuthClientRequest
                        .tokenLocation(tokenEndPoint)
                        .setGrantType(AUTHORIZATION_CODE)
                        .setRedirectURI(callbackUrl)
                        .setCode(code);

                accessTokenRequest = tokenRequestBuilder.buildBodyMessage();
                String base64EncodedCredential = new String(Base64.encodeBase64((clientId + ":" +
                        clientSecret).getBytes()));
                accessTokenRequest.addHeader(OAuth.HeaderType.AUTHORIZATION, "Basic " + base64EncodedCredential);
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authenticating to token endpoint: " + tokenEndPoint + " including client credentials "
                            + "in request body.");
                }
                OAuthClientRequest.TokenRequestBuilder tokenRequestBuilder = OAuthClientRequest
                        .tokenLocation(tokenEndPoint)
                        .setGrantType(AUTHORIZATION_CODE)
                        .setClientId(clientId)
                        .setClientSecret(clientSecret)
                        .setRedirectURI(callbackUrl)
                        .setCode(code);
                accessTokenRequest = tokenRequestBuilder.buildBodyMessage();
            }
            // set 'Origin' header to access token request.
            if (accessTokenRequest != null) {
                // fetch the 'Hostname' configured in carbon.xml
                String serverURL = ServiceURLBuilder.create().build().getAbsolutePublicURL();
                accessTokenRequest.addHeader(OIDCAuthenticatorConstants.HTTP_ORIGIN_HEADER, serverURL);
                loggerInputs.put("origin", serverURL);
            }
        } catch (OAuthSystemException | URLBuilderException exception) {
            throw handleFlowEngineServerException("Error while building the access token request.", exception);
        }
        logDiagnostic("Building the access token request", SUCCESS, INVOKE_TOKEN_ENDPOINT, loggerInputs);
        return accessTokenRequest;
    }

    protected String resolveAccessToken(OAuthClientResponse oAuthResponse) throws FlowEngineException {

        String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);

        if (StringUtils.isBlank(accessToken)) {
            throw handleFlowEngineServerException("Access token is empty or null.", null);
        }
        return accessToken;
    }

    private String resolveIDToken(OAuthClientResponse oAuthResponse) throws FlowEngineException {

        String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);

        if (StringUtils.isBlank(idToken)) {
            throw handleFlowEngineServerException("ID token is empty or null.", null);
        }
        return idToken;
    }

    protected Map<String, Object> resolveUserAttributes(FlowExecutionContext flowExecutionContext, String code)
            throws FlowEngineException {

        OAuthClientResponse oAuthResponse = requestAccessToken(flowExecutionContext, code);
        String accessToken = resolveAccessToken(oAuthResponse);
        String idToken = resolveIDToken(oAuthResponse);
        Map<ClaimMapping, String> remoteClaimsMap = new HashMap<>();
        Map<String, Object> jwtAttributeMap = new HashMap<>();
        if (idToken != null) {
            jwtAttributeMap.putAll(getIdTokenClaims(idToken));
        }
        jwtAttributeMap.putAll(getClaimsViaUserInfo(accessToken, flowExecutionContext.getAuthenticatorProperties()));

        String attributeSeparator = getMultiAttributeSeparator(flowExecutionContext.getTenantDomain());

        jwtAttributeMap.entrySet().stream()
                .filter(entry -> !ArrayUtils.contains(NON_USER_ATTRIBUTES, entry.getKey()))
                .forEach(entry -> OIDCCommonUtil.buildClaimMappings(remoteClaimsMap, entry, attributeSeparator));


        return resolveLocalClaims(flowExecutionContext, remoteClaimsMap, jwtAttributeMap);
    }

    protected Map<String, Object> resolveLocalClaims(FlowExecutionContext flowExecutionContext,
                                                   Map<ClaimMapping, String> remoteClaimMappings,
                                                   Map<String, Object> jwtAttributeMap) throws FlowEngineException {

        Map<String, Object> localClaimsMap = new HashMap<>();
        Map<String, String> remoteClaimsMap = remoteClaimMappings.entrySet().stream()
                .collect(Collectors.toMap(entry -> entry.getKey().getLocalClaim().getClaimUri(), Map.Entry::getValue));
        try {
            Map<String, String> localToIdPClaimMap =
                    ClaimMetadataHandler.getInstance().getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT,
                            remoteClaimsMap.keySet(),
                            flowExecutionContext.getTenantDomain(),
                            true);
            remoteClaimsMap.forEach((remoteKey, remoteValue) ->
                    localToIdPClaimMap.entrySet().stream()
                            .filter(entry -> entry.getValue().equals(remoteKey))
                            .map(Map.Entry::getKey)
                            .findFirst()
                            .ifPresent(localKey -> localClaimsMap.put(localKey, remoteValue))
            );
            String defaultSubject = getAuthenticatedUserIdentifier(jwtAttributeMap);
            String subject = (String) localClaimsMap.getOrDefault(USERNAME_CLAIM_URI, defaultSubject);
            flowExecutionContext.getFlowUser().addFederatedAssociation(flowExecutionContext.getExternalIdPConfig().getIdPName(),
                    subject);
            localClaimsMap.putIfAbsent(USERNAME_CLAIM_URI, getFederatedUsername(flowExecutionContext, localClaimsMap,
                    defaultSubject));
            return localClaimsMap;
        } catch (ClaimMetadataException e) {
            throw handleFlowEngineServerException("Error while resolving local claims.", e);
        }
    }

    private OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws FlowEngineException {

        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            logDiagnostic("Error occurred while requesting access token.", FAILED, INVOKE_TOKEN_ENDPOINT, Collections.emptyMap());
            throw handleFlowEngineServerException("Error while getting the access token.", e);
        }
        return oAuthResponse;
    }

    protected Map<String, Object> getIdTokenClaims(String idToken) {

        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = OIDCCommonUtil.parseIDToken(idToken);
        } catch (ParseException e) {
            LOG.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }

    private String getFederatedUsername(FlowExecutionContext flowExecutionContext, Map<String, Object> localClaims,
                                        String defaultSubject)
            throws FlowEngineException {


        String federatedUsername = null;
        // Check if the user ID claim URI is configured in the IDP config. If it is configured, use that claim URI
        // to get the federated user identifier.
        ExternalIdPConfig idpConfig = flowExecutionContext.getExternalIdPConfig();
        String userIdClaimUriInLocalDialect = getUserIdClaimUriInLocalDialect(idpConfig);
        if (isUserNameFoundFromUserIDClaimURI(localClaims, userIdClaimUriInLocalDialect)) {
            federatedUsername = (String) localClaims.get(userIdClaimUriInLocalDialect);
        }

        String federatedUserId = getFederatedUserId(flowExecutionContext, defaultSubject);

        // If the user ID claim URI is not configured or the claim value is not available, set the federated user ID
        // as the federated username.
        if (StringUtils.isBlank(federatedUsername) && StringUtils.isNotBlank(federatedUserId)) {
            // Set the skip username pattern validation thread local to true to skip the username pattern validation
            // for the federated user ID.
            UserCoreUtil.setSkipUsernamePatternValidationThreadLocal(true);
            flowExecutionContext.setProperty(USERNAME_PATTERN_VALIDATION_SKIPPED, true);
            federatedUsername = federatedUserId;
        }
        return federatedUsername;
    }

    private static String getFederatedUserId(FlowExecutionContext flowExecutionContext, String defaultSubject)
            throws FlowEngineServerException {

        String federatedUserId;
        ExternalIdPConfig idpConfig = flowExecutionContext.getExternalIdPConfig();
        int tenantId = IdentityTenantUtil.getTenantId(flowExecutionContext.getTenantDomain());
        try {
            int idpId = Integer.parseInt(idpConfig.getIdentityProvider().getId());
            federatedUserId = UserSessionStore.getInstance().getFederatedUserId(defaultSubject, tenantId,
                    idpId);
            if (StringUtils.isBlank(federatedUserId)) {
                federatedUserId = UUID.randomUUID().toString();
                UserSessionStore.getInstance().storeUserData(federatedUserId, defaultSubject, tenantId, idpId);
            }
        } catch (UserSessionException e) {
            LOG.error("Error checking federated user ID existence for user in flow: "
                    + flowExecutionContext.getContextIdentifier(), e);
            throw handleFlowEngineServerException("Error checking federated user ID existence.", e);
        }
        return federatedUserId;
    }

    protected String getMultiAttributeSeparator(String tenantDomain) throws FlowEngineServerException {

        try {
            return OIDCCommonUtil.getMultiAttributeSeparator(tenantDomain);
        } catch (UserStoreException e) {
            throw handleFlowEngineServerException("Error while retrieving the attribute separator.", e);
        }
    }

    protected Map<String, String> getClaimsViaUserInfo(String accessToken,
                                                     Map<String, String> authenticatorProperties) {

        Map<String, String> claims = new HashMap<>();
        String url = getUserInfoEndpoint(authenticatorProperties);
        Map<String, Object> inputsForLogger = new HashMap<>();
        inputsForLogger.put("endpoint", url);
        try {
            String json = OIDCCommonUtil.triggerRequest(url, accessToken);
            Map<ClaimMapping, String> claimMappings = OIDCCommonUtil.extractUserClaimsFromJsonPayload(json);
            if (!claimMappings.isEmpty()) {
                claims = claimMappings.entrySet().stream()
                        .collect(Collectors.toMap(
                                entry -> entry.getKey().getLocalClaim().getClaimUri(),
                                Map.Entry::getValue
                        ));
            }
            logDiagnostic("User claims retrieved successfully from user info endpoint.", SUCCESS,
                          INVOKE_USER_INFO_ENDPOINT, inputsForLogger);
        } catch (IOException e) {
            logDiagnostic("Error occurred while accessing user info endpoint.", FAILED, INVOKE_USER_INFO_ENDPOINT,
                          inputsForLogger);
        }
        return claims;
    }

    /**
     * This method is used to log the diagnostic information.
     *
     * @param message  Message to be logged.
     * @param status   Status of the log.
     * @param actionId Action ID.
     */
    protected void logDiagnostic(String message, DiagnosticLog.ResultStatus status, String actionId,
                               Map<String, Object> inputParams) {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(
                    new DiagnosticLog.DiagnosticLogBuilder(getDiagnosticLogComponentId(), actionId)
                            .resultMessage(message)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .inputParams(inputParams)
                            .resultStatus(status)
            );
        }
    }

    /**
     * Get the component ID for the diagnostic log.
     *
     * @return Component ID.
     */
    protected String getDiagnosticLogComponentId() {

        return OUTBOUND_AUTH_OIDC_SERVICE;
    }

    private String getUserIdClaimUriInLocalDialect(ExternalIdPConfig idPConfig) {
        // get external identity provider user id claim URI.
        String userIdClaimUri = idPConfig.getUserIdClaimUri();

        if (StringUtils.isBlank(userIdClaimUri)) {
            return null;
        }

        boolean useDefaultLocalIdpDialect = idPConfig.useDefaultLocalIdpDialect();
        if (useDefaultLocalIdpDialect) {
            return userIdClaimUri;
        } else {
            ClaimMapping[] claimMappings = idPConfig.getClaimMappings();
            if (!ArrayUtils.isEmpty(claimMappings)) {
                for (ClaimMapping claimMapping : claimMappings) {
                    if (userIdClaimUri.equals(claimMapping.getRemoteClaim().getClaimUri())) {
                        return claimMapping.getLocalClaim().getClaimUri();
                    }
                }
            }
        }

        return null;
    }

    private boolean isUserNameFoundFromUserIDClaimURI(Map<String, Object> localClaimValues, String
            userIdClaimUriInLocalDialect) {

        return StringUtils.isNotBlank(userIdClaimUriInLocalDialect) && StringUtils.isNotBlank
                ((String) localClaimValues.get(userIdClaimUriInLocalDialect));
    }
}
