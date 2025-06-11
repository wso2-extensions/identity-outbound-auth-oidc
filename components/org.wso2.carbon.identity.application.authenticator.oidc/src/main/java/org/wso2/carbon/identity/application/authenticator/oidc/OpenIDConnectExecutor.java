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
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCCommonUtil;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.user.api.UserStoreException;

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
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE;
import static org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCCommonUtil.isUserIdFoundAmongClaims;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.OAuth2.SCOPES;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ErrorMessages.ERROR_CODE_EXECUTOR_FAILURE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.REDIRECT_URL;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;

/**
 * OIDC Social Signup Executor.
 */
public class OpenIDConnectExecutor implements Executor {

    private static final Log LOG = LogFactory.getLog(OpenIDConnectExecutor.class);
    private static final String OIDC_SIGNUP_EXECUTOR = "OpenIDConnectExecutor";
    private static final String[] NON_USER_ATTRIBUTES = new String[]{"at_hash", "iss", "iat", "exp", "aud", "azp",
            "nonce"};
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    private static String getSubjectFromUserIDClaimURI(ExternalIdPConfig idpConfig, Map<String, Object> idTokenClaims,
                                                       String tenantDomain) {

        String userIdClaimUri = idpConfig.getUserIdClaimUri();
        try {
            return OIDCCommonUtil.getSubjectFromUserIDClaimURI(idpConfig, idTokenClaims, tenantDomain);
        } catch (ClaimMetadataException ex) {
            LOG.error("Error while retrieving claim URI for user id claim: " + userIdClaimUri, ex);
        }
        return null;
    }

    /**
     * This method is used to throw a Flow engine exception with the given error code and error message.
     *
     * @param errorDescription Error description to be set in the exception.
     * @param exception        Exception
     * @return FlowEngineServerException
     */
    private static FlowEngineServerException handleFlowEngineServerException(
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

    @Override
    public String getName() {

        return OIDC_SIGNUP_EXECUTOR;
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext flowExecutionContext) throws FlowEngineException {

        if (isInitialRequest(flowExecutionContext)) {
            return initiateSocialSignup(flowExecutionContext);
        }
        return processResponse(flowExecutionContext);
    }

    @Override
    public List<String> getInitiationData() {

        return Collections.emptyList();
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext flowExecutionContext) throws FlowEngineException {

        return null;
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

    protected String getAuthenticateUser(Map<String, Object> oidcClaims) {

        return (String) oidcClaims.get(OIDCAuthenticatorConstants.Claim.SUB);
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

        OAuthClientRequest authzRequest;
        String scopes = getScope(authenticatorProperties);
        String clientId = authenticatorProperties.get(CLIENT_ID);
        String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);
        String nonce = UUID.randomUUID().toString();

        try {
            authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                    .setRedirectURI(callbackUrl)
                    .setResponseType(OAUTH2_GRANT_TYPE_CODE)
                    .setScope(scopes)
                    .setState(state)
                    .setParameter(NONCE, nonce).buildQueryMessage();
            return authzRequest.getLocationUri();
        } catch (OAuthSystemException exception) {
            throw handleFlowEngineServerException("Error while building the authorization request.", exception);
        }
    }

    protected OAuthClientResponse requestAccessToken(FlowExecutionContext flowExecutionContext, String code)
            throws FlowEngineException {

        OAuthClientRequest accessTokenRequest = getAccessTokenRequest(flowExecutionContext.getAuthenticatorProperties(), code,
                flowExecutionContext.getCallbackUrl());

        // Create OAuth client that uses custom http client under the hood.
        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        return getOauthResponse(oAuthClient, accessTokenRequest);
    }

    protected OAuthClientRequest getAccessTokenRequest(Map<String, String> authenticatorProperties, String code,
                                                       String callbackUrl)
            throws FlowEngineException {

        String clientId = authenticatorProperties.get(CLIENT_ID);
        String clientSecret = authenticatorProperties.get(CLIENT_SECRET);
        String tokenEndPoint = getTokenEndpoint(authenticatorProperties);

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
            }
        } catch (OAuthSystemException | URLBuilderException exception) {
            throw handleFlowEngineServerException("Error while building the access token request.", exception);
        }
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

    private Map<String, Object> resolveUserAttributes(FlowExecutionContext flowExecutionContext, String code)
            throws FlowEngineException {

        OAuthClientResponse oAuthResponse = requestAccessToken(flowExecutionContext, code);
        String accessToken = resolveAccessToken(oAuthResponse);
        String idToken = resolveIDToken(oAuthResponse);
        Map<ClaimMapping, String> remoteClaimsMap = new HashMap<>();
        Map<String, Object> jwtAttributeMap = new HashMap<>();
        jwtAttributeMap.putAll(getIdTokenClaims(idToken));
        jwtAttributeMap.putAll(getClaimsViaUserInfo(accessToken, flowExecutionContext.getAuthenticatorProperties()));

        String attributeSeparator = getMultiAttributeSeparator(flowExecutionContext.getTenantDomain());

        jwtAttributeMap.entrySet().stream()
                .filter(entry -> !ArrayUtils.contains(NON_USER_ATTRIBUTES, entry.getKey()))
                .forEach(entry -> OIDCCommonUtil.buildClaimMappings(remoteClaimsMap, entry, attributeSeparator));


        return resolveLocalClaims(flowExecutionContext, remoteClaimsMap, jwtAttributeMap);
    }

    private Map<String, Object> resolveLocalClaims(FlowExecutionContext flowExecutionContext,
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
            localClaimsMap.putIfAbsent(USERNAME_CLAIM_URI, getAuthenticatedUserId(flowExecutionContext, jwtAttributeMap));
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
            throw handleFlowEngineServerException("Error while getting the access token.", e);
        }
        return oAuthResponse;
    }

    private Map<String, Object> getIdTokenClaims(String idToken) {

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

    private String getAuthenticatedUserId(FlowExecutionContext flowExecutionContext, Map<String, Object> idTokenClaims)
            throws FlowEngineException {

        String authenticatedUserId;
        if (isUserIdFoundAmongClaims(flowExecutionContext.getAuthenticatorProperties())) {
            authenticatedUserId = getSubjectFromUserIDClaimURI(flowExecutionContext.getExternalIdPConfig(), idTokenClaims, flowExecutionContext
                    .getTenantDomain());
            if (StringUtils.isNotBlank(authenticatedUserId)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authenticated user id: " + authenticatedUserId + " was found among id_token claims.");
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Subject claim could not be found amongst id_token claims. Defaulting to the 'sub' "
                            + "attribute in id_token as authenticated user id.");
                }
                // Default to userId sent as the 'sub' claim.
                authenticatedUserId = getAuthenticateUser(idTokenClaims);
            }
        } else {
            authenticatedUserId = getAuthenticateUser(idTokenClaims);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authenticated user id: " + authenticatedUserId + " retrieved from the 'sub' claim.");
            }
        }
        if (authenticatedUserId == null) {
            throw handleFlowEngineServerException("Error while resolving user identifier.", null);
        }
        return authenticatedUserId;
    }

    private String getMultiAttributeSeparator(String tenantDomain) throws FlowEngineServerException {

        try {
            return OIDCCommonUtil.getMultiAttributeSeparator(tenantDomain);
        } catch (UserStoreException e) {
            throw handleFlowEngineServerException("Error while retrieving the attribute separator.", e);
        }
    }

    private Map<String, String> getClaimsViaUserInfo(String accessToken,
                                                     Map<String, String> authenticatorProperties) {

        Map<String, String> claims = new HashMap<>();
        try {
            String url = getUserInfoEndpoint(authenticatorProperties);
            String json = OIDCCommonUtil.triggerRequest(url, accessToken);
            Map<ClaimMapping, String> claimMappings = OIDCCommonUtil.extractUserClaimsFromJsonPayload(json);
            if (!claimMappings.isEmpty()) {
                claims = claimMappings.entrySet().stream()
                        .collect(Collectors.toMap(
                                entry -> entry.getKey().getLocalClaim().getClaimUri(),
                                Map.Entry::getValue
                        ));
            }
        } catch (IOException e) {
            LOG.error("Communication error occurred while accessing user info endpoint", e);
        }
        return claims;
    }
}
