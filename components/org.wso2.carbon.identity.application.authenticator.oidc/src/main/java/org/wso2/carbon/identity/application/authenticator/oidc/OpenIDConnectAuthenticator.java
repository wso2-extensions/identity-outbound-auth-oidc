/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.oidc;

import com.nimbusds.jose.util.JSONObjectUtils;
import net.minidev.json.JSONArray;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.internal.OpenIDConnectAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.oidc.model.OIDCStateInfo;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.base.IdentityConstants.FEDERATED_IDP_SESSION_ID;

public class OpenIDConnectAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -4154255583070524018L;

    private static final Log log = LogFactory.getLog(OpenIDConnectAuthenticator.class);
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    private static final String DYNAMIC_PARAMETER_LOOKUP_REGEX = "\\$\\{(\\w+)\\}";
    private static Pattern pattern = Pattern.compile(DYNAMIC_PARAMETER_LOOKUP_REGEX);
    private static final String[] NON_USER_ATTRIBUTES = new String[]{"at_hash", "iss", "iat", "exp", "aud", "azp"};

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        /* In the OIDC Authenticator, the canHandle() returns true whenever the state parameter for the request
        satisfy the loginType condition.
        This fails in a scenario as described in wso2/product-is#10057, where there
        are more than one redirections before the user is prompted for authentication and an authorization code is
        returned. In such scenarios as per the current behaviour, the OIDC Authenticator would call the
        processAuthenticationResponse, even if no code parameter is returned in the request.
        Also in cases described in wso2/product-is#10697, where making the authentication request to federated IDP
        even the response contains an error. In order to mitigate that in this code segment the error parameter is
        also checked before initiating the authentication request. */
        if (isInitialRequest(context, request)) {
            if (canHandle(request) || Boolean.TRUE.equals(request.getAttribute(FrameworkConstants.REQ_ATTR_HANDLED))) {
                if (getName().equals(context.getProperty(FrameworkConstants.LAST_FAILED_AUTHENTICATOR))) {
                    context.setRetrying(true);
                }
                initiateAuthenticationRequest(request, response, context);
                context.setCurrentAuthenticator(getName());
                context.setRetrying(false);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        }
        return super.process(request, response, context);
    }

    @Override
    protected void processLogoutResponse(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) {

        if (log.isDebugEnabled()) {
            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                log.debug("Handled logout response from service provider " + request.getParameter("sp") +
                        " in tenant domain " + IdentityTenantUtil.getTenantDomainFromContext());
            } else {
                log.debug("Handled logout response from service provider " + request.getParameter("sp") +
                        " in tenant domain " + request.getParameter("tenantDomain"));
            }
        }

    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isTraceEnabled()) {
            log.trace("Inside OpenIDConnectAuthenticator.canHandle()");
        }

        if (OIDCAuthenticatorConstants.LOGIN_TYPE.equals(getLoginType(request))) {
            return true;
        }

        // TODO : What if IdP failed?
        return false;
    }

    private boolean isInitialRequest(AuthenticationContext context, HttpServletRequest request) {

        return !context.isLogoutRequest() && !hasCodeParamInRequest(request) && !hasErrorParamInRequest(request);
    }

    private boolean hasErrorParamInRequest(HttpServletRequest request) {

        String error = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR);
        return StringUtils.isNotBlank(error);
    }

    private boolean hasCodeParamInRequest(HttpServletRequest request) {

        String code = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE);
        return StringUtils.isNotBlank(code);
    }

    /**
     * @return
     */
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        return null;
    }

    /**
     * Returns the callback URL of the IdP Hub.
     *
     * @param authenticatorProperties Authentication properties configured in OIDC federated authenticator
     *                                configuration.
     * @return Callback URL configured in OIDC federated authenticator configuration. If it is empty returns
     * /commonauth endpoint URL path as the default value.
     */
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        String callbackUrl = authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        if (StringUtils.isBlank(callbackUrl)) {
            try {
                callbackUrl = ServiceURLBuilder.create().addPath(FrameworkConstants.COMMONAUTH).build()
                        .getAbsolutePublicURL();
            } catch (URLBuilderException e) {
                throw new RuntimeException("Error occurred while building URL in tenant qualified mode.", e);
            }
        }
        return callbackUrl;
    }

    protected String getLogoutUrl(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(OIDCAuthenticatorConstants.IdPConfParams.OIDC_LOGOUT_URL);
    }

    /**
     * Returns the token endpoint of OIDC federated authenticator
     *
     * @param authenticatorProperties Authentication properties configured in OIDC federated authenticator
     *                                configuration.
     * @return Token endpoint configured in OIDC federated authenticator configuration.
     */
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
    }

    /**
     * @param state
     * @return
     */
    protected String getState(String state, Map<String, String> authenticatorProperties) {

        return state;
    }

    /**
     * @return
     */
    protected String getScope(String scope, Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(scope)) {
            scope = OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE;
        }
        return scope;
    }

    /**
     * @return
     */
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {

        return true;
    }

    /**
     * @param context
     * @param oidcClaims
     * @param oidcResponse
     * @return
     */

    protected String getAuthenticateUser(AuthenticationContext context, Map<String, Object> oidcClaims,
                                         OAuthClientResponse oidcResponse) {

        return (String) oidcClaims.get(OIDCAuthenticatorConstants.Claim.SUB);
    }

    protected String getCallBackURL(Map<String, String> authenticatorProperties) {

        return getCallbackUrl(authenticatorProperties);
    }

    protected String getQueryString(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(FrameworkConstants.QUERY_PARAMS);
    }

    /**
     * Get user info endpoint.
     *
     * @param token                   OAuthClientResponse
     * @param authenticatorProperties Map<String, String> (Authenticator property, Property value)
     * @return User info endpoint.
     */
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL);
    }

    /**
     * Get subject attributes.
     *
     * @param token                   OAuthClientResponse
     * @param authenticatorProperties Map<String, String> (Authenticator property, Property value)
     * @return Map<ClaimMapping, String> Claim mappings.
     */
    protected Map<ClaimMapping, String> getSubjectAttributes(OAuthClientResponse token,
                                                             Map<String, String> authenticatorProperties) {

        Map<ClaimMapping, String> claims = new HashMap<>();

        try {
            String accessToken = token.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);
            String url = getUserInfoEndpoint(token, authenticatorProperties);
            String json = sendRequest(url, accessToken);

            if (StringUtils.isBlank(json)) {
                if (log.isDebugEnabled()) {
                    log.debug("Empty JSON response from user info endpoint. Unable to fetch user claims." +
                            " Proceeding without user claims");
                }
                return claims;
            }

            Map<String, Object> jsonObject = JSONUtils.parseJSON(json);

            for (Map.Entry<String, Object> data : jsonObject.entrySet()) {
                String key = data.getKey();
                Object valueObject = data.getValue();

                if (valueObject != null) {
                    String value;
                    if (valueObject instanceof Object[]) {
                        value = StringUtils.join((Object[]) valueObject, FrameworkUtils.getMultiAttributeSeparator());
                    } else {
                        value = valueObject.toString();
                    }
                    claims.put(ClaimMapping.build(key, key, null, false), value);
                }

                if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)
                        && jsonObject.get(key) != null) {
                    log.debug("Adding claims from end-point data mapping : " + key + " - " + jsonObject.get(key)
                            .toString());
                }
            }
        } catch (IOException e) {
            log.error("Communication error occurred while accessing user info endpoint", e);
        }

        return claims;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
                String authorizationEP = getOIDCAuthzEndpoint(authenticatorProperties);
                String callbackurl = getCallbackUrl(authenticatorProperties);
                String state = getStateParameter(context, authenticatorProperties);

                OAuthClientRequest authzRequest;

                String queryString = getQueryString(authenticatorProperties);
                queryString = interpretQueryString(context, queryString, request.getParameterMap());
                Map<String, String> paramValueMap = new HashMap<>();

                if (StringUtils.isNotBlank(queryString)) {
                    String[] params = queryString.split("&");
                    for (String param : params) {
                        String[] intParam = param.split("=");
                        if (intParam.length >= 2) {
                            paramValueMap.put(intParam[0], intParam[1]);
                        }
                    }
                    context.setProperty(OIDCAuthenticatorConstants.OIDC_QUERY_PARAM_MAP_PROPERTY_KEY, paramValueMap);
                }
                queryString = getEvaluatedQueryString(paramValueMap);

                String scope = paramValueMap.get(OAuthConstants.OAuth20Params.SCOPE);
                scope = getScope(scope, authenticatorProperties);

                if (StringUtils.isNotBlank(queryString) && queryString.toLowerCase().contains("scope=") && queryString
                        .toLowerCase().contains("redirect_uri=")) {
                    authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                            .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE).setState(state)
                            .buildQueryMessage();
                } else if (StringUtils.isNotBlank(queryString) && queryString.toLowerCase().contains("scope=")) {
                    authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                            .setRedirectURI(callbackurl)
                            .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE).setState(state)
                            .buildQueryMessage();
                } else if (StringUtils.isNotBlank(queryString) && queryString.toLowerCase().contains("redirect_uri=")) {
                    authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                            .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                            .setScope(OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE).setState(state).buildQueryMessage();

                } else {
                    authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                            .setRedirectURI(callbackurl)
                            .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE).setScope(scope)
                            .setState(state).buildQueryMessage();
                }

                String loginPage = authzRequest.getLocationUri();
                String domain = request.getParameter("domain");

                if (StringUtils.isNotBlank(domain)) {
                    loginPage = loginPage + "&fidp=" + domain;
                }

                if (StringUtils.isNotBlank(queryString)) {
                    if (!queryString.startsWith("&")) {
                        loginPage = loginPage + "&" + queryString;
                    } else {
                        loginPage = loginPage + queryString;
                    }
                }
                response.sendRedirect(loginPage);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(ErrorMessages.RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED.getMessage());
                }
                throw new AuthenticationFailedException(
                        ErrorMessages.RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED.getCode(),
                        ErrorMessages.RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED.getMessage());
            }
        } catch (UnsupportedEncodingException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while encoding the additional query parameters", e);
            }
            throw new AuthenticationFailedException(ErrorMessages.BUILDING_AUTHORIZATION_CODE_REQUEST_FAILED.getCode(),
                    e.getMessage(), e);
        } catch (IOException e) {
            throw new AuthenticationFailedException(ErrorMessages.IO_ERROR.getCode(), e.getMessage(), e);
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException(ErrorMessages.BUILDING_AUTHORIZATION_CODE_REQUEST_FAILED.getCode(),
                    e.getMessage(), e);
        }
        return;
    }

    private String getStateParameter(AuthenticationContext context, Map<String, String> authenticatorProperties) {

        String state = context.getContextIdentifier() + "," + OIDCAuthenticatorConstants.LOGIN_TYPE;
        return getState(state, authenticatorProperties);
    }

    private String getOIDCAuthzEndpoint(Map<String, String> authenticatorProperties) {

        String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);
        if (StringUtils.isBlank(authorizationEP)) {
            authorizationEP = authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
        }
        return authorizationEP;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {

            OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            OAuthClientRequest accessTokenRequest = getAccessTokenRequest(context, authzResponse);

            // Create OAuth client that uses custom http client under the hood
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, accessTokenRequest);

            // TODO : return access token and id token to framework
            String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);

            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException(ErrorMessages.ACCESS_TOKEN_EMPTY_OR_NULL.getCode(),
                        ErrorMessages.ACCESS_TOKEN_EMPTY_OR_NULL.getMessage());
            }

            String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (StringUtils.isBlank(idToken) && requiredIDToken(authenticatorProperties)) {
                throw new AuthenticationFailedException(ErrorMessages.ID_TOKEN_MISSED_IN_OIDC_RESPONSE.getCode(),
                        String.format(ErrorMessages.ID_TOKEN_MISSED_IN_OIDC_RESPONSE.getMessage(),
                                getTokenEndpoint(authenticatorProperties),
                                authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID)));
            }

            OIDCStateInfo stateInfoOIDC = new OIDCStateInfo();
            stateInfoOIDC.setIdTokenHint(idToken);
            context.setStateInfo(stateInfoOIDC);

            context.setProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN, accessToken);

            processAuthenticatedUserScopes(context, oAuthResponse.getParam(OAuthConstants.OAuth20Params.SCOPE));

            AuthenticatedUser authenticatedUser;
            Map<ClaimMapping, String> claims = new HashMap<>();
            Map<String, Object> jsonObject = new HashMap<>();

            if (StringUtils.isNotBlank(idToken)) {
                jsonObject = getIdTokenClaims(context, idToken);
                if (jsonObject == null) {
                    String errorMessage = ErrorMessages.DECODED_JSON_OBJECT_IS_NULL.getMessage();
                    if (log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    throw new AuthenticationFailedException(ErrorMessages.DECODED_JSON_OBJECT_IS_NULL.getCode(),
                            errorMessage);
                }

                String idpName = context.getExternalIdP().getIdPName();
                String sidClaim = (String) jsonObject.get(OIDCAuthenticatorConstants.Claim.SID);
                if (StringUtils.isNotBlank(sidClaim) && StringUtils.isNotBlank(idpName)) {
                    // Add 'sid' claim into authentication context, to be stored in the UserSessionStore for
                    // single logout.
                    context.setProperty(FEDERATED_IDP_SESSION_ID + idpName, sidClaim);
                }

                if (log.isDebugEnabled() && IdentityUtil
                        .isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
                    log.debug("Retrieved the User Information:" + jsonObject);
                }

                String authenticatedUserId = getAuthenticatedUserId(context, oAuthResponse, jsonObject);
                String attributeSeparator = getMultiAttributeSeparator(context, authenticatedUserId);

                jsonObject.entrySet().stream()
                        .filter(entry -> !ArrayUtils.contains(NON_USER_ATTRIBUTES, entry.getKey()))
                        .forEach(entry -> buildClaimMappings(claims, entry, attributeSeparator));
                
                authenticatedUser = AuthenticatedUser
                        .createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
            } else {

                if (log.isDebugEnabled()) {
                    log.debug("The IdToken is null");
                }
                authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                        getAuthenticateUser(context, jsonObject, oAuthResponse));
            }

            claims.putAll(getSubjectAttributes(oAuthResponse, authenticatorProperties));
            authenticatedUser.setUserAttributes(claims);

            context.setSubject(authenticatedUser);

        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException(ErrorMessages.AUTHENTICATION_PROCESS_FAILED.getCode(),
                    ErrorMessages.AUTHENTICATION_PROCESS_FAILED.getMessage(), context.getSubject(), e);
        }
    }

    protected void processAuthenticatedUserScopes(AuthenticationContext context, String scopes) {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Scopes in token response: %s", scopes));
        }
    }

    @Override
    protected void initiateLogoutRequest(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) throws LogoutFailedException {

        if (isLogoutEnabled(context)) {
            String logoutUrl = getLogoutUrl(context.getAuthenticatorProperties());

            Map<String, String> paramMap = new HashMap<>();

            String idTokenHint = getIdTokenHint(context);
            if (StringUtils.isNotBlank(idTokenHint)) {
                paramMap.put(OIDCAuthenticatorConstants.ID_TOKEN_HINT, idTokenHint);
            }

            String callback = getCallbackUrl(context.getAuthenticatorProperties());
            paramMap.put(OIDCAuthenticatorConstants.POST_LOGOUT_REDIRECT_URI, callback);

            String sessionID = getStateParameter(context, context.getAuthenticatorProperties());
            paramMap.put(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE, sessionID);

            try {
                logoutUrl = FrameworkUtils.buildURLWithQueryParams(logoutUrl, paramMap);
                response.sendRedirect(logoutUrl);
            } catch (IOException e) {
                String idpName = context.getExternalIdP().getName();
                String tenantDomain = context.getTenantDomain();
                throw new LogoutFailedException("Error occurred while initiating the logout request to IdP: " + idpName
                        + " of tenantDomain: " + tenantDomain, e);
            }
        } else {
            super.initiateLogoutRequest(request, response, context);
        }
    }

    private boolean isLogoutEnabled(AuthenticationContext context) {

        String logoutUrl = getLogoutUrl(context.getAuthenticatorProperties());
        return StringUtils.isNotBlank(logoutUrl);
    }

    private String getIdTokenHint(AuthenticationContext context) {

        if (context.getStateInfo() instanceof OIDCStateInfo) {
            return ((OIDCStateInfo) context.getStateInfo()).getIdTokenHint();
        }
        return null;
    }

    private Map<String, Object> getIdTokenClaims(AuthenticationContext context, String idToken) {

        context.setProperty(OIDCAuthenticatorConstants.ID_TOKEN, idToken);
        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parseJSONObject(new String(decoded)).entrySet();
        } catch (ParseException e) {
            log.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }

    private String getMultiAttributeSeparator(AuthenticationContext context, String authenticatedUserId)
            throws AuthenticationFailedException {

        String attributeSeparator = null;
        try {

            String tenantDomain = context.getTenantDomain();

            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            int tenantId = OpenIDConnectAuthenticatorDataHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
            UserRealm userRealm = OpenIDConnectAuthenticatorDataHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId);

            if (userRealm != null) {
                UserStoreManager userStore = (UserStoreManager) userRealm.getUserStoreManager();
                attributeSeparator = userStore.getRealmConfiguration()
                        .getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
                if (log.isDebugEnabled()) {
                    log.debug("For the claim mapping: " + attributeSeparator
                            + " is used as the attributeSeparator in tenant: " + tenantDomain);
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException(ErrorMessages.RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED.getCode(),
                    ErrorMessages.RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED.getMessage(),
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId), e);
        }
        return attributeSeparator;
    }

    private String getAuthenticatedUserId(AuthenticationContext context, OAuthClientResponse oAuthResponse,
                                          Map<String, Object> idTokenClaims) throws AuthenticationFailedException {

        String authenticatedUserId;
        if (isUserIdFoundAmongClaims(context)) {
            authenticatedUserId = getSubjectFromUserIDClaimURI(context, idTokenClaims);
            if (StringUtils.isNotBlank(authenticatedUserId)) {
                if (log.isDebugEnabled()) {
                    log.debug("Authenticated user id: " + authenticatedUserId + " was found among id_token claims.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Subject claim could not be found amongst id_token claims. Defaulting to the 'sub' "
                            + "attribute in id_token as authenticated user id.");
                }
                // Default to userId sent as the 'sub' claim.
                authenticatedUserId = getAuthenticateUser(context, idTokenClaims, oAuthResponse);
            }
        } else {
            authenticatedUserId = getAuthenticateUser(context, idTokenClaims, oAuthResponse);
            if (log.isDebugEnabled()) {
                log.debug("Authenticated user id: " + authenticatedUserId + " retrieved from the 'sub' claim.");
            }
        }

        if (authenticatedUserId == null) {
            throw new AuthenticationFailedException(
                    ErrorMessages.USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.getCode(),
                    ErrorMessages.USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.getMessage());
        }
        return authenticatedUserId;
    }

    private boolean isUserIdFoundAmongClaims(AuthenticationContext context) {

        return Boolean.parseBoolean(context.getAuthenticatorProperties()
                .get(IdentityApplicationConstants.Authenticator.OIDC.IS_USER_ID_IN_CLAIMS));
    }

    protected void buildClaimMappings(Map<ClaimMapping, String> claims, Map.Entry<String, Object> entry,
                                      String separator) {

        StringBuilder claimValue = null;
        if (StringUtils.isBlank(separator)) {
            separator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
        }
        if (entry.getValue() instanceof JSONArray) {
            JSONArray jsonArray = (JSONArray) entry.getValue();
            if (jsonArray != null && !jsonArray.isEmpty()) {
                Iterator attributeIterator = jsonArray.iterator();
                while (attributeIterator.hasNext()) {
                    if (claimValue == null) {
                        claimValue = new StringBuilder(attributeIterator.next().toString());
                    } else {
                        claimValue.append(separator).append(attributeIterator.next().toString());
                    }
                }
            }
        } else {
            claimValue =
                    entry.getValue() != null ? new StringBuilder(entry.getValue().toString()) : new StringBuilder();
        }
        claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null, false),
                claimValue != null ? claimValue.toString() : StringUtils.EMPTY);
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
            log.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : " + claimValue);
        }

    }

    protected OAuthClientRequest getAccessTokenRequest(AuthenticationContext context, OAuthAuthzResponse
            authzResponse) throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
        String tokenEndPoint = getTokenEndpoint(authenticatorProperties);

        String callbackUrl = getCallbackUrlFromInitialRequestParamMap(context);
        if (StringUtils.isBlank(callbackUrl)) {
            callbackUrl = getCallbackUrl(authenticatorProperties);
        }

        boolean isHTTPBasicAuth = Boolean.parseBoolean(authenticatorProperties.get(OIDCAuthenticatorConstants
                .IS_BASIC_AUTH_ENABLED));

        OAuthClientRequest accessTokenRequest;
        try {
            if (isHTTPBasicAuth) {

                if (log.isDebugEnabled()) {
                    log.debug("Authenticating to token endpoint: " + tokenEndPoint + " with HTTP basic " +
                            "authentication scheme.");
                }

                accessTokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint).setGrantType(GrantType
                        .AUTHORIZATION_CODE).setRedirectURI(callbackUrl).setCode(authzResponse.getCode())
                        .buildBodyMessage();
                String base64EncodedCredential = new String(Base64.encodeBase64((clientId + ":" +
                        clientSecret).getBytes()));
                accessTokenRequest.addHeader(OAuth.HeaderType.AUTHORIZATION, "Basic " + base64EncodedCredential);
            } else {

                if (log.isDebugEnabled()) {
                    log.debug("Authenticating to token endpoint: " + tokenEndPoint + " including client credentials "
                            + "in request body.");
                }
                accessTokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint).setGrantType(GrantType
                        .AUTHORIZATION_CODE).setClientId(clientId).setClientSecret(clientSecret).setRedirectURI
                        (callbackUrl).setCode(authzResponse.getCode()).buildBodyMessage();
            }
            // set 'Origin' header to access token request.
            if (accessTokenRequest != null) {
                // fetch the 'Hostname' configured in carbon.xml
                String serverURL = ServiceURLBuilder.create().build().getAbsolutePublicURL();
                accessTokenRequest.addHeader(OIDCAuthenticatorConstants.HTTP_ORIGIN_HEADER, serverURL);
            }
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug(String.format(ErrorMessages.BUILDING_ACCESS_TOKEN_REQUEST_FAILED.getMessage(),
                        tokenEndPoint), e);
            }
            throw new AuthenticationFailedException(ErrorMessages.BUILDING_ACCESS_TOKEN_REQUEST_FAILED.getCode(), e);
        } catch (URLBuilderException e) {
            throw new RuntimeException("Error occurred while building URL in tenant qualified mode.", e);
        }

        return accessTokenRequest;
    }

    protected OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {

        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            if (log.isDebugEnabled()) {
                log.debug(ErrorMessages.REQUESTING_ACCESS_TOKEN_FAILED.getMessage(), e);
            }
            throw new AuthenticationFailedException(
                    ErrorMessages.REQUESTING_ACCESS_TOKEN_FAILED.getCode(), e.getMessage(), e);
        }
        return oAuthResponse;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Inside OpenIDConnectAuthenticator.getContextIdentifier()");
        }
        String state = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }

    private String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            String[] stateElements = state.split(",");
            if (stateElements.length > 1) {
                return stateElements[1];
            }
        }
        return null;
    }

    @Override
    public String getFriendlyName() {

        return OIDCAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return OIDCAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getClaimDialectURI() {

        return "http://wso2.org/oidc/claim";
    }

    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        Property clientId = new Property();
        clientId.setName(IdentityApplicationConstants.Authenticator.OIDC.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter OAuth2/OpenID Connect client identifier value");
        clientId.setType("string");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(IdentityApplicationConstants.Authenticator.OIDC.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setDescription("Enter OAuth2/OpenID Connect client secret value");
        clientSecret.setType("string");
        clientSecret.setDisplayOrder(2);
        clientSecret.setConfidential(true);
        configProperties.add(clientSecret);

        Property authzEpUrl = new Property();
        authzEpUrl.setName(IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_AUTHZ_URL);
        authzEpUrl.setDisplayName("Authorization Endpoint URL");
        authzEpUrl.setRequired(true);
        authzEpUrl.setDescription("Enter OAuth2/OpenID Connect authorization endpoint URL value");
        authzEpUrl.setType("string");
        authzEpUrl.setDisplayOrder(3);
        configProperties.add(authzEpUrl);

        Property tokenEpUrl = new Property();
        tokenEpUrl.setName(IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
        tokenEpUrl.setDisplayName("Token Endpoint URL");
        tokenEpUrl.setRequired(true);
        tokenEpUrl.setDescription("Enter OAuth2/OpenID Connect token endpoint URL value");
        tokenEpUrl.setType("string");
        tokenEpUrl.setDisplayOrder(4);
        configProperties.add(tokenEpUrl);

        Property callBackUrl = new Property();
        callBackUrl.setName(IdentityApplicationConstants.Authenticator.OIDC.CALLBACK_URL);
        callBackUrl.setDisplayName("Callback Url");
        callBackUrl.setRequired(false);
        callBackUrl.setDescription("Enter value corresponding to callback url");
        callBackUrl.setType("string");
        callBackUrl.setDisplayOrder(5);
        configProperties.add(callBackUrl);

        Property userInfoUrl = new Property();
        userInfoUrl.setName(IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL);
        userInfoUrl.setDisplayName("Userinfo Endpoint URL");
        userInfoUrl.setRequired(false);
        userInfoUrl.setDescription("Enter value corresponding to userinfo endpoint url");
        userInfoUrl.setType("string");
        userInfoUrl.setDisplayOrder(6);
        configProperties.add(userInfoUrl);

        Property userIdLocation = new Property();
        userIdLocation.setName(IdentityApplicationConstants.Authenticator.OIDC.IS_USER_ID_IN_CLAIMS);
        userIdLocation.setDisplayName("OpenID Connect User ID Location");
        userIdLocation.setRequired(false);
        userIdLocation.setDescription("Specifies the location to find the user identifier in the ID token assertion");
        userIdLocation.setType("boolean");
        userIdLocation.setDisplayOrder(7);
        configProperties.add(userIdLocation);

        Property additionalParams = new Property();
        additionalParams.setName("commonAuthQueryParams");
        additionalParams.setDisplayName("Additional Query Parameters");
        additionalParams.setRequired(false);
        additionalParams.setDescription("Additional query parameters. e.g: paramName1=value1");
        additionalParams.setType("string");
        additionalParams.setDisplayOrder(8);
        configProperties.add(additionalParams);

        Property enableBasicAuth = new Property();
        enableBasicAuth.setName(IdentityApplicationConstants.Authenticator.OIDC.IS_BASIC_AUTH_ENABLED);
        enableBasicAuth.setDisplayName("Enable HTTP basic auth for client authentication");
        enableBasicAuth.setRequired(false);
        enableBasicAuth.setDescription(
                "Specifies that HTTP basic authentication should be used for client authentication, else client credentials will be included in the request body");
        enableBasicAuth.setType("boolean");
        enableBasicAuth.setDisplayOrder(9);
        configProperties.add(enableBasicAuth);

        return configProperties;
    }

    /**
     * @subject
     */
    protected String getSubjectFromUserIDClaimURI(AuthenticationContext context) {

        String subject = null;
        try {
            subject = FrameworkUtils.getFederatedSubjectFromClaims(context, getClaimDialectURI());
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Couldn't find the subject claim from claim mappings ", e);
            }
        }
        return subject;
    }

    protected String getSubjectFromUserIDClaimURI(AuthenticationContext context, Map<String, Object> idTokenClaims)
            throws AuthenticationFailedException {

        boolean useLocalClaimDialect = context.getExternalIdP().useDefaultLocalIdpDialect();
        String userIdClaimUri = context.getExternalIdP().getUserIdClaimUri();
        String spTenantDomain = context.getTenantDomain();

        try {
            String userIdClaimUriInOIDCDialect = null;
            if (useLocalClaimDialect) {
                if (StringUtils.isNotBlank(userIdClaimUri)) {
                    // User ID is defined in local claim dialect at the IDP. Find the corresponding OIDC claim and retrieve
                    // from idTokenClaims.
                    userIdClaimUriInOIDCDialect = getUserIdClaimUriInOIDCDialect(userIdClaimUri, spTenantDomain);
                } else {
                    if (log.isDebugEnabled()) {
                        String idpName = context.getExternalIdP().getIdPName();
                        log.debug("User ID Claim URI is not configured for IDP: " + idpName + ". " +
                                "Cannot retrieve subject using user id claim URI.");
                    }
                }
            } else {
                ClaimMapping[] claimMappings = context.getExternalIdP().getClaimMappings();
                // Try to find the userIdClaimUri within the claimMappings.
                if (!ArrayUtils.isEmpty(claimMappings)) {
                    for (ClaimMapping claimMapping : claimMappings) {
                        if (log.isDebugEnabled()) {
                            log.debug("Evaluating " + claimMapping.getRemoteClaim().getClaimUri() + " against " +
                                    userIdClaimUri);
                        }
                        if (StringUtils.equals(claimMapping.getRemoteClaim().getClaimUri(), userIdClaimUri)) {
                            // Get the subject claim in OIDC dialect.
                            String userIdClaimUriInLocalDialect = claimMapping.getLocalClaim().getClaimUri();
                            userIdClaimUriInOIDCDialect =
                                    getUserIdClaimUriInOIDCDialect(userIdClaimUriInLocalDialect, spTenantDomain);
                            break;
                        }
                    }
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("using userIdClaimUriInOIDCDialect to get subject from idTokenClaims: " +
                        userIdClaimUriInOIDCDialect);
            }
            Object subject = idTokenClaims.get(userIdClaimUriInOIDCDialect);
            if (subject instanceof String) {
                return (String) subject;
            } else if (subject != null) {
                log.warn("Unable to map subject claim (non-String type): " + subject);
            }
        } catch (ClaimMetadataException ex) {
            throw new AuthenticationFailedException(
                    ErrorMessages.EXECUTING_CLAIM_TRANSFORMATION_FOR_IDP_FAILED.getCode(),
                    String.format(ErrorMessages.EXECUTING_CLAIM_TRANSFORMATION_FOR_IDP_FAILED.getMessage(),
                            context.getExternalIdP().getIdPName()), ex);
        }
        if (log.isDebugEnabled()) {
            log.debug("Couldn't find the subject claim among id_token claims for IDP: " + context.getExternalIdP()
                    .getIdPName());
        }
        return null;
    }

    private String getUserIdClaimUriInOIDCDialect(String userIdClaimInLocalDialect, String spTenantDomain)
            throws ClaimMetadataException {

        List<ExternalClaim> externalClaims = OpenIDConnectAuthenticatorDataHolder.getInstance()
                .getClaimMetadataManagementService().getExternalClaims(OIDC_DIALECT, spTenantDomain);
        String userIdClaimUri = null;
        ExternalClaim oidcUserIdClaim = null;

        for (ExternalClaim externalClaim : externalClaims) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Evaluating " + userIdClaimInLocalDialect + " against " + externalClaim.getMappedLocalClaim());
            }
            if (userIdClaimInLocalDialect.equals(externalClaim.getMappedLocalClaim())) {
                oidcUserIdClaim = externalClaim;
            }
        }

        if (oidcUserIdClaim != null) {
            userIdClaimUri = oidcUserIdClaim.getClaimURI();
        }

        return userIdClaimUri;
    }

    /**
     * Request user claims from user info endpoint.
     *
     * @param url         User info endpoint.
     * @param accessToken Access token.
     * @return Response string.
     * @throws IOException
     */
    protected String sendRequest(String url, String accessToken) throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("Claim URL: " + url);
        }

        if (url == null) {
            return StringUtils.EMPTY;
        }

        StringBuilder builder = new StringBuilder();
        BufferedReader reader = null;

        try {
            URL obj = new URL(url);
            HttpURLConnection urlConnection = (HttpURLConnection) obj.openConnection();
            urlConnection.setRequestMethod("GET");
            urlConnection.setRequestProperty("Authorization", "Bearer " + accessToken);
            reader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            String inputLine = reader.readLine();

            while (inputLine != null) {
                builder.append(inputLine).append("\n");
                inputLine = reader.readLine();
            }
        } finally {
            if (reader != null) {
                reader.close();
            }
        }

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
            log.debug("response: " + builder.toString());
        }
        return builder.toString();
    }

    private String interpretQueryString(AuthenticationContext context, String queryString,
                                        Map<String, String[]> parameters) {

        if (StringUtils.isBlank(queryString)) {
            return null;
        }
        if (queryString.contains(OIDCAuthenticatorConstants.AUTH_PARAM)) {
            queryString = getQueryStringWithAuthenticatorParam(context, queryString);
        }
        Matcher matcher = pattern.matcher(queryString);
        while (matcher.find()) {
            String name = matcher.group(1);
            String[] values = parameters.get(name);
            String value = "";
            if (values != null && values.length > 0) {
                value = values[0];
            }
            if (log.isDebugEnabled()) {
                log.debug("InterpretQueryString name: " + name + ", value: " + value);
            }
            queryString = queryString.replaceAll("\\$\\{" + name + "}", Matcher.quoteReplacement(value));
        }
        if (log.isDebugEnabled()) {
            log.debug("Output QueryString: " + queryString);
        }
        return queryString;
    }

    /**
     * Evaluate the query string for additional query params with actual key and value.
     *
     * @param paramMap addition query param and value
     * @return evaluated query string
     */
    private String getEvaluatedQueryString(Map<String, String> paramMap) throws UnsupportedEncodingException {

        StringBuilder queryString = new StringBuilder();
        if (paramMap.isEmpty()) {
            return queryString.toString();
        }
        for (Map.Entry param : paramMap.entrySet()) {
            queryString.append(param.getKey()).append("=")
                    .append(URLEncoder.encode(param.getValue().toString(), StandardCharsets.UTF_8.toString()))
                    .append("&");

        }
        return queryString.substring(0, queryString.length() - 1);
    }

    /**
     * To capture the additional authenticator params from the adaptive script and interpret the query string with
     * additional params.
     *
     * @param context     Authentication context
     * @param queryString the query string with additional param
     * @return interpreted query string
     */
    private String getQueryStringWithAuthenticatorParam(AuthenticationContext context, String queryString) {

        Matcher matcher = Pattern.compile(OIDCAuthenticatorConstants.DYNAMIC_AUTH_PARAMS_LOOKUP_REGEX)
                .matcher(queryString);
        String value = "";
        while (matcher.find()) {
            String paramName = matcher.group(1);
            if (StringUtils.isNotEmpty(getRuntimeParams(context).get(paramName))) {
                value = getRuntimeParams(context).get(paramName);
            }
            try {
                value = URLEncoder.encode(value, StandardCharsets.UTF_8.name());
                if (log.isDebugEnabled()) {
                    log.debug("InterpretQueryString with authenticator param: " + paramName + "," +
                            " value: " + value);
                }
            } catch (UnsupportedEncodingException e) {
                log.error("Error while encoding the authenticator param: " + paramName +
                        " with value: " + value, e);
            }
            queryString = queryString.replaceAll("\\$authparam\\{" + paramName + "}",
                    Matcher.quoteReplacement(value));
        }
        if (log.isDebugEnabled()) {
            log.debug("Output QueryString with Authenticator Params : " + queryString);
        }
        return queryString;
    }

    private String getCallbackUrlFromInitialRequestParamMap(AuthenticationContext context) {

        // 'oidc:param.map' is populated from the authorization request query string and being set in the
        // AuthenticationContext as a key value pair map. Therefore, it is always ensured that this map is available
        // and in of type Map<String, String>
        @SuppressWarnings({"unchecked"}) Map<String, String> paramValueMap = (Map<String, String>) context
                .getProperty(OIDCAuthenticatorConstants.OIDC_QUERY_PARAM_MAP_PROPERTY_KEY);

        if (MapUtils.isNotEmpty(paramValueMap) && paramValueMap.containsKey(OIDCAuthenticatorConstants.REDIRECT_URI)) {
            return paramValueMap.get(OIDCAuthenticatorConstants.REDIRECT_URI);
        }

        return null;
    }
}
