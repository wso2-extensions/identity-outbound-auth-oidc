/*
 * Copyright (c) 2013-2024, WSO2 LLC. (http://www.wso2.com).
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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.CollectionUtils;
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
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.FederatedToken;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.model.OIDCStateInfo;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCCommonUtil;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCTokenValidationUtil;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.util.IdPManagementConstants;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.ACCESS_TOKEN_PARAM;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.AUTHENTICATOR_OIDC;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.Claim.NONCE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.SHARE_FEDERATED_TOKEN_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.ID_TOKEN_PARAM;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.LogConstants.ActionIDs.INITIATE_OUTBOUND_AUTH_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.LogConstants.OUTBOUND_AUTH_OIDC_SERVICE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.MULTI_OPTION_URI;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OIDC_FEDERATION_NONCE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.QUERY_PARAM_KEY_VALUE_DELIMITER;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.REDIRECT_URL_SUFFIX;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.SCOPE_PARAM_SUFFIX;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.STATE_PARAM_SUFFIX;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.URI_QUERY_PARAM_DELIMITER;
import static org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCCommonUtil.isUserIdFoundAmongClaims;
import static org.wso2.carbon.identity.base.IdentityConstants.FEDERATED_IDP_SESSION_ID;

/**
 * This class holds the OIDC authenticator.
 */
public class OpenIDConnectAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -4154255583070524018L;

    private static final Log LOG = LogFactory.getLog(OpenIDConnectAuthenticator.class);
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    private static final String PKCE_CODE_CHALLENGE_METHOD = "S256";

    private static final String DYNAMIC_PARAMETER_LOOKUP_REGEX = "\\$\\{(\\w+)\\}";
    private static final String IS_API_BASED = "IS_API_BASED";
    private static final String REDIRECT_URL = "REDIRECT_URL";
    private static final String SPACE_REGEX = "\\s+";
    private static final String SPACE = " ";
    private static final String SEMI_COLON_DELIMITER = ";";
    private static final String COMMA_DELIMITER = ",";
    private static Pattern pattern = Pattern.compile(DYNAMIC_PARAMETER_LOOKUP_REGEX);
    private static final String[] NON_USER_ATTRIBUTES = new String[]{"at_hash", "iss", "iat", "exp", "aud", "azp"};
    private static final String AUTHENTICATOR_MESSAGE = "authenticatorMessage";

    private static final String IS_PKCE_ENABLED_NAME = "IsPKCEEnabled";
    private static final String IS_PKCE_ENABLED_DISPLAY_NAME = "Enable PKCE";
    private static final String IS_PKCE_ENABLED_DESCRIPTION = "Specifies that PKCE should be used for client authentication";
    private static final String TYPE_BOOLEAN = "boolean";

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
        /*
        During the logout flow, the string 'OIDC' is appended to the logout request. This is done to identify the
        logout request as an OIDC logout request. However, in scenarios where multiple IS instances are chained as
        federated idps, the logout request and the logout response needs to be distinctly identified and handled
        accordingly. To identify this some additional checks needs to be performed which is handled in the following
        method.
         */
        if (context.isLogoutRequest()) {
            return processLogout(request, response, context);
        }
        return super.process(request, response, context);
    }

    @Override
    protected void processLogoutResponse(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) {

        if (LOG.isDebugEnabled()) {
            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                LOG.debug("Handled logout response from service provider " + request.getParameter("sp") +
                        " in tenant domain " + IdentityTenantUtil.getTenantDomainFromContext());
            } else {
                LOG.debug("Handled logout response from service provider " + request.getParameter("sp") +
                        " in tenant domain " + request.getParameter("tenantDomain"));
            }
        }

    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (LOG.isTraceEnabled()) {
            LOG.trace("Inside OpenIDConnectAuthenticator.canHandle()");
        }

        boolean canHandle;
        if (isNativeSDKBasedFederationCall(request)) {
            canHandle = true;
        } else {
            canHandle = OIDCAuthenticatorConstants.LOGIN_TYPE.equals(getLoginType(request));
        }
        if (canHandle && LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    getComponentId(), FrameworkConstants.LogConstants.ActionIDs.HANDLE_AUTH_STEP);
            diagnosticLogBuilder.resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                    .resultMessage("Outbound OIDC authenticator handling the authentication.");
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;
        // TODO : What if IdP failed?
    }

    /**
     * There are several types of requests such as authorization request, token request as well as different stages
     * like logout, error etc.
     * This method identifies if the request is an initial request or not, so that will help to initialize the request.
     *
     * @param context AuthenticationContext.
     * @param request HttpServletRequest.
     * @return Whether this is an initial request or not.
     */
    protected boolean isInitialRequest(AuthenticationContext context, HttpServletRequest request) {

        return !context.isLogoutRequest() && !hasCodeParamInRequest(request) && !hasErrorParamInRequest(request) &&
                !isNativeSDKBasedFederationCall(request);
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
     * @deprecated use {@link #getCallbackUrl(Map, AuthenticationContext)}.
     */
    @Deprecated
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

    /**
     * Returns the callback URL of the IdP Hub.
     *
     * @param authenticatorProperties Authentication properties configured in OIDC federated authenticator
     *                                configuration.
     * @param context                 Authentication context.
     * @return If API based authn flow, returns the redirect URL from the authentication context. If not returns the
     * callback URL configured in OIDC federated authenticator configuration and if it is empty returns
     * /commonauth endpoint URL path as the default value.
     */
    protected String getCallbackUrl(Map<String, String> authenticatorProperties, AuthenticationContext context) {

        if (Boolean.parseBoolean((String) context.getProperty(IS_API_BASED))) {
            return resolveCallBackURLForAPIBasedAuthFlow(context);
        }
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

    /**
     * Resolve the callback URL from the context properties to use in the API based authentication flow.
     *
     * @param context Authentication context.
     * @return Callback URL to be used in API based authentication flow.
     */
    protected String resolveCallBackURLForAPIBasedAuthFlow(AuthenticationContext context) {

        return (String) context.getProperty(REDIRECT_URL);
    }

    protected String getLogoutUrl(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(OIDCAuthenticatorConstants.IdPConfParams.OIDC_LOGOUT_URL);
    }

    /**
     * Returns the token endpoint of OIDC federated authenticator.
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
     * Get scopes from query param string or return default `openid` if none defined.
     *
     * @param scope String
     * @param authenticatorProperties Map<String, String> (Authenticator property, Property value)
     * @return Scopes.
     */
    protected String getScope(String scope, Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(scope)) {
            scope = OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE;
        }
        return scope;
    }

    /**
     * Get scopes defined in Scopes field.
     *
     * @param authenticatorProperties Map<String, String> (Authenticator property, Property value)
     * @return Scopes.
     */
    protected String getScope(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(IdentityApplicationConstants.Authenticator.OIDC.SCOPES);
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

    /**
     * @deprecated use {@link #getCallbackUrl(Map, AuthenticationContext)} instead.
     */
    @Deprecated
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
            claims = OIDCCommonUtil.extractUserClaimsFromJsonPayload(json);
        } catch (IOException e) {
            LOG.error("Communication error occurred while accessing user info endpoint", e);
        }

        return claims;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
            if (LoggerUtils.isDiagnosticLogsEnabled() && context.getAuthenticatorProperties() != null) {
                diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        getComponentId(), INITIATE_OUTBOUND_AUTH_REQUEST);
                diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                        .inputParam("authenticator properties", context.getAuthenticatorProperties().keySet())
                        .inputParam(LogConstants.InputKeys.IDP, context.getExternalIdP().getIdPName())
                        .inputParams(getApplicationDetails(context));
            }

            String loginPage = prepareLoginPage(request, context);
            response.sendRedirect(loginPage);
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                String scopes = extractScopesFromURL(loginPage);
                if (StringUtils.isNotEmpty(scopes)) {
                    diagnosticLogBuilder.inputParam("scopes", scopes);
                }
                diagnosticLogBuilder.resultMessage("Redirecting to the federated IDP login page.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException(ErrorMessages.IO_ERROR.getCode(), e.getMessage(), e);
        }
    }

    /**
     * Prepare the login page needed for initiating authentication request.
     *
     * @param request Http Servlet Request.
     * @param context Authentication Context of the flow.
     * @return Login page needed for initiating authentication request.
     */
    protected String prepareLoginPage(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                        new DiagnosticLog.DiagnosticLogBuilder(
                        getComponentId(), INITIATE_OUTBOUND_AUTH_REQUEST);
                diagnosticLogBuilder.resultMessage("Initiate outbound OIDC authentication request.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                        .inputParam(LogConstants.InputKeys.IDP, context.getExternalIdP().getIdPName())
                        .inputParams(getApplicationDetails(context));
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
                String authorizationEP = getOIDCAuthzEndpoint(authenticatorProperties);
                String callbackurl = getCallbackUrl(authenticatorProperties, context);

                String state = getStateParameter(request, context, authenticatorProperties);
                context.setProperty(getName() + STATE_PARAM_SUFFIX, state);
                String nonce = UUID.randomUUID().toString();
                context.setProperty(getName() + OIDC_FEDERATION_NONCE, nonce);
                boolean isPKCEEnabled = Boolean.parseBoolean(
                        authenticatorProperties.get(OIDCAuthenticatorConstants.IS_PKCE_ENABLED));

                OAuthClientRequest authzRequest;

                String scopes = getScope(authenticatorProperties);

                /*
                  The scopes for the federated tokens are evaluated only if the authenticator
                  configuration ShareFederatedToken is enabled and the application has requested the federated token.
                 */
                if (Boolean.parseBoolean(authenticatorProperties.get(SHARE_FEDERATED_TOKEN_CONFIG)) &&
                        requestedToShareFederatedToken(context)) {
                    // Adding the scopes requested by the application side for token sharing.
                    scopes = addValidScopesForFederatedTokenSharing(context, authenticatorProperties, scopes);
                }

                String queryString = getQueryString(authenticatorProperties);
                if (StringUtils.isNotBlank(scopes)) {
                    queryString += "&scope=" + scopes;
                }
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
                context.setProperty(getName() + SCOPE_PARAM_SUFFIX, scope);

                if (StringUtils.isNotBlank(queryString) && queryString.toLowerCase().contains("scope=") && queryString
                        .toLowerCase().contains("redirect_uri=")) {
                    authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                            .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE).setState(state)
                            .setParameter(NONCE, nonce)
                            .buildQueryMessage();
                } else if (StringUtils.isNotBlank(queryString) && queryString.toLowerCase().contains("scope=")) {
                    authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                            .setRedirectURI(callbackurl)
                            .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE).setState(state)
                            .setParameter(NONCE, nonce)
                            .buildQueryMessage();
                } else if (StringUtils.isNotBlank(queryString) && queryString.toLowerCase().contains("redirect_uri=")) {
                    authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                            .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                            .setScope(OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE).setState(state)
                            .setParameter(NONCE, nonce).buildQueryMessage();

                } else {
                    authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                            .setRedirectURI(callbackurl)
                            .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE).setScope(scope)
                            .setState(state)
                            .setParameter(NONCE, nonce).buildQueryMessage();
                }

                String loginPage = authzRequest.getLocationUri();
                String domain = request.getParameter("domain");

                if (StringUtils.isNotBlank(domain)) {
                    loginPage = loginPage + "&fidp=" + domain;
                }

                // If PKCE is enabled, add code_challenge and code_challenge_method to the request.
                if (isPKCEEnabled) {
                    String codeVerifier = generateCodeVerifier();
                    context.setProperty(OIDCAuthenticatorConstants.PKCE_CODE_VERIFIER, codeVerifier);
                    String codeChallenge = generateCodeChallenge(codeVerifier);
                    loginPage += "&code_challenge=" + codeChallenge + "&code_challenge_method="
                            + PKCE_CODE_CHALLENGE_METHOD;
                }

                if (StringUtils.isNotBlank(queryString)) {
                    if (!queryString.startsWith("&")) {
                        loginPage = loginPage + "&" + queryString;
                    } else {
                        loginPage = loginPage + queryString;
                    }
                }
                context.setProperty(getName() + REDIRECT_URL_SUFFIX, loginPage);
                return loginPage;
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(ErrorMessages.RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED.getMessage());
                }
                setAuthenticatorMessageToContext(ErrorMessages.RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED, context);

                throw new AuthenticationFailedException(
                        ErrorMessages.RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED.getCode(),
                        ErrorMessages.RETRIEVING_AUTHENTICATOR_PROPERTIES_FAILED.getMessage());
            }
        } catch (UnsupportedEncodingException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error while encoding the additional query parameters", e);
            }
            setAuthenticatorMessageToContext(ErrorMessages.BUILDING_AUTHORIZATION_CODE_REQUEST_FAILED, context);

            throw new AuthenticationFailedException(ErrorMessages.BUILDING_AUTHORIZATION_CODE_REQUEST_FAILED.getCode(),
                    e.getMessage(), e);
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException(ErrorMessages.BUILDING_AUTHORIZATION_CODE_REQUEST_FAILED.getCode(),
                    e.getMessage(), e);
        }
    }

    /**
     * This method can be used to add the authentication error message content into the context.
     *
     * @param errorMessage  ErrorMessage object.
     * @param context       AuthenticationContext.
     */
    protected static void setAuthenticatorMessageToContext(ErrorMessages errorMessage,
                                                           AuthenticationContext context) {

        AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(FrameworkConstants.
                AuthenticatorMessageType.ERROR, errorMessage.
                getCode(), errorMessage.getMessage(), null);
        context.setProperty(AUTHENTICATOR_MESSAGE, authenticatorMessage);
    }

    /**
     * This method is used to append the application side requested scopes after validating.
     * The application can request the scopes for federated token sharing either via adaptive scripts
     * or via the authorize request query parameters. The adaptive script has the first priority
     * while the request query parameters will be evaluated later.
     * i.e. Adaptive Script example:
     * This will ignore any other definition (common, local) of the authenticatorParams.
     * var onLoginRequest = function(context) {
     * executeStep(1, {
     * authenticatorParams: {
     * federated: {
     * "Google Calender": {
     * federated_token_scope: "https://googleapis.calander.readonly https://google.calander.list"
     * }}}}, {});}
     * i.e Authorize request query param example:
     * /authorize?response_type=id_token&client_id={ClientId}&redirect_uri={https://app/callback}
     * &scope=email profile openid
     * &federated_token_scope=Google Calender;read write,Microsoft Authenticator;https://googleapis.calender
     *
     * @param context                 The authentication context.
     * @param authenticatorProperties The authenticator properties.
     * @param scopes                  The scopes defined in the authenticator properties.
     * @return The IDP defined scope and the validated scopes requested by the application.
     */
    private String addValidScopesForFederatedTokenSharing(AuthenticationContext context,
                                                          Map<String, String> authenticatorProperties, String scopes) {

        // Get the application requested scopes for the federated tokens.
        String requestedScopesForTokenSharing = getRequestedScopesForTokenSharing(context);

        // Validating the application requested scopes by the authenticator allowed scopes for federated token sharing.
        Set<String> validScopesForTokenSharing = validateScopeForTokenSharing(
                authenticatorProperties.get(OIDCAuthenticatorConstants.FEDERATED_TOKEN_ALLOWED_SCOPE),
                requestedScopesForTokenSharing);

        if (CollectionUtils.isEmpty(validScopesForTokenSharing)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No matching scopes found for federated token sharing.");
            }
            return scopes;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Valid scopes found for the IDP" + getFederatedAuthenticatorName(context) +
                    " in federated token sharing: " + validScopesForTokenSharing);
        }
        /*
        Remove the duplicate scopes among the validated scopes for federated token sharing and the existing scopes
        of the authenticators.
         */
        scopes = removeDuplicateScopes(scopes, validScopesForTokenSharing);
        if (LOG.isDebugEnabled()) {
            LOG.debug("The scopes for the IDP: " + getFederatedAuthenticatorName(context) + " : " + scopes +
                    " after considering federated token sharing.");
        }
        return scopes;
    }

    /**
     * This method is used to remove the duplicate scopes.
     *
     * @param scopes                     The scopes defined in the authenticator. i.e. "openid email profile"
     * @param validScopesForTokenSharing The validated scopes requested by the application and the allowed scopes
     *                                   for the token sharing.
     * @return The scopes after removing the duplicate scopes.
     */
    private String removeDuplicateScopes(String scopes, Set<String> validScopesForTokenSharing) {

        if (StringUtils.isBlank(scopes)) {
            scopes = StringUtils.join(validScopesForTokenSharing, SPACE);
        }

        Set<String> scopeSet = new HashSet<>(Arrays.asList(scopes.split(SPACE_REGEX)));
        scopeSet.addAll(validScopesForTokenSharing);

        scopes = StringUtils.join(scopeSet, SPACE);
        return scopes;
    }

    /**
     * This method returns the scopes requested by the application for the federated tokens.
     *
     * @param context The authentication context.
     * @return The scopes requested by the application for token sharing.
     */
    private String getRequestedScopesForTokenSharing(AuthenticationContext context) {

        // The first priority is given to the parameters passed from the adaptive script. Then the query parameters.
        String requestedScopesViaAdaptiveScript =
                getAdaptiveScriptValues(context, OIDCAuthenticatorConstants.FEDERATED_TOKEN_SCOPE);
        // Checks if there exists scopes requested via adaptive script.
        if (StringUtils.isNotBlank(requestedScopesViaAdaptiveScript)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Adaptive script parameter found for " + OIDCAuthenticatorConstants.FEDERATED_TOKEN_SCOPE
                        + " in federated token sharing, IDP: " + getFederatedAuthenticatorName(context));
            }
            return requestedScopesViaAdaptiveScript;
        } else {
            String requestedScopesViaQueryParams = getRequestedScopesViaQueryParams(context);
            if (LOG.isDebugEnabled() && StringUtils.isNotBlank(requestedScopesViaQueryParams)) {
                LOG.debug("No adaptive script parameter: " + OIDCAuthenticatorConstants.FEDERATED_TOKEN_SCOPE +
                        " found. Query parameter: " + OIDCAuthenticatorConstants.FEDERATED_TOKEN_SCOPE +
                        " value: " + requestedScopesViaQueryParams + " found for federated token sharing, IDP: "
                        + getFederatedAuthenticatorName(context));
            }
            return requestedScopesViaQueryParams;
        }
    }

    /**
     * This method returns the adaptive script federated authenticator param value for a given parameter name.
     *
     * @param context The authentication context with federated authenticator params.
     * @param param   The federated authenticator parameter name.
     * @return The adaptive script federated authenticator param value for the given parameter name.
     */
    private String getAdaptiveScriptValues(AuthenticationContext context, String param) {

        Map<String, String> runtimeParams = this.getRuntimeParams(context);
        if (runtimeParams != null) {
            return runtimeParams.get(param);
        }
        return StringUtils.EMPTY;
    }

    /**
     * The optional scope string cannot have scattered segments for the same authenticator.
     * Only the very first segment is considered.
     * i.e. A valid string:
     * Google Calender has read write scopes, Microsoft Authenticator has https://googleapis.calender scope
     * A valid string:
     * federated_token_scope=Google Calander;read write,Microsoft Authenticator;https://googleapis.calender
     * A valid string:
     * federated_token_scope=Google Calender;read https://googleapis.calender.read
     *
     * @param context The authentication context with authentication request having the query parameters.
     * @return  The scopes requested by the application via the query parameters for federated token sharing.
     */
    private String getRequestedScopesViaQueryParams(AuthenticationContext context) {

        String authenticatorName = getFederatedAuthenticatorName(context);
        if (StringUtils.isBlank(authenticatorName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No external IDP name found in the authentication context for federated token sharing. " +
                        "Cannot retrieve the query parameters.");
            }
            return null;
        }

        String scopeString = getQueryParameter(context, OIDCAuthenticatorConstants.FEDERATED_TOKEN_SCOPE);
        if (StringUtils.isBlank(scopeString)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No query parameter " + OIDCAuthenticatorConstants.FEDERATED_TOKEN_SCOPE +
                        " found in federated token sharing, IDP: " + authenticatorName);
            }
            return null;
        }
        /*
        The requested scopes for particular authenticator should come with the authenticator name separated
        by a semicolon.
        i.e. A valid string:
        When Google Calender has read write scopes and Microsoft Authenticator has https://googleapis.calender scope
        A valid requested scopes string:
        federated_token_scope=Google Calander;read write,Microsoft Authenticator;https://googleapis.calender
         */
        if (!scopeString.contains(SEMI_COLON_DELIMITER)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Query parameter name: " + OIDCAuthenticatorConstants.FEDERATED_TOKEN_SCOPE + " value: " +
                        scopeString + " is missing " + SEMI_COLON_DELIMITER +
                        " delimiter in federated token sharing, IDP: " + authenticatorName);
            }
            return null;
        }

        String[] scopeSegments = StringUtils.split(scopeString, COMMA_DELIMITER);
        StringBuilder filteredScopes = new StringBuilder();

        for (String scopesFollowedByAuthenticator : scopeSegments) {
            String[] scopes = StringUtils.split(scopesFollowedByAuthenticator, SEMI_COLON_DELIMITER);
            if (ArrayUtils.getLength(scopes) == 2 &&
                    StringUtils.equals(authenticatorName, StringUtils.trim(scopes[0]))) {
                filteredScopes.append(StringUtils.trim(scopes[1])).append(SPACE);
            }
        }

        String requestedScopes = filteredScopes.toString();
        if (LOG.isDebugEnabled() && StringUtils.isBlank(requestedScopes)) {
            LOG.debug("No valid values found for the IDP: " + authenticatorName + " in the query parameter " +
                    OIDCAuthenticatorConstants.FEDERATED_TOKEN_SCOPE + " for federated token sharing");
        }

        return requestedScopes;
    }

    /**
     * This method evaluates whether application has requested to share the token. The first priority is given to the
     * authenticator parameters set at the adaptive script. Then the query parameters.
     *
     * @param context The authentication context.
     * @return Whether the application has requested to share the token.
     */
    private boolean requestedToShareFederatedToken(AuthenticationContext context) {

        // The first priority is given to the parameters setup at the adaptive script. Then the query parameters.
        String shareFederatedToken =
                getAdaptiveScriptValues(context, OIDCAuthenticatorConstants.SHARE_FEDERATED_TOKEN_PARAM);

        if (LOG.isDebugEnabled() && StringUtils.isNotBlank(shareFederatedToken)) {
            LOG.debug("Adaptive script parameter " + OIDCAuthenticatorConstants.SHARE_FEDERATED_TOKEN_PARAM +
                    " found for federated token sharing, IDP: " + getFederatedAuthenticatorName(context));
        }

        if (StringUtils.isBlank(shareFederatedToken)) {
            // Checks if the token sharing is requested via authorize request query parameters.
            shareFederatedToken = getQueryParameter(context, OIDCAuthenticatorConstants.SHARE_FEDERATED_TOKEN_PARAM);
            if (LOG.isDebugEnabled()) {
                LOG.debug("No adaptive script parameter: " + OIDCAuthenticatorConstants.SHARE_FEDERATED_TOKEN_PARAM +
                        " found. Query parameter: " + OIDCAuthenticatorConstants.SHARE_FEDERATED_TOKEN_PARAM +
                        " value: " + shareFederatedToken + " found for federated token sharing, IDP: "
                        + getFederatedAuthenticatorName(context));
            }
        }
        return Boolean.parseBoolean(shareFederatedToken);
    }

    /**
     * This method is used to retrieve the query parameters from the authentication request.
     *
     * @param context        The authentication context with authentication request.
     * @param queryParamName The required query parameter name.
     * @return The query parameter value.
     */
    private String getQueryParameter(AuthenticationContext context, String queryParamName) {

        AuthenticationRequest authenticationRequest = context.getAuthenticationRequest();
        if (authenticationRequest == null || StringUtils.isBlank(queryParamName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Invalid authentication request or invalid query parameter name : " + queryParamName +
                        " for federated token sharing, IDP: " + getFederatedAuthenticatorName(context));
            }
            return null;
        }
        String[] queryParamValues = authenticationRequest.getRequestQueryParam(queryParamName);
        if (ArrayUtils.isNotEmpty(queryParamValues)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Query parameter found for, " + queryParamName + " in federated token sharing, IDP: " +
                        getFederatedAuthenticatorName(context));
            }
            return queryParamValues[0];
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("No value found for the query parameter : " + queryParamName +
                    " in federated token sharing, IDP: " + getFederatedAuthenticatorName(context));
        }
        return null;
    }

    private String getStateParameter(HttpServletRequest request, AuthenticationContext context,
                                     Map<String, String> authenticatorProperties) {

        String state;
        if (FrameworkUtils.isAPIBasedAuthenticationFlow(request)) {
            state = UUID.randomUUID() + "," + OIDCAuthenticatorConstants.LOGIN_TYPE;
        } else {
            state = context.getContextIdentifier() + "," + OIDCAuthenticatorConstants.LOGIN_TYPE;
        }

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

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    getComponentId(), PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Processing outbound OIDC authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParam(LogConstants.InputKeys.IDP, context.getExternalIdP().getIdPName())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        // oAuthResponse can be null in some authentication flows. i.e Google One Tap.
        OAuthClientResponse oAuthResponse = requestAccessToken(request, context);
        // TODO : return access token and id token to framework
        mapAccessToken(request, context, oAuthResponse);

        /*
        Federated tokens are added only if the authenticator configuration ShareFederatedToken is enabled and the
        application has requested the federated token.
         */
        if (context.getAuthenticatorProperties() != null && Boolean.parseBoolean(
                context.getAuthenticatorProperties().get(OIDCAuthenticatorConstants.SHARE_FEDERATED_TOKEN_CONFIG)) &&
                requestedToShareFederatedToken(context)) {
            // Adding the federated tokens to the context for token sharing.
            addFederatedTokensToContext(context, oAuthResponse);
        }


        String idToken = mapIdToken(context, request, oAuthResponse);

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        if (requiredIDToken(authenticatorProperties) && StringUtils.isBlank(idToken)) {
            setAuthenticatorMessageToContext(ErrorMessages.ID_TOKEN_MISSED_IN_OIDC_RESPONSE, context);

            throw new AuthenticationFailedException(ErrorMessages.ID_TOKEN_MISSED_IN_OIDC_RESPONSE.getCode(),
                    String.format(ErrorMessages.ID_TOKEN_MISSED_IN_OIDC_RESPONSE.getMessage(),
                            getTokenEndpoint(authenticatorProperties),
                            authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID)));
        }

        OIDCStateInfo stateInfoOIDC = new OIDCStateInfo();
        stateInfoOIDC.setIdTokenHint(idToken);
        context.setStateInfo(stateInfoOIDC);

        AuthenticatedUser authenticatedUser;
        Map<ClaimMapping, String> claimsMap = new HashMap<>();
        Map<String, Object> jwtAttributeMap = new HashMap<>();

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    getComponentId(), PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context))
                    .inputParam(LogConstants.InputKeys.IDP, context.getExternalIdP().getIdPName())
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
        }
        if (StringUtils.isNotBlank(idToken)) {
            jwtAttributeMap = getIdTokenClaims(context, idToken);
            if (jwtAttributeMap.isEmpty()) {
                String errorMessage = ErrorMessages.DECODED_JSON_OBJECT_IS_NULL.getMessage();
                if (LOG.isDebugEnabled()) {
                    LOG.debug(errorMessage);
                }
                setAuthenticatorMessageToContext(ErrorMessages.DECODED_JSON_OBJECT_IS_NULL, context);

                throw new AuthenticationFailedException(ErrorMessages.DECODED_JSON_OBJECT_IS_NULL.getCode(),
                        errorMessage);
            }
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                diagnosticLogBuilder.inputParam("id token claims", jwtAttributeMap.keySet());
            }
            String idpName = context.getExternalIdP().getIdPName();
            String sidClaim = (String) jwtAttributeMap.get(OIDCAuthenticatorConstants.Claim.SID);
            if (StringUtils.isNotBlank(sidClaim) && StringUtils.isNotBlank(idpName)) {
                if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.inputParam("federated idp name", idpName);
                }
                // Add 'sid' claim into authentication context, to be stored in the UserSessionStore for single logout.
                context.setProperty(FEDERATED_IDP_SESSION_ID + idpName, sidClaim);
            }

            if (LOG.isDebugEnabled() && IdentityUtil
                    .isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
                LOG.debug("Retrieved the User Information:" + jwtAttributeMap);
            }

            String nonceKey = getName() + OIDC_FEDERATION_NONCE;
            if (StringUtils.isNotBlank((String) context.getProperty(nonceKey))) {
                String nonce = (String) jwtAttributeMap.get(NONCE);
                if (nonce == null) {
                    LOG.debug("OIDC provider does not support nonce claim in id_token.");
                }
                if (nonce != null && !nonce.equals(context.getProperty(nonceKey))) {
                    setAuthenticatorMessageToContext(ErrorMessages.NONCE_MISMATCH, context);

                    throw new AuthenticationFailedException(ErrorMessages.NONCE_MISMATCH.getCode(),
                            ErrorMessages.NONCE_MISMATCH.getMessage());
                }
            }
            String authenticatedUserId = getAuthenticatedUserId(context, oAuthResponse, jwtAttributeMap);
            String attributeSeparator = getMultiAttributeSeparator(context, authenticatedUserId);

            jwtAttributeMap.entrySet().stream()
                    .filter(entry -> !ArrayUtils.contains(NON_USER_ATTRIBUTES, entry.getKey()))
                    .forEach(entry -> buildClaimMappings(claimsMap, entry, attributeSeparator));

            authenticatedUser = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("The IdToken is null");
            }
            authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                    getAuthenticateUser(context, jwtAttributeMap, oAuthResponse));
        }
        claimsMap.putAll(getSubjectAttributes(oAuthResponse, authenticatorProperties));
        authenticatedUser.setUserAttributes(claimsMap);
        context.setSubject(authenticatedUser);
        if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
            diagnosticLogBuilder.resultMessage("Outbound OIDC authentication response processed successfully.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            diagnosticLogBuilder.inputParam("user attributes (local claim : remote claim)",
                    getUserAttributeClaimMappingList(authenticatedUser));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
    }

    /**
     * Get the i18n key defined to represent the authenticator name.
     *
     * @return the 118n key.
     */
    @Override
    public String getI18nKey() {

        return AUTHENTICATOR_OIDC;
    }

    /**
     * Retrieves or maps the ID token according to the flow supported by the authenticator.
     * Overridden in Google Authenticator for Google one tap.
     *
     * @param context       AuthenticationContext.
     * @param request       HttpServletRequest.
     * @param oAuthResponse OAuthClientResponse.
     * @return The valid JWT token for the authentication request.
     * @throws AuthenticationFailedException when ID token is not valid. i.e Google Authenticator.
     */
    protected String mapIdToken(AuthenticationContext context, HttpServletRequest request,
                                OAuthClientResponse oAuthResponse) throws AuthenticationFailedException {

        return oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
    }

    /**
     * Retrieves or maps the access token according to the flow supported by the authenticator.
     * Overridden in Google Authenticator for Google one tap.
     *
     * @param request       HttpServletRequest.
     * @param context       AuthenticationContext.
     * @param oAuthResponse OAuthClientResponse.
     * @throws AuthenticationFailedException Throws error when access token is not found.
     */
    protected void mapAccessToken(HttpServletRequest request, AuthenticationContext context,
                                  OAuthClientResponse oAuthResponse) throws AuthenticationFailedException {

        String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);

        if (StringUtils.isBlank(accessToken)) {
            setAuthenticatorMessageToContext(ErrorMessages.ACCESS_TOKEN_EMPTY_OR_NULL, context);

            throw new AuthenticationFailedException(ErrorMessages.ACCESS_TOKEN_EMPTY_OR_NULL.getCode(),
                    ErrorMessages.ACCESS_TOKEN_EMPTY_OR_NULL.getMessage());
        }
        context.setProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN, accessToken);
    }

    /**
     * Add the federated tokens to the authentication context. This is used to share the tokens with the application.
     *
     * @param context       The authentication context for the request on which the federated tokens are kept.
     * @param oAuthResponse The OAuth client response.
     */
    private void addFederatedTokensToContext(AuthenticationContext context, OAuthClientResponse oAuthResponse) {

        // If there is an existing list of federated tokens obtained in a previous step, utilizing the same list.
        List<FederatedToken> federatedTokens;
        Object federatedTokensObj = context.getProperty(FrameworkConstants.FEDERATED_TOKENS);
        if (federatedTokensObj instanceof List) {
            federatedTokens = (List<FederatedToken>) federatedTokensObj;
        } else {
            federatedTokens = new ArrayList<>();
        }

        String identityProviderName = getFederatedAuthenticatorName(context);

        FederatedToken federatedToken = new FederatedToken(identityProviderName,
                oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN));
        federatedToken.setRefreshToken(oAuthResponse.getParam(OIDCAuthenticatorConstants.REFRESH_TOKEN));
        federatedToken.setTokenValidityPeriod(oAuthResponse.getParam(OIDCAuthenticatorConstants.EXPIRES_IN));
        federatedToken.setScope(oAuthResponse.getParam(OIDCAuthenticatorConstants.SCOPE));
        federatedTokens.add(federatedToken);

        context.setProperty(FrameworkConstants.FEDERATED_TOKENS, federatedTokens);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Federated tokens added to the authentication context, IDP: " + identityProviderName);
        }
    }

    /**
     * This returns the intersection of the allowed scopes defined at the IDP configuration and the requested scopes
     * from the application side for federated token sharing.
     *
     * @param allowedScope   The administrator defined scopes in the IDP configuration for federated token sharing.
     * @param requestedScope The application side requested scopes for federated token sharing.
     * @return The intersection of the allowed and the requested scopes for federated token sharing as a set of list.
     */
    private Set<String> validateScopeForTokenSharing(String allowedScope, String requestedScope) {

        if (StringUtils.isBlank(allowedScope)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No scopes are allowed for federated token sharing.");
            }
            return null;
        }
        if (StringUtils.isBlank(requestedScope)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No scopes are requested for federated token sharing.");
            }
            return null;
        }
        Set<String> allowedScopesSet = new HashSet<>(Arrays.asList(allowedScope.split(SPACE_REGEX)));
        Set<String> requestedScopesSet = new HashSet<>(Arrays.asList(requestedScope.split(SPACE_REGEX)));

        Set<String> subset = new HashSet<>(requestedScopesSet);
        subset.retainAll(allowedScopesSet);

        return subset;
    }

    /**
     * Generates OAuth client and returns the oAuthResponse according to the flow supported by the authenticator.
     * Overridden in Google Authenticator for Google one tap.
     *
     * @param request HttpServletRequest.
     * @param context AuthenticationContext.
     * @return OAuthClientResponse.
     * @throws AuthenticationFailedException throws error when OAuthAuthzResponse validation fails for either error
     *                                       response or the parameters.
     */
    protected OAuthClientResponse requestAccessToken(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        OAuthClientResponse oAuthResponse;
        if (isTrustedTokenIssuer(context) && isNativeSDKBasedFederationCall(request)) {
            String idToken = request.getParameter(ID_TOKEN_PARAM);
            String accessToken = request.getParameter(ACCESS_TOKEN_PARAM);
            try {
                validateJWTToken(context, idToken);
            } catch (ParseException | IdentityOAuth2ClientException | JOSEException e) {
                throw new AuthenticationFailedException(ErrorMessages.INVALID_JWT_TOKEN.getCode(),
                        ErrorMessages.INVALID_JWT_TOKEN.getMessage());
            } catch (IdentityOAuth2Exception e) {
                throw new AuthenticationFailedException(ErrorMessages.JWT_TOKEN_VALIDATION_FAILED.getCode(),
                        ErrorMessages.JWT_TOKEN_VALIDATION_FAILED.getMessage(), e);
            }
            NativeSDKBasedFederatedOAuthClientResponse nativeSDKBasedFederatedOAuthClientResponse
                    = new NativeSDKBasedFederatedOAuthClientResponse();
            nativeSDKBasedFederatedOAuthClientResponse.setAccessToken(accessToken);
            nativeSDKBasedFederatedOAuthClientResponse.setIdToken(idToken);

            return nativeSDKBasedFederatedOAuthClientResponse;
        }
        try {
            OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            OAuthClientRequest accessTokenRequest = getAccessTokenRequest(context, authzResponse);

            // Create OAuth client that uses custom http client under the hood.
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            oAuthResponse = getOauthResponse(oAuthClient, accessTokenRequest);
            if (oAuthResponse != null) {
                processAuthenticatedUserScopes(context, oAuthResponse.getParam(OAuthConstants.OAuth20Params.SCOPE));
            }
        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException(ErrorMessages.AUTHENTICATION_PROCESS_FAILED.getCode(),
                    ErrorMessages.AUTHENTICATION_PROCESS_FAILED.getMessage(), context.getSubject(), e);
        }
        return oAuthResponse;
    }

    private void validateJWTToken(AuthenticationContext context, String idToken) throws ParseException,
            AuthenticationFailedException, JOSEException, IdentityOAuth2Exception {

        SignedJWT signedJWT = SignedJWT.parse(idToken);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        OIDCTokenValidationUtil.validateIssuerClaim(claimsSet);
        String tenantDomain = context.getTenantDomain();
        String idpIdentifier = OIDCTokenValidationUtil.getIssuer(claimsSet);
        IdentityProvider identityProvider = getIdentityProvider(idpIdentifier, tenantDomain);

        OIDCTokenValidationUtil.validateSignature(signedJWT, identityProvider);
        OIDCTokenValidationUtil.validateAudience(claimsSet.getAudience(), identityProvider, tenantDomain);
    }

    /**
     * Get the identity provider from issuer and tenant domain.
     *
     * @param jwtIssuer   JWT issuer.
     * @param tenantDomain Tenant domain.
     * @return IdentityProvider.
     * @throws AuthenticationFailedException If there is an issue while getting the identity provider.
     */
    private IdentityProvider getIdentityProvider(String jwtIssuer, String tenantDomain)
            throws AuthenticationFailedException {

        IdentityProvider identityProvider;
        ErrorMessages errorMessages = ErrorMessages.NO_REGISTERED_IDP_FOR_ISSUER;
        try {
            identityProvider = IdentityProviderManager.getInstance().getIdPByMetadataProperty(
                    IdentityApplicationConstants.IDP_ISSUER_NAME, jwtIssuer, tenantDomain, false);

            if (identityProvider == null) {
                identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);
            }
            if (identityProvider != null && StringUtils.equalsIgnoreCase(identityProvider.getIdentityProviderName(),
                    OIDCAuthenticatorConstants.BackchannelLogout.DEFAULT_IDP_NAME)) {
                // Check whether this jwt was issued by the resident identity provider.
                identityProvider = getResidentIDPForIssuer(tenantDomain, jwtIssuer);

                if (identityProvider == null) {
                    throw new AuthenticationFailedException(errorMessages.getCode(), errorMessages.getMessage());
                }
            }
        } catch (IdentityProviderManagementException e) {
            throw new AuthenticationFailedException(errorMessages.getCode(), errorMessages.getMessage(), e);
        }
        return identityProvider;
    }

    /**
     * Get the resident identity provider from issuer and tenant domain.
     *
     * @param tenantDomain Tenant domain.
     * @param jwtIssuer   Issuer of the jwt.
     * @return IdentityProvider.
     * @throws AuthenticationFailedException If there is an issue while getting the resident identity provider.
     */
    private IdentityProvider getResidentIDPForIssuer(String tenantDomain, String jwtIssuer)
            throws AuthenticationFailedException {

        String issuer = StringUtils.EMPTY;
        IdentityProvider residentIdentityProvider;
        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = ErrorMessages.GETTING_RESIDENT_IDP_FAILED.getCode() + " - " +
                    String.format(ErrorMessages.GETTING_RESIDENT_IDP_FAILED.getMessage(), tenantDomain);
            throw new AuthenticationFailedException(errorMsg);
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

    protected void processAuthenticatedUserScopes(AuthenticationContext context, String scopes) {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Scopes in token response: %s", scopes));
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

            String callback = getCallbackUrl(context.getAuthenticatorProperties(), context);
            paramMap.put(OIDCAuthenticatorConstants.POST_LOGOUT_REDIRECT_URI, callback);

            String sessionID = getStateParameter(request, context, context.getAuthenticatorProperties());
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
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = OIDCCommonUtil.parseIDToken(idToken);
        } catch (ParseException e) {
            setAuthenticatorMessageToContext(ErrorMessages.JWT_TOKEN_PARSING_FAILED, context);

            LOG.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }

    private String getMultiAttributeSeparator(AuthenticationContext context, String authenticatedUserId)
            throws AuthenticationFailedException {

        try {
            return OIDCCommonUtil.getMultiAttributeSeparator(context.getTenantDomain());
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException(ErrorMessages.RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED.getCode(),
                    ErrorMessages.RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED.getMessage(),
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId), e);
        }
    }

    private String getAuthenticatedUserId(AuthenticationContext context, OAuthClientResponse oAuthResponse,
                                          Map<String, Object> idTokenClaims) throws AuthenticationFailedException {

        String authenticatedUserId;
        if (isUserIdFoundAmongClaims(context.getAuthenticatorProperties())) {
            authenticatedUserId = getSubjectFromUserIDClaimURI(context, idTokenClaims);
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
                authenticatedUserId = getAuthenticateUser(context, idTokenClaims, oAuthResponse);
            }
        } else {
            authenticatedUserId = getAuthenticateUser(context, idTokenClaims, oAuthResponse);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authenticated user id: " + authenticatedUserId + " retrieved from the 'sub' claim.");
            }
        }

        if (authenticatedUserId == null) {
            setAuthenticatorMessageToContext(ErrorMessages.USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP, context);
            throw new AuthenticationFailedException(
                    ErrorMessages.USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.getCode(),
                    ErrorMessages.USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.getMessage());
        }
        return authenticatedUserId;
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
        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
            LOG.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : " + claimValue);
        }

    }

    protected OAuthClientRequest getAccessTokenRequest(AuthenticationContext context, OAuthAuthzResponse
            authzResponse) throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
        String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
        boolean isPKCEEnabled = Boolean.parseBoolean(
                authenticatorProperties.get(OIDCAuthenticatorConstants.IS_PKCE_ENABLED));
        String codeVerifier = (String) context.getProperty(OIDCAuthenticatorConstants.PKCE_CODE_VERIFIER);

        String callbackUrl = getCallbackUrlFromInitialRequestParamMap(context);
        if (StringUtils.isBlank(callbackUrl)) {
            callbackUrl = getCallbackUrl(authenticatorProperties, context);
        }

        boolean isHTTPBasicAuth = Boolean.parseBoolean(authenticatorProperties.get(OIDCAuthenticatorConstants
                .IS_BASIC_AUTH_ENABLED));

        OAuthClientRequest accessTokenRequest;
        try {
            if (isHTTPBasicAuth) {

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authenticating to token endpoint: " + tokenEndPoint + " with HTTP basic " +
                            "authentication scheme.");
                }

                OAuthClientRequest.TokenRequestBuilder tokenRequestBuilder = OAuthClientRequest
                        .tokenLocation(tokenEndPoint)
                        .setGrantType(GrantType.AUTHORIZATION_CODE)
                        .setRedirectURI(callbackUrl)
                        .setCode(authzResponse.getCode());

                if (isPKCEEnabled) {
                    if (StringUtils.isEmpty(codeVerifier)) {
                        throw new AuthenticationFailedException("PKCE is enabled, but the code verifier is not found.");
                    }
                    tokenRequestBuilder.setParameter("code_verifier", codeVerifier);
                }

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
                        .setGrantType(GrantType.AUTHORIZATION_CODE)
                        .setClientId(clientId)
                        .setClientSecret(clientSecret)
                        .setRedirectURI(callbackUrl)
                        .setCode(authzResponse.getCode());
                if (isPKCEEnabled) {
                    if (StringUtils.isEmpty(codeVerifier)) {
                        throw new AuthenticationFailedException("PKCE is enabled, but the code verifier is not found.");
                    }
                    tokenRequestBuilder.setParameter("code_verifier", codeVerifier);
                }
                accessTokenRequest = tokenRequestBuilder.buildBodyMessage();
            }
            context.removeProperty(OIDCAuthenticatorConstants.PKCE_CODE_VERIFIER);
            // set 'Origin' header to access token request.
            if (accessTokenRequest != null) {
                // fetch the 'Hostname' configured in carbon.xml
                String serverURL = ServiceURLBuilder.create().build().getAbsolutePublicURL();
                accessTokenRequest.addHeader(OIDCAuthenticatorConstants.HTTP_ORIGIN_HEADER, serverURL);
            }
        } catch (OAuthSystemException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format(ErrorMessages.BUILDING_ACCESS_TOKEN_REQUEST_FAILED.getMessage(),
                        tokenEndPoint), e);
            }
            setAuthenticatorMessageToContext(ErrorMessages.BUILDING_ACCESS_TOKEN_REQUEST_FAILED, context);

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
            if (LOG.isDebugEnabled()) {
                LOG.debug(ErrorMessages.REQUESTING_ACCESS_TOKEN_FAILED.getMessage(), e);
            }
            throw new AuthenticationFailedException(
                    ErrorMessages.REQUESTING_ACCESS_TOKEN_FAILED.getCode(), e.getMessage(), e);
        }
        return oAuthResponse;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Inside OpenIDConnectAuthenticator.getContextIdentifier()");
        }

        if (FrameworkUtils.isAPIBasedAuthenticationFlow(request)) {
            return request.getParameter(OIDCAuthenticatorConstants.SESSION_DATA_KEY_PARAM);
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

        Property scopes = new Property();
        scopes.setName(IdentityApplicationConstants.Authenticator.OIDC.SCOPES);
        scopes.setDisplayName("Scopes");
        scopes.setRequired(false);
        scopes.setDescription("A list of scopes");
        scopes.setDefaultValue(OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE);
        scopes.setType("string");
        scopes.setDisplayOrder(8);
        configProperties.add(scopes);

        Property additionalParams = new Property();
        additionalParams.setName(IdentityApplicationConstants.Authenticator.OIDC.QUERY_PARAMS);
        additionalParams.setDisplayName("Additional Query Parameters");
        additionalParams.setRequired(false);
        additionalParams.setDescription("Additional query parameters. e.g: paramName1=value1");
        additionalParams.setType("string");
        additionalParams.setDisplayOrder(9);
        configProperties.add(additionalParams);

        Property enableBasicAuth = new Property();
        enableBasicAuth.setName(IdentityApplicationConstants.Authenticator.OIDC.IS_BASIC_AUTH_ENABLED);
        enableBasicAuth.setDisplayName("Enable HTTP basic auth for client authentication");
        enableBasicAuth.setRequired(false);
        enableBasicAuth.setDescription(
                "Specifies that HTTP basic authentication should be used for client authentication, " +
                        "else client credentials will be included in the request body");
        enableBasicAuth.setType("boolean");
        enableBasicAuth.setDisplayOrder(10);
        configProperties.add(enableBasicAuth);

        Property enablePKCE = new Property();
        enablePKCE.setName(IS_PKCE_ENABLED_NAME);
        enablePKCE.setDisplayName(IS_PKCE_ENABLED_DISPLAY_NAME);
        enablePKCE.setRequired(false);
        enablePKCE.setDescription(IS_PKCE_ENABLED_DESCRIPTION);
        enablePKCE.setType(TYPE_BOOLEAN);
        enablePKCE.setDisplayOrder(10);
        configProperties.add(enablePKCE);

        return configProperties;
    }

    /**
     * This method is responsible for validating whether the authenticator is supported for API Based Authentication.
     *
     * @return true if the authenticator is supported for API Based Authentication.
     */
    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    /**
     * This method is responsible for obtaining authenticator-specific data needed to
     * initialize the authentication process within the provided authentication context.
     *
     * @param context The authentication context containing information about the current authentication attempt.
     * @return An {@code Optional} containing an {@code AuthenticatorData} object representing the initiation data.
     *         If the initiation data is available, it is encapsulated within the {@code Optional}; otherwise,
     *         an empty {@code Optional} is returned.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setI18nKey(getI18nKey());
        String idpName = context.getExternalIdP().getIdPName();
        authenticatorData.setIdp(idpName);

        List<String> requiredParameterList = new ArrayList<>();
        if (isTrustedTokenIssuer(context)) {
            requiredParameterList.add(ACCESS_TOKEN_PARAM);
            requiredParameterList.add(ID_TOKEN_PARAM);
            authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT);
            authenticatorData.setAdditionalData(getAdditionalData(context, true));
        } else {
            requiredParameterList.add(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE);
            requiredParameterList.add(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE);
            authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.REDIRECTION_PROMPT);
            authenticatorData.setAdditionalData(getAdditionalData(context, false));
        }
        authenticatorData.setRequiredParams(requiredParameterList);
        if (context.getProperty(AUTHENTICATOR_MESSAGE) != null) {
            authenticatorData.setMessage((AuthenticatorMessage) context.getProperty(AUTHENTICATOR_MESSAGE));
        }

        return Optional.of(authenticatorData);
    }

    private static AdditionalData getAdditionalData(
            AuthenticationContext context, boolean isNativeSDKBasedFederationCall) {

        AdditionalData additionalData = new AdditionalData();
        String currentAuthenticator = StringUtils.isNotBlank(context.getCurrentAuthenticator()) ?
                context.getCurrentAuthenticator() : OIDCAuthenticatorConstants.AUTHENTICATOR_NAME;

        if (isNativeSDKBasedFederationCall) {
            Map<String, String> additionalAuthenticationParams = new HashMap<>();

            String nonce = (String) context.getProperty(currentAuthenticator + OIDC_FEDERATION_NONCE);
            if (StringUtils.isNotBlank(nonce)) {
                additionalAuthenticationParams.put(NONCE, nonce);
            }
            additionalAuthenticationParams.put(OIDCAuthenticatorConstants.CLIENT_ID_PARAM,
                    context.getAuthenticatorProperties().get(OIDCAuthenticatorConstants.CLIENT_ID));
            String scope = (String) context.getProperty(currentAuthenticator + SCOPE_PARAM_SUFFIX);
            additionalAuthenticationParams.put(OIDCAuthenticatorConstants.SCOPE, scope);
            additionalData.setAdditionalAuthenticationParams(additionalAuthenticationParams);
        } else {
            additionalData.setRedirectUrl((String) context.getProperty(currentAuthenticator + REDIRECT_URL_SUFFIX));
            Map<String, String> additionalAuthenticationParams = new HashMap<>();
            String state = (String) context.getProperty(currentAuthenticator + STATE_PARAM_SUFFIX);
            additionalAuthenticationParams.put(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE, state);
            additionalData.setAdditionalAuthenticationParams(additionalAuthenticationParams);
        }
        return additionalData;
    }

    /**
     * @subject
     */
    protected String getSubjectFromUserIDClaimURI(AuthenticationContext context) {

        String subject = null;
        try {
            subject = FrameworkUtils.getFederatedSubjectFromClaims(context, getClaimDialectURI());
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Couldn't find the subject claim from claim mappings ", e);
            }
        }
        return subject;
    }

    protected String getSubjectFromUserIDClaimURI(AuthenticationContext context, Map<String, Object> idTokenClaims)
            throws AuthenticationFailedException {

        String spTenantDomain = context.getTenantDomain();

        try {
            return OIDCCommonUtil.getSubjectFromUserIDClaimURI(context.getExternalIdP(), idTokenClaims,
                                                               spTenantDomain);
        } catch (ClaimMetadataException ex) {
            setAuthenticatorMessageToContext(ErrorMessages.EXECUTING_CLAIM_TRANSFORMATION_FOR_IDP_FAILED, context);

            throw new AuthenticationFailedException(
                    ErrorMessages.EXECUTING_CLAIM_TRANSFORMATION_FOR_IDP_FAILED.getCode(),
                    String.format(ErrorMessages.EXECUTING_CLAIM_TRANSFORMATION_FOR_IDP_FAILED.getMessage(),
                            context.getExternalIdP().getIdPName()), ex);
        }
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

        if (LOG.isDebugEnabled()) {
            LOG.debug("Claim URL: " + url);
        }

        String response = OIDCCommonUtil.triggerRequest(url, accessToken);

        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
            LOG.debug("response: " + response);
        }
        return response;
    }

    /**
     * Return the component ID of the Authenticator. This will be used for logging purposes.
     * @return Component ID String.
     */
    protected String getComponentId() {

        return OUTBOUND_AUTH_OIDC_SERVICE;
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
            String value = getParameterFromParamMap(parameters, name);
            if (StringUtils.isBlank(value)) {
                String multiOptionURI = getParameterFromParamMap(parameters, MULTI_OPTION_URI);
                value = getParameterFromURIString(multiOptionURI, name);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("InterpretQueryString name: " + name + ", value: " + value);
            }
            queryString = queryString.replaceAll("\\$\\{" + name + "}", Matcher.quoteReplacement(value));
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Output QueryString: " + queryString);
        }
        return queryString;
    }

    /**
     * Gets the value of the parameter corresponding to the given parameter
     * name from the request's parameter map.
     *
     * @param parameters    The parameter map of the request.
     * @param parameterName The name of the parameter to be retrieved.
     * @return The value of the parameter if it is present in the parameter map.
     * If it is not present, an empty String is returned instead.
     */
    private String getParameterFromParamMap(Map<String, String[]> parameters, String parameterName) {

        String[] parameterValueMap = parameters.get(parameterName);
        if (parameterValueMap != null && parameterValueMap.length > 0) {
            return parameterValueMap[0];
        }
        return StringUtils.EMPTY;
    }

    /**
     * Parses the given URI String to get the parameter value corresponding to the
     * given parameter name.
     *
     * @param uriString     The URI String to be parsed.
     * @param parameterName The name of the parameter to be retrieved.
     * @return The value of the parameter if it is present in the URI String.
     * If it is not present, an empty String is returned instead.
     */
    private String getParameterFromURIString(String uriString, String parameterName) {

        if (StringUtils.isNotBlank(uriString)) {
            String[] queryParams = uriString.split(URI_QUERY_PARAM_DELIMITER, -1);
            for (String queryParam: queryParams) {
                String[] queryParamComponents = queryParam.split(QUERY_PARAM_KEY_VALUE_DELIMITER);
                if (queryParamComponents.length == 2 && queryParamComponents[0].equalsIgnoreCase(parameterName)) {
                    return URLDecoder.decode(queryParamComponents[1], StandardCharsets.UTF_8);
                }
            }
        }
        return StringUtils.EMPTY;
    }


    /**
     * Evaluate the query string for additional query params with actual key and value.
     *
     * @param paramMap addition query param and value.
     * @return evaluated query string.
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
     * @param context     Authentication context.
     * @param queryString the query string with additional param.
     * @return interpreted query string.
     */
    private String getQueryStringWithAuthenticatorParam(AuthenticationContext context, String queryString) {

        Matcher matcher = Pattern.compile(OIDCAuthenticatorConstants.DYNAMIC_AUTH_PARAMS_LOOKUP_REGEX)
                .matcher(queryString);
        while (matcher.find()) {
            String value = "";
            String paramName = matcher.group(1);
            if (StringUtils.isNotEmpty(getRuntimeParams(context).get(paramName))) {
                value = getRuntimeParams(context).get(paramName);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("InterpretQueryString with authenticator param: " + paramName + "," +
                        " value: " + value);
            }
            queryString = queryString.replaceAll("\\$authparam\\{" + paramName + "}",
                    Matcher.quoteReplacement(value));
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Output QueryString with Authenticator Params : " + queryString);
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

    private AuthenticatorFlowStatus processLogout(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context) throws LogoutFailedException {
        try {
            // check if a logout response
            if (canHandle(request)
                    && StringUtils.isEmpty(request.getParameter(FrameworkConstants.RequestParams.TYPE))
                    && context.getExternalIdP() != null
                    && context.getExternalIdP().getIdentityProvider() != null) {
                processLogoutResponse(request, response, context);
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
            context.setCurrentAuthenticator(getName());
            initiateLogoutRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        } catch (UnsupportedOperationException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Logout is disabled during social logout or logout url not defined in " +
                        "idp configuration. Skipping logout and ignoring UnsupportedOperationException.", e);
            }
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
    }

    /**
     * Get application details from the authentication context.
     * @param context Authentication context.
     * @return Map of application details.
     */
    protected Map<String, String> getApplicationDetails(AuthenticationContext context) {

        Map<String, String> applicationDetailsMap = new HashMap<>();
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME,
                        applicationName));
        return applicationDetailsMap;
    }

    /**
     * Extract query param scopes from a given url.
     *
     * @param url Given url.
     * @return Extracted scopes as a String.
     */
    protected String extractScopesFromURL(String url) throws UnsupportedEncodingException {

        if (StringUtils.isNotBlank(url)) {
            String[] splitUrl = url.split(OIDCAuthenticatorConstants.QUESTION_SIGN, 2);
            if (splitUrl.length == 2) {
                String[] params = splitUrl[1].split(OIDCAuthenticatorConstants.AMPERSAND_SIGN);
                for (String param : params) {
                    String[] keyValue = param.split(OIDCAuthenticatorConstants.EQUAL_SIGN, 2);
                    if (keyValue.length == 2 && OAuthConstants.OAuth20Params.SCOPE.equals(keyValue[0])) {
                        return URLDecoder.decode(keyValue[1], FrameworkUtils.UTF_8);
                    }
                }
            }
        }
        return StringUtils.EMPTY;
    }

    private static List<String> getUserAttributeClaimMappingList(AuthenticatedUser authenticatedUser) {

        return authenticatedUser.getUserAttributes().keySet().stream()
                .map(claimMapping -> {
                    String localClaim = claimMapping.getLocalClaim().getClaimUri();
                    String remoteClaim = claimMapping.getRemoteClaim().getClaimUri();
                    return localClaim + " : " + remoteClaim;
                })
                .collect(Collectors.toList());
    }


    private boolean isTrustedTokenIssuer(AuthenticationContext context) {

        ExternalIdPConfig externalIdPConfig = context.getExternalIdP();
        if (externalIdPConfig == null) {
            return false;
        }

        IdentityProvider externalIdentityProvider = externalIdPConfig.getIdentityProvider();
        if (externalIdentityProvider == null) {
            return false;
        }

        IdentityProviderProperty[] identityProviderProperties = externalIdentityProvider.getIdpProperties();
        for (IdentityProviderProperty identityProviderProperty: identityProviderProperties) {
            if (IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER.equals(identityProviderProperty.getName())) {
                return Boolean.parseBoolean(identityProviderProperty.getValue());
            }
        }

        return false;
    }

    private boolean isNativeSDKBasedFederationCall(HttpServletRequest request) {

        return request.getParameter(ACCESS_TOKEN_PARAM) != null && request.getParameter(ID_TOKEN_PARAM) != null;
    }

    /**
     * This method returns the current federated authenticator name. If there is no external IdP, then the current
     * authenticator name is returned.
     *
     * @param context Authentication context.
     * @return Federated authenticator name.
     */
    private String getFederatedAuthenticatorName(AuthenticationContext context) {

        if (context == null || context.getExternalIdP() == null || context.getExternalIdP().getIdPName() == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cannot resolve the authenticator name from the authentication context.");
            }
            return StringUtils.EMPTY;
        }
        return context.getExternalIdP().getIdPName();
    }

    /**
     * Generate code verifier for PKCE
     *
     * @return code verifier
     */
    private String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    /**
     * Generate code challenge for PKCE
     *
     * @param codeVerifier code verifier
     * @return code challenge
     * @throws AuthenticationFailedException
     */
    private String generateCodeChallenge(String codeVerifier) throws AuthenticationFailedException {
        try {
            byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bytes, 0, bytes.length);
            byte[] digest = messageDigest.digest();
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new AuthenticationFailedException("Error while generating code challenge", e);
        }
    }
}
