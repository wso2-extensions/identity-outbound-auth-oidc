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

import net.minidev.json.JSONArray;
import net.minidev.json.JSONValue;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.internal.OpenIDConnectAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.URLEncoder;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

public class OpenIDConnectAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -4154255583070524018L;

    private static Log log = LogFactory.getLog(OpenIDConnectAuthenticator.class);
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    private static final String DYNAMIC_PARAMETER_LOOKUP_REGEX = "\\$\\{(\\w+)\\}";
    private static Pattern pattern = Pattern.compile(DYNAMIC_PARAMETER_LOOKUP_REGEX);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isTraceEnabled()) {
            log.trace("Inside OpenIDConnectAuthenticator.canHandle()");
        }

        // Check commonauth got an OIDC response
        if (request.getParameter(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE) != null
                && request.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE) != null
                && OIDCAuthenticatorConstants.LOGIN_TYPE.equals(getLoginType(request))) {
            return true;
        } else if (request.getParameter(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE) != null &&
                request.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR) != null) {
            //if sends error like access_denied
            return true;
        }
        // TODO : What if IdP failed?

        return false;
    }

    /**
     * @return
     */
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        return null;
    }

    /**
     * @return
     */
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
    }

    /**
     * @return
     */
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        return null;
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
     * @param token OAuthClientResponse
     * @param authenticatorProperties Map<String, String> (Authenticator property, Property value)
     * @return User info endpoint.
     */
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL);
    }

    /**
     * Get subject attributes.
     * @param token OAuthClientResponse
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
                if(log.isDebugEnabled()) {
                    log.debug("Empty JSON response from user info endpoint. Unable to fetch user claims." +
                            " Proceeding without user claims");
                }
                return claims;
            }

            Map<String, Object> jsonObject = JSONUtils.parseJSON(json);

            for (Map.Entry<String, Object> data : jsonObject.entrySet()) {
                String key = data.getKey();
                Object value = data.getValue();

                if (value != null) {
                    claims.put(ClaimMapping.build(key, key, null, false), value.toString());
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
                String callbackurl = getOIDCCallbackUrl(authenticatorProperties);
                String state = getStateParameter(context, authenticatorProperties);

                OAuthClientRequest authzRequest;

                String queryString = getQueryString(authenticatorProperties);
                queryString = interpretQueryString(queryString, request.getParameterMap());
                Map<String, String> paramValueMap = new HashMap<>();

                if (StringUtils.isNotBlank(queryString)) {
                    String[] params = queryString.split("&");
                    for (String param : params) {
                        String[] intParam = param.split("=");
                        if (intParam != null && intParam.length >= 2) {
                            paramValueMap.put(intParam[0], intParam[1]);
                        }
                    }
                    context.setProperty("oidc:param.map", paramValueMap);
                }

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
                    log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                }
                throw new AuthenticationFailedException(
                        "Error while retrieving properties. Authenticator Properties cannot be null");
            }
        } catch (IOException e) {
            log.error("Exception while sending to the login page", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e) {
            log.error("Exception while building authorization code request", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return;
    }

    private String getStateParameter(AuthenticationContext context, Map<String, String> authenticatorProperties) {
        String state = context.getContextIdentifier() + "," + OIDCAuthenticatorConstants.LOGIN_TYPE;
        return getState(state, authenticatorProperties);
    }

    private String getOIDCCallbackUrl(Map<String, String> authenticatorProperties) {
        String callbackurl = getCallbackUrl(authenticatorProperties);
        if (StringUtils.isBlank(callbackurl)) {
            callbackurl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        }
        return callbackurl;
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

            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

            String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
            String tokenEndPoint = getOIDCTokenEndpoint(authenticatorProperties);
            String callbackUrl = getOIDCCallbackUrl(authenticatorProperties);

            @SuppressWarnings({"unchecked"})
            Map<String, String> paramValueMap = (Map<String, String>) context.getProperty("oidc:param.map");

            if (paramValueMap != null && paramValueMap.containsKey("redirect_uri")) {
                callbackUrl = paramValueMap.get("redirect_uri");
            }

            OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = authzResponse.getCode();

            OAuthClientRequest accessRequest = getAccessRequest(tokenEndPoint, clientId, code, clientSecret,
                    callbackUrl);

            // Create OAuth client that uses custom http client under the hood
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, accessRequest);

            // TODO : return access token and id token to framework
            String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);

            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException("Access token is empty or null");
            }

            String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
            if (StringUtils.isBlank(idToken) && requiredIDToken(authenticatorProperties)) {
                throw new AuthenticationFailedException(
                        "Id token is required and is missing in oidc response from " + "the federated IDP for "
                                + "clientId: " + clientId);
            }

            context.setProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN, accessToken);

            AuthenticatedUser authenticatedUser;
            Map<ClaimMapping, String> claims = new HashMap<>();
            Map<String, Object> jsonObject = new HashMap<>();

            if (StringUtils.isNotBlank(idToken)) {
                jsonObject = getIdTokenClaims(context, idToken);
                if (jsonObject == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Decoded json object is null");
                    }
                    throw new AuthenticationFailedException("Decoded json object is null");
                }

                if (log.isDebugEnabled() && IdentityUtil
                        .isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
                    log.debug("Retrieved the User Information:" + jsonObject);
                }

                String authenticatedUserId = getAuthenticatedUserId(context, oAuthResponse, jsonObject);
                String attributeSeparator = getMultiAttributeSeparator(context, authenticatedUserId);

                for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
                    buildClaimMappings(claims, entry, attributeSeparator);
                }
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
            throw new AuthenticationFailedException("Authentication process failed", context.getSubject(), e);
        }
    }

    private String getOIDCTokenEndpoint(Map<String, String> authenticatorProperties) {
        String tokenEndPoint = getTokenEndpoint(authenticatorProperties);

        if (StringUtils.isBlank(tokenEndPoint)) {
            tokenEndPoint = authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
        }
        return tokenEndPoint;
    }

    private Map<String, Object> getIdTokenClaims(AuthenticationContext context, String idToken) {
        context.setProperty(OIDCAuthenticatorConstants.ID_TOKEN, idToken);
        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());

        return JSONUtils.parseJSON(new String(decoded));
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
            throw new AuthenticationFailedException("Error while retrieving multi attribute separator",
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
                    "Cannot find the userId from the id_token sent by the federated IDP.");
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
        try {
            JSONArray jsonArray = (JSONArray)JSONValue.parseWithException(entry.getValue().toString());
            if (jsonArray != null && jsonArray.size() > 0) {
                Iterator attributeIterator = jsonArray.iterator();
                while (attributeIterator.hasNext()) {
                    if (claimValue == null) {
                        claimValue = new StringBuilder(attributeIterator.next().toString());
                    } else {
                        claimValue.append(separator).append(attributeIterator.next().toString());
                    }
                }

            }
        } catch (Exception e) {
            claimValue = new StringBuilder(entry.getValue().toString());
        }

        claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null, false), claimValue.toString());
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
            log.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : " + claimValue);
        }

    }

    private OAuthClientRequest getAccessRequest(String tokenEndPoint, String clientId, String code, String clientSecret,
            String callbackurl) throws AuthenticationFailedException {

        OAuthClientRequest accessRequest = null;
        try {
            accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(clientId)
                    .setClientSecret(clientSecret).setRedirectURI(callbackurl).setCode(code)
                    .buildBodyMessage();

        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Exception while building request for request access token", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return accessRequest;
    }

    protected OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {

        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            if (log.isDebugEnabled()) {
                log.debug("Exception while requesting access token", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
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
            return state.split(",")[1];
        } else {
            return null;
        }
    }

    @Override
    public String getFriendlyName() {
        return "openidconnect";
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
     * @subject
     */
    protected String getSubjectFromUserIDClaimURI(AuthenticationContext context) {
        String subject = null;
        try {
            subject = FrameworkUtils.getFederatedSubjectFromClaims(context, getClaimDialectURI());
        } catch (Exception e) {
            if(log.isDebugEnabled()) {
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
            if (useLocalClaimDialect) {
                // User ID is defined in local claim dialect at the IDP. Find the corresponding OIDC claim and retrieve
                // from idTokenClaims.
                String userIdClaimUriInOIDCDialect = getUserIdClaimUriInOIDCDialect(userIdClaimUri, spTenantDomain);
                return (String) idTokenClaims.get(userIdClaimUriInOIDCDialect);

            } else {
                ClaimMapping[] claimMappings = context.getExternalIdP().getClaimMappings();
                // Try to find the userIdClaimUri within the claimMappings.
                if (!ArrayUtils.isEmpty(claimMappings)) {
                    for (ClaimMapping claimMapping : claimMappings) {
                        if (StringUtils.equals(claimMapping.getRemoteClaim().getClaimUri(), userIdClaimUri)) {
                            // Get the subject claim in OIDC dialect.
                            String userIdClaimUriInLocalDialect = claimMapping.getLocalClaim().getClaimUri();
                            return (String) idTokenClaims
                                    .get(getUserIdClaimUriInOIDCDialect(userIdClaimUriInLocalDialect, spTenantDomain));
                        }
                    }
                }
            }
        } catch (ClaimMetadataException ex) {
            throw new AuthenticationFailedException(
                    "Error while executing claim transformation for IDP: " + context.getExternalIdP().getIdPName(), ex);
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
     * @param url User info endpoint.
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
    
    private String interpretQueryString (String queryString, Map<String,String[]> parameters) {

        Matcher matcher = pattern.matcher(queryString);
        while (matcher.find()) {
            String name = matcher.group(1);
            String[] values = parameters.get(name);
            String value = "";
            if (values != null && values.length > 0) {
                value = values[0];
            }
            try {
                value = URLEncoder.encode(value, StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException e) {
                log.error(e.toString(),e);
            }
            if (log.isDebugEnabled()) {
                log.debug ("interpretQueryString " + name + " <" + value + ">");
            }
            queryString = queryString.replaceAll("\\$\\{" + name + "}", Matcher.quoteReplacement(value));
        }
        if (log.isDebugEnabled()) {
            log.debug ("interpretQueryString <" + queryString + ">");
        }
        return queryString;
    }
    
}
