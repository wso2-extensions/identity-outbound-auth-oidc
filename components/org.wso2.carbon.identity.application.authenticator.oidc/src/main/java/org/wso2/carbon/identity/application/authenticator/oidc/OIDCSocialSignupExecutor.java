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

import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import net.minidev.json.JSONArray;
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
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.internal.OpenIDConnectAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.user.registration.engine.exception.RegistrationEngineException;
import org.wso2.carbon.identity.user.registration.engine.exception.RegistrationEngineServerException;
import org.wso2.carbon.identity.user.registration.engine.graph.Executor;
import org.wso2.carbon.identity.user.registration.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.user.registration.engine.model.RegistrationContext;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import static org.apache.oltu.oauth2.common.message.types.GrantType.AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.Claim.NONCE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.IS_BASIC_AUTH_ENABLED;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE;
import static org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCExecutorUtil.handleRegistrationServerException;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.OAuth2.SCOPES;
import static org.wso2.carbon.identity.user.registration.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.user.registration.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;
import static org.wso2.carbon.identity.user.registration.engine.Constants.REDIRECT_URL;
import static org.wso2.carbon.identity.user.registration.engine.Constants.USERNAME_CLAIM_URI;

/**
 * OIDC Social Signup Executor.
 */
public class OIDCSocialSignupExecutor implements Executor {

    private static final Log LOG = LogFactory.getLog(OIDCSocialSignupExecutor.class);
    private static final String OIDC_SIGNUP_EXECUTOR = "OIDCSignupExecutor";
    private static final String REGISTRATION_PORTAL_PATH = "/authenticationendpoint/register.do";
    private static final String[] NON_USER_ATTRIBUTES = new String[] {"at_hash", "iss", "iat", "exp", "aud", "azp",
            "nonce"};
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    @Override
    public String getName() {

        return OIDC_SIGNUP_EXECUTOR;
    }

    @Override
    public ExecutorResponse execute(RegistrationContext context) throws RegistrationEngineException {

        if (isInitialRequest(context)) {
            return initiateSocialSignup(context);
        }
        return processResponse(context);
    }

    @Override
    public List<String> getInitiationData() {

        return Collections.emptyList();
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

    private boolean isInitialRequest(RegistrationContext context) {

        Map<String, String> userInputs = context.getUserInputData();
        return userInputs == null || userInputs.isEmpty() || userInputs.get(OAUTH2_GRANT_TYPE_CODE) == null ||
                userInputs.get(OAUTH2_PARAM_STATE) == null;
    }

    private ExecutorResponse processResponse(RegistrationContext context) throws RegistrationEngineException {

        Map<String, String> userInputs = context.getUserInputData();

        if (!StringUtils.equals(userInputs.get(OAUTH2_PARAM_STATE),
                                context.getProperty(OAUTH2_PARAM_STATE).toString())) {
            throw handleRegistrationServerException("State parameter mismatch.", null);
        }

        ExecutorResponse response = new ExecutorResponse(STATUS_COMPLETE);
        response.setUpdatedUserClaims(resolveUserAttributes(context, userInputs.get(OAUTH2_GRANT_TYPE_CODE)));
        return response;
    }

    private ExecutorResponse initiateSocialSignup(RegistrationContext context) throws RegistrationEngineException {

        ExecutorResponse executorResponse = new ExecutorResponse();
        executorResponse.setResult(STATUS_EXTERNAL_REDIRECTION);
        List<String> requiredData = new ArrayList<>();
        requiredData.add(OAUTH2_GRANT_TYPE_CODE);
        requiredData.add(OAUTH2_PARAM_STATE);
        String state = UUID.randomUUID() + "," + OIDCAuthenticatorConstants.LOGIN_TYPE;
        executorResponse.setRequiredData(requiredData);
        executorResponse.setAdditionalInfo(getAdditionalData(context.getAuthenticatorProperties(), state));

        Map<String, Object> contextProperties = new HashMap<>();
        contextProperties.put(OAUTH2_PARAM_STATE, state);
        executorResponse.setContextProperty(contextProperties);
        return executorResponse;
    }

    private Map<String, String> getAdditionalData(Map<String, String> authenticatorProperties, String state)
            throws RegistrationEngineException {

        Map<String, String> additionalData = new HashMap<>();
        additionalData.put(REDIRECT_URL, getRedirectUrl(authenticatorProperties, state));
        additionalData.put(OAUTH2_PARAM_STATE, state);
        return additionalData;
    }

    private String getRedirectUrl(Map<String, String> authenticatorProperties, String state)
            throws RegistrationEngineException {

        OAuthClientRequest authzRequest;
        String scopes = getScope(authenticatorProperties);
        String clientId = authenticatorProperties.get(CLIENT_ID);
        String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);
        String nonce = UUID.randomUUID().toString();
        String callbackUrl = getCallbackUrl();

        try {
            authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId)
                    .setRedirectURI(callbackUrl)
                    .setResponseType(OAUTH2_GRANT_TYPE_CODE)
                    .setScope(scopes)
                    .setState(state)
                    .setParameter(NONCE, nonce).buildQueryMessage();
            return authzRequest.getLocationUri();
        } catch (OAuthSystemException exception) {
            throw handleRegistrationServerException("Error while building the authorization request.", exception);
        }
    }

    private String getCallbackUrl() throws RegistrationEngineException {

        try {
            return ServiceURLBuilder.create().addPath(REGISTRATION_PORTAL_PATH).build().getAbsolutePublicURL();
        } catch (URLBuilderException exception) {
            throw handleRegistrationServerException("Error while resolving the callback URL.", exception);
        }
    }

    protected OAuthClientResponse requestAccessToken(RegistrationContext context, String code)
            throws RegistrationEngineException {

        OAuthClientRequest accessTokenRequest = getAccessTokenRequest(context.getAuthenticatorProperties(), code);

        // Create OAuth client that uses custom http client under the hood.
        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        return getOauthResponse(oAuthClient, accessTokenRequest);
    }

    protected OAuthClientRequest getAccessTokenRequest(Map<String, String> authenticatorProperties, String code)
            throws RegistrationEngineException {

        String clientId = authenticatorProperties.get(CLIENT_ID);
        String clientSecret = authenticatorProperties.get(CLIENT_SECRET);
        String tokenEndPoint = getTokenEndpoint(authenticatorProperties);

        String callbackUrl = getCallbackUrl();
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
            throw handleRegistrationServerException("Error while building the access token request.", exception);
        }
        return accessTokenRequest;
    }

    protected String resolveAccessToken(OAuthClientResponse oAuthResponse) throws RegistrationEngineException {

        String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);

        if (StringUtils.isBlank(accessToken)) {
            throw handleRegistrationServerException("Access token is empty or null.", null);
        }
        return accessToken;
    }

    private String resolveIDToken(OAuthClientResponse oAuthResponse) throws RegistrationEngineException {

        String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);

        if (StringUtils.isBlank(idToken)) {
            throw handleRegistrationServerException("ID token is empty or null.", null);
        }
        return idToken;
    }

    private Map<String, Object> resolveUserAttributes(RegistrationContext context, String code)
            throws RegistrationEngineException {

        OAuthClientResponse oAuthResponse = requestAccessToken(context, code);
        String accessToken = resolveAccessToken(oAuthResponse);
        String idToken = resolveIDToken(oAuthResponse);
        Map<String, String> remoteClaimsMap = new HashMap<>();
        Map<String, Object> jwtAttributeMap = new HashMap<>();
        jwtAttributeMap.putAll(getIdTokenClaims(idToken));
        jwtAttributeMap.putAll(getClaimsViaUserInfo(accessToken, context.getAuthenticatorProperties()));

        String attributeSeparator = getMultiAttributeSeparator(context.getTenantDomain());

        jwtAttributeMap.entrySet().stream()
                .filter(entry -> !ArrayUtils.contains(NON_USER_ATTRIBUTES, entry.getKey()))
                .forEach(entry -> buildClaimMappings(remoteClaimsMap, entry, attributeSeparator));

        return resolveLocalClaims(context, remoteClaimsMap, jwtAttributeMap);
    }

    private Map<String, Object> resolveLocalClaims(RegistrationContext context, Map<String, String> remoteClaimsMap,
                                                   Map<String, Object> jwtAttributeMap)
            throws RegistrationEngineException {

        Map<String, Object> localClaimsMap = new HashMap<>();
        try {
            Map<String, String> localToIdPClaimMap =
                    ClaimMetadataHandler.getInstance().getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT,
                                                                                              remoteClaimsMap.keySet(),
                                                                                              context.getTenantDomain(),
                                                                                              true);
            remoteClaimsMap.forEach((remoteKey, remoteValue) ->
                                            localToIdPClaimMap.entrySet().stream()
                                                    .filter(entry -> entry.getValue().equals(remoteKey))
                                                    .map(Map.Entry::getKey)
                                                    .findFirst()
                                                    .ifPresent(localKey -> localClaimsMap.put(localKey, remoteValue))
            );
            localClaimsMap.putIfAbsent(USERNAME_CLAIM_URI, getAuthenticatedUserId(context, jwtAttributeMap));
            return localClaimsMap;
        } catch (ClaimMetadataException e) {
            throw handleRegistrationServerException("Error while resolving local claims.", e);
        }
    }

    private void buildClaimMappings(Map<String, String> claims, Map.Entry<String, Object> entry,
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
        claims.put(entry.getKey(), claimValue != null ? claimValue.toString() : StringUtils.EMPTY);
        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
            LOG.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : " + claimValue);
        }
    }

    private OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws RegistrationEngineException {

        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            throw handleRegistrationServerException("Error while getting the access token.", e);
        }
        return oAuthResponse;
    }

    private Map<String, Object> getIdTokenClaims(String idToken) {

        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parseJSONObject(new String(decoded)).entrySet();
        } catch (ParseException e) {
            LOG.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }

    private String getAuthenticatedUserId(RegistrationContext context, Map<String, Object> idTokenClaims)
            throws RegistrationEngineException {

        String authenticatedUserId;
        if (isUserIdFoundAmongClaims(context.getAuthenticatorProperties())) {
            authenticatedUserId = getSubjectFromUserIDClaimURI(context.getExternalIdPConfig(), idTokenClaims, context
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
            throw handleRegistrationServerException("Error while resolving user identifier.", null);
        }
        return authenticatedUserId;
    }

    private static String getSubjectFromUserIDClaimURI(ExternalIdPConfig idpConfig, Map<String, Object> idTokenClaims,
                                                       String tenantDomain) {

        boolean useLocalClaimDialect = idpConfig.useDefaultLocalIdpDialect();
        String userIdClaimUri = idpConfig.getUserIdClaimUri();
        try {
            String userIdClaimUriInOIDCDialect = null;
            if (useLocalClaimDialect) {
                if (StringUtils.isNotBlank(userIdClaimUri)) {
                    // User ID is defined in local claim dialect at the IDP.
                    // Find the corresponding OIDC claim and retrieve from idTokenClaims.
                    userIdClaimUriInOIDCDialect = getUserIdClaimUriInOIDCDialect(userIdClaimUri, tenantDomain);
                } else {
                    if (LOG.isDebugEnabled()) {
                        String idpName = idpConfig.getIdPName();
                        LOG.debug("User ID Claim URI is not configured for IDP: " + idpName + ". " +
                                          "Cannot retrieve subject using user id claim URI.");
                    }
                }
            } else {
                ClaimMapping[] claimMappings = idpConfig.getClaimMappings();
                // Try to find the userIdClaimUri within the claimMappings.
                if (!ArrayUtils.isEmpty(claimMappings)) {
                    for (ClaimMapping claimMapping : claimMappings) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Evaluating " + claimMapping.getRemoteClaim().getClaimUri() + " against " +
                                              userIdClaimUri);
                        }
                        if (StringUtils.equals(claimMapping.getRemoteClaim().getClaimUri(), userIdClaimUri)) {
                            // Get the subject claim in OIDC dialect.
                            String userIdClaimUriInLocalDialect = claimMapping.getLocalClaim().getClaimUri();
                            userIdClaimUriInOIDCDialect =
                                    getUserIdClaimUriInOIDCDialect(userIdClaimUriInLocalDialect, tenantDomain);
                            break;
                        }
                    }
                }
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("using userIdClaimUriInOIDCDialect to get subject from idTokenClaims: " +
                                  userIdClaimUriInOIDCDialect);
            }
            Object subject = idTokenClaims.get(userIdClaimUriInOIDCDialect);
            if (subject instanceof String) {
                return (String) subject;
            } else if (subject != null) {
                LOG.warn("Unable to map subject claim (non-String type): " + subject);
            }
        } catch (ClaimMetadataException ex) {
            LOG.error("Error while retrieving claim URI for user id claim: " + userIdClaimUri, ex);
        }
        return null;
    }

    private static String getUserIdClaimUriInOIDCDialect(String userIdClaimInLocalDialect, String spTenantDomain)
            throws ClaimMetadataException {

        List<ExternalClaim> externalClaims = OpenIDConnectAuthenticatorDataHolder.getInstance()
                .getClaimMetadataManagementService().getExternalClaims(OIDC_DIALECT, spTenantDomain);
        String userIdClaimUri = null;
        ExternalClaim oidcUserIdClaim = null;

        for (ExternalClaim externalClaim : externalClaims) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
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

    private static boolean isUserIdFoundAmongClaims(Map<String, String> authenticatorProperties) {

        return Boolean.parseBoolean(authenticatorProperties
                                            .get(IdentityApplicationConstants.Authenticator.OIDC.IS_USER_ID_IN_CLAIMS));
    }

    private String getMultiAttributeSeparator(String tenantDomain) throws RegistrationEngineServerException {

        String attributeSeparator = null;
        try {
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
                if (LOG.isDebugEnabled()) {
                    LOG.debug("For the claim mapping: " + attributeSeparator
                                      + " is used as the attributeSeparator in tenant: " + tenantDomain);
                }
            }
            return attributeSeparator;
        } catch (UserStoreException e) {
            throw handleRegistrationServerException("Error while retrieving the attribute separator.", e);
        }
    }

    private Map<String, Object> getClaimsViaUserInfo(String accessToken,
                                                             Map<String, String> authenticatorProperties) {

        Map<String, Object> claims = new HashMap<>();
        try {
            String url = getUserInfoEndpoint(authenticatorProperties);
            String json = triggerUserInfoRequest(url, accessToken);

            if (StringUtils.isBlank(json)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Empty JSON response from user info endpoint. Unable to fetch user claims." +
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
                    claims.put(key, value);
                }

                if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)
                        && jsonObject.get(key) != null) {
                    LOG.debug("Adding claims from end-point data mapping : " + key + " - " + jsonObject.get(key)
                            .toString());
                }
            }
        } catch (IOException e) {
            LOG.error("Communication error occurred while accessing user info endpoint", e);
        }
        return claims;
    }

    private String triggerUserInfoRequest(String url, String accessToken) throws IOException {

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
        return builder.toString();
    }
}
