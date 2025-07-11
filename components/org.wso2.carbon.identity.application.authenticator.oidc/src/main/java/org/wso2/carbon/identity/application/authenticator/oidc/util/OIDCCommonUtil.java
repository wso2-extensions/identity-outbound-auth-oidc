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

package org.wso2.carbon.identity.application.authenticator.oidc.util;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.minidev.json.JSONArray;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.internal.OpenIDConnectAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.DiagnosticLog;
import static org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants.LogConstants.ActionIDs.INVOKE_USER_INFO_ENDPOINT;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.OIDC.IS_USER_ID_IN_CLAIMS;
import static org.wso2.carbon.identity.base.IdentityConstants.IdentityTokens.USER_CLAIMS;
import static org.wso2.carbon.utils.DiagnosticLog.ResultStatus.SUCCESS;

/**
 * This class holds the utils related to the OIDC authentication.
 */
public class OIDCCommonUtil {

    private static final Log LOG = LogFactory.getLog(OIDCCommonUtil.class);
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    /**
     * This method is used to update the claim mappings with the given claim mapping and the entry.
     *
     * @param claims    Claims to be updated.
     * @param entry     THe new claim entry.
     * @param separator Separator to be used for the claim value.
     */
    public static void buildClaimMappings(Map<ClaimMapping, String> claims, Map.Entry<String, Object> entry,
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
    }

    /**
     * This method checks whether authenticator property is set to get user id from the claims.
     *
     * @param authenticatorProperties Authenticator properties.
     * @return True if user id is found among claims.
     */
    public static boolean isUserIdFoundAmongClaims(Map<String, String> authenticatorProperties) {

        return Boolean.parseBoolean(authenticatorProperties.get(IS_USER_ID_IN_CLAIMS));
    }

    /**
     * This method is used to get the user id from the claims.
     *
     * @param idpConfig     IDP configuration.
     * @param idTokenClaims ID token claims.
     * @param tenantDomain  Tenant domain.
     * @return User id.
     * @throws ClaimMetadataException If an error occurs while getting the claim metadata.
     */
    public static String getSubjectFromUserIDClaimURI(ExternalIdPConfig idpConfig, Map<String, Object> idTokenClaims,
                                                      String tenantDomain) throws ClaimMetadataException {

        boolean useLocalClaimDialect = idpConfig.useDefaultLocalIdpDialect();
        String userIdClaimUri = idpConfig.getUserIdClaimUri();
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
        if (LOG.isDebugEnabled()) {
            LOG.debug("Couldn't find the subject claim among id_token claims for IDP: " + idpConfig.getIdPName());
        }
        return null;
    }

    /**
     * Triggers a request to the given URL with the provided access token.
     *
     * @param url         The url to trigger.
     * @param accessToken The access token to be used for the request.
     * @return The response from the request.
     * @throws IOException If an error occurs while reading the response.
     */
    public static String triggerRequest(String url, String accessToken) throws IOException {

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

    /**
     * This method is used to get the multi attribute separator for the given tenant domain.
     *
     * @param tenantDomain Tenant domain.
     * @return Multi attribute separator.
     * @throws UserStoreException If an error occurs while getting the user store manager.
     */
    public static String getMultiAttributeSeparator(String tenantDomain) throws UserStoreException {

        String attributeSeparator = null;
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
                LOG.debug("For the claim mapping: " + attributeSeparator +
                                  " is used as the attributeSeparator in tenant: " + tenantDomain);
            }
        }
        return attributeSeparator;
    }

    /**
     * This method is used to get the user id claim uri in OIDC dialect.
     *
     * @param userIdClaimInLocalDialect User id claim in local dialect.
     * @param tenantDomain              Tenant domain.
     * @return User id claim uri in OIDC dialect.
     * @throws ClaimMetadataException If an error occurs while getting the claim metadata.
     */
    public static String getUserIdClaimUriInOIDCDialect(String userIdClaimInLocalDialect, String tenantDomain)
            throws ClaimMetadataException {

        List<ExternalClaim> externalClaims = OpenIDConnectAuthenticatorDataHolder.getInstance()
                .getClaimMetadataManagementService().getExternalClaims(OIDC_DIALECT, tenantDomain);
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

    /**
     * This method is used to decode the ID token payload.
     *
     * @param idToken ID token.
     * @return Set of entries in the ID token payload.
     * @throws ParseException If an error occurs while parsing the ID token payload.
     */
    public static Set<Map.Entry<String, Object>> parseIDToken(String idToken) throws ParseException {

        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        return JSONObjectUtils.parseJSONObject(new String(decoded)).entrySet();
    }

    /**
     * This method is used to extract the user claims from the JSON payload.
     *
     * @param json JSON payload.
     * @return Map of claims.
     */
    public static Map<ClaimMapping, String> extractUserClaimsFromJsonPayload(String json) {

        Map<ClaimMapping, String> claims = new HashMap<>();

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
                claims.put(ClaimMapping.build(key, key, null, false), value);
            }

            if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(USER_CLAIMS) && jsonObject.get(key) != null) {
                LOG.debug(
                        "Adding claims from end-point data mapping : " + key + " - " + jsonObject.get(key).toString());
            }
        }
        return claims;
    }
}
