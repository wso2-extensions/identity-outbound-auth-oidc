/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.debug;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants.ErrorMessages;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.exception.DebugExecutionException;
import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkServerException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.model.DebugResult;
import org.wso2.carbon.identity.debug.framework.store.DebugSessionStore;
import org.wso2.carbon.identity.debug.framework.util.DebugDiagnosticsUtil;

/**
 * OIDC debug flow executor.
 * Reads resolved OIDC parameters from the context (populated by OIDCContextProvider), delegates authorization URL
 * construction to {@link OIDCCommonUtil#buildAuthorizationUrl}, and persists the context to the session store for
 * callback retrieval.
 */
public class OIDCDebugExecutor extends DebugExecutor {

    private static final Log LOG = LogFactory.getLog(OIDCDebugExecutor.class);

    @Override
    public DebugResult execute(DebugContext context) throws DebugExecutionException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Executing OIDC authorization URL generation");
        }

        try {
            String clientId = (String) context.getProperty(OIDCDebugConstants.CLIENT_ID);
            String authzEndpoint = (String) context.getProperty(OIDCDebugConstants.AUTHORIZATION_ENDPOINT);
            String scope = (String) context.getProperty(OIDCDebugConstants.IDP_SCOPE);
            String redirectUri = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);

            byte[] nonceBytes = new byte[32];
            new SecureRandom().nextBytes(nonceBytes);
            String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
            String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);

            // Nonce stored here is validated against the id_token nonce claim during callback processing.
            context.setProperty(OIDCDebugConstants.DEBUG_NONCE, nonce);

            String authorizationUrl = buildAuthorizationUrl(authzEndpoint, clientId, redirectUri,
                    scope, debugId, nonce, null, null, null);
            context.setProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL, authorizationUrl);

            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_SUCCESS, "Configurations validated successfully.");

            cacheDebugContext(context);

            DebugResult result = new DebugResult();
            result.setDebugId(debugId);
            result.setStatus(DebugFrameworkConstants.DEBUG_STATUS_SUCCESS_INCOMPLETE);
            result.addResultData(OIDCDebugConstants.RESULT_AUTHORIZATION_URL, authorizationUrl);

            if (LOG.isDebugEnabled()) {
                LOG.debug("OIDC Authorization URL generated: debugId=" + debugId);
            }
            return result;

        } catch (DebugExecutionException e) {
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_FAILED, e.getMessage());
            throw e;
        } catch (OAuthSystemException e) {
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_FAILED, "Error building authorization URL: " + e.getMessage());
            throw new DebugExecutionException(ErrorMessages.ERROR_CODE_EXECUTION_FAILED.getCode(),
                    ErrorMessages.ERROR_CODE_EXECUTION_FAILED.getMessage(),
                    "Error building authorization URL: " + e.getMessage(), e);
        }
    }

    /*
     * Builds an OIDC authorization request URL with optional PKCE and nonce parameters.
     */
    public static String buildAuthorizationUrl(String authorizationEndpoint, String clientId, String callbackUrl,
                                               String scopes, String state, String nonce,
                                               String codeChallenge, String codeChallengeMethod,
                                               Map<String, String> additionalParams) throws OAuthSystemException {

        OAuthClientRequest.AuthenticationRequestBuilder builder = OAuthClientRequest
                .authorizationLocation(authorizationEndpoint)
                .setClientId(clientId)
                .setRedirectURI(callbackUrl)
                .setResponseType(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                .setScope(scopes)
                .setState(state);

        if (StringUtils.isNotBlank(nonce)) {
            builder.setParameter(OIDCAuthenticatorConstants.Claim.NONCE, nonce);
        }
        if (StringUtils.isNotBlank(codeChallenge)) {
            builder.setParameter("code_challenge", codeChallenge);
            builder.setParameter("code_challenge_method",
                    StringUtils.isNotBlank(codeChallengeMethod) ? codeChallengeMethod : "S256");
        }
        if (additionalParams != null) {
            for (Map.Entry<String, String> entry : additionalParams.entrySet()) {
                builder.setParameter(entry.getKey(), entry.getValue());
            }
        }
        return builder.buildQueryMessage().getLocationUri();
    }

    private void cacheDebugContext(DebugContext context) throws DebugExecutionException {

        String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);

        try {
            DebugContext cachedContext = DebugContext.buildContextFromMap(context.getProperties());
            cachedContext.setResourceType(context.getResourceType());
            DebugSessionStore.getInstance().put(debugId, cachedContext);
        } catch (DebugFrameworkServerException e) {
            throw new DebugExecutionException(e.getErrorCode(), e.getMessage(),
                    "Failed to cache debug context for debugId: " + debugId, e);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Debug context cached successfully with debugId: " + debugId);
        }
    }
}
