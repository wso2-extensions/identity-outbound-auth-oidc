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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor;
import org.wso2.carbon.identity.application.common.model.AccountLookupAttributeMappingConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkServerException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.util.DebugDiagnosticsUtil;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugProcessor;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OIDC-specific implementation of IdpDebugProcessor. Handles the OIDC authorization code callback by
 * driving the same {@link OpenIDConnectExecutor#execute} path used by production OIDC signup, then
 * runs debug-only stages (claim mapping, account linking) over the resolved local claims and persists
 * the debug result.
 */
public class OIDCDebugProcessor extends IdpDebugProcessor {

    private static final Log LOG = LogFactory.getLog(OIDCDebugProcessor.class);
    private final OpenIDConnectExecutor executor;
    private final OIDCDebugResultBuilder resultBuilder = new OIDCDebugResultBuilder();

    public OIDCDebugProcessor() {

        this(createDefaultExecutor());
    }

    public OIDCDebugProcessor(OpenIDConnectExecutor executor) {

        this.executor = executor;
    }

    static OpenIDConnectExecutor createDefaultExecutor() {

        return new OpenIDConnectExecutor() {
            @Override
            protected void onRawClaimsResolved(FlowExecutionContext flowExecutionContext, String idToken,
                    Map<String, Object> rawClaims) {

                if (StringUtils.isNotBlank(idToken)) {
                    flowExecutionContext.setProperty(OIDCDebugConstants.ID_TOKEN, idToken);
                }
                flowExecutionContext.setProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS, new HashMap<>(rawClaims));
            }
        };
    }

    @Override
    protected boolean processAuthentication(HttpServletRequest request, DebugContext context,
            HttpServletResponse response, String state, String resourceIdentifier) throws DebugFrameworkServerException {

        String error = request.getParameter(OIDCDebugConstants.OIDC_ERROR_PARAM);
        if (error != null) {
            String errorDescription = request.getParameter(OIDCDebugConstants.OIDC_ERROR_DESCRIPTION_PARAM);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, error + ": " + errorDescription);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            resultBuilder.buildAndCacheErrorResponse(error, errorDescription, state, context);
            return false;
        }

        String resourceId = (String) context.getProperty(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID);
        IdentityProvider idp;
        try {
            idp = IdentityProviderManager.getInstance().getIdPByResourceId(resourceId,
                    IdentityTenantUtil.resolveTenantDomain(), true);
        } catch (IdentityProviderManagementException e) {
            throw new DebugFrameworkServerException("OIDC_DEBUG_IDP_RESOLVE_ERROR",
                    "Failed to resolve IdP by resourceId: " + resourceId, e.getMessage(), e);
        }
        context.setProperty(OIDCDebugConstants.IDP_CONFIG, idp);
        Map<String, String> authenticatorProperties = resolveAuthenticatorProperties(context);
        // Credentials are scrubbed from the session store before caching; re-inject from the
        // freshly-fetched IdP so the token exchange has access to the client secret.
        String clientSecret = extractClientSecretFromIdP(idp);
        if (StringUtils.isNotBlank(clientSecret)) {
            authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, clientSecret);
        }
        if (!validateRequiredTokenConfig(authenticatorProperties, state, context)) {
            return false;
        }

        return retrieveTokensFromCode(request, context, state, authenticatorProperties);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected Map<String, Object> extractClaims(DebugContext context, String state) {

        Object resolvedLocalClaims = context.getProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS);
        Map<String, Object> claims = resolvedLocalClaims instanceof Map
                ? new HashMap<>((Map<String, Object>) resolvedLocalClaims)
                : new HashMap<>();

        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                OIDCDebugConstants.STATUS_SUCCESS, "Claims extracted successfully from executor response.");
        if (LOG.isDebugEnabled()) {
            LOG.debug("Extracted " + claims.size() + " claims from executor response: " + claims.keySet());
        }
        return claims;
    }

    @Override
    protected void buildAndCacheDebugResult(DebugContext context, String state, Map<String, Object> claims)
            throws DebugFrameworkServerException {

        Map<String, Object> normalizedClaims = normalizeIncomingClaims(claims != null ? claims : new HashMap<>());
        IdentityProvider idp = (IdentityProvider) context.getProperty(OIDCDebugConstants.IDP_CONFIG);

        Map<String, Object> debugResult = new HashMap<>();
        processClaimMappings(context, idp, normalizedClaims, debugResult);
        evaluateAccountLinking(context, idp, normalizedClaims);
        resultBuilder.buildResultMetadata(debugResult, context);
        resultBuilder.persistDebugResult(state, context, debugResult);
    }

    @Override
    protected void sendDebugResponse(HttpServletResponse response, String state,
            String resourceIdentifier) throws DebugFrameworkServerException {

        try {
            String successPageUrl = IdentityUtil.getServerURL(OIDCDebugConstants.DEBUG_SUCCESS_PAGE, true, true);
            response.sendRedirect(successPageUrl + "?state=" + state);
        } catch (IOException e) {
            throw new DebugFrameworkServerException(
                    DebugFrameworkConstants.ErrorMessages.ERROR_CODE_SERVER_ERROR.getCode(),
                    DebugFrameworkConstants.ErrorMessages.ERROR_CODE_SERVER_ERROR.getMessage(),
                    e.getMessage(),
                    e);
        }
    }

    /**
     * Flattens nested map-valued claims to the top level so they can be matched against IdP claim mappings.
     * Sub-keys are added both as plain keys and prefixed with the parent key.
     */
    private Map<String, Object> normalizeIncomingClaims(Map<String, Object> incomingClaims) {

        Map<String, Object> normalizedClaims = new HashMap<>(incomingClaims);
        for (Map.Entry<String, Object> entry : incomingClaims.entrySet()) {
            if (!(entry.getValue() instanceof Map)) {
                continue;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> nestedClaims = (Map<String, Object>) entry.getValue();
            for (Map.Entry<String, Object> nestedEntry : nestedClaims.entrySet()) {
                if (nestedEntry.getValue() == null) {
                    continue;
                }
                normalizedClaims.putIfAbsent(nestedEntry.getKey(), nestedEntry.getValue());
                normalizedClaims.put(entry.getKey() + "." + nestedEntry.getKey(), nestedEntry.getValue());
            }
        }
        return normalizedClaims;
    }

    /**
     * Processes IdP claim mappings against incoming OIDC claims and writes the mapped claims array
     * to the debug result. Records a diagnostic event for the claim mapping stage.
     */
    private void processClaimMappings(DebugContext context, IdentityProvider idp,
            Map<String, Object> incomingClaims, Map<String, Object> debugResult) {

        Map<String, String> idpClaimMappings = extractIdPClaimMappings(idp);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Building mapped claims array from " + idpClaimMappings.size() +
                    " configured mappings. Incoming claims: " +
                    (incomingClaims.isEmpty() ? "none" : incomingClaims.keySet()));
        }

        List<Map<String, Object>> mappedClaimsArray = buildMappedClaimsArray(idpClaimMappings, incomingClaims);
        debugResult.put(OIDCDebugConstants.RESULT_MAPPED_CLAIMS, mappedClaimsArray);

        // SUCCESS if all mappings resolved, PARTIAL if any remain unmapped.
        String claimMappingStatus = determineClaimMappingStatus(mappedClaimsArray, idpClaimMappings);
        String statusMessage = OIDCDebugConstants.STATUS_PARTIAL.equals(claimMappingStatus)
                ? "Claim mappings are partially successful."
                : "Claim mapping processing successful.";
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_MAPPING, claimMappingStatus,
                statusMessage, resultBuilder.buildClaimMappingDiagnosticDetails(claimMappingStatus, mappedClaimsArray));
    }

    /**
     * Evaluates account linking readiness by checking whether the required federated attributes
     * are present in the incoming claims. Records a diagnostic event for the account linking stage.
     */
    private void evaluateAccountLinking(DebugContext context, IdentityProvider idp,
            Map<String, Object> incomingClaims) {

        Object existingStatus = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS);
        if (!isAccountLinkingEnabled(idp) || (existingStatus instanceof String
                && StringUtils.isNotBlank((String) existingStatus))) {
            return;
        }

        if (idp.getJustInTimeProvisioningConfig() == null) {
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                    OIDCDebugConstants.STATUS_PENDING, "Account linking configuration is not available.",
                    resultBuilder.buildAccountLinkingDetails(context));
            return;
        }

        AccountLookupAttributeMappingConfig[] accountLookupMappings =
                idp.getJustInTimeProvisioningConfig().getAccountLookupAttributeMappings();
        if (accountLookupMappings == null || accountLookupMappings.length == 0) {
            evaluateDefaultAccountLinkingAttribute(context, incomingClaims);
        } else {
            evaluateConfiguredAccountLinkingAttributes(context, incomingClaims, accountLookupMappings);
        }

        Object statusProp = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS);
        String accountLinkingStatus = (statusProp instanceof String && StringUtils.isNotBlank((String) statusProp))
                ? (String) statusProp : OIDCDebugConstants.STATUS_PENDING;
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                accountLinkingStatus,
                OIDCDebugConstants.STATUS_FAILED.equals(accountLinkingStatus)
                        ? "Account linking attribute check failed."
                        : "Account linking attribute check successful.",
                resultBuilder.buildAccountLinkingDetails(context));
    }

    private Map<String, String> extractIdPClaimMappings(IdentityProvider idp) {

        Map<String, String> mappings = new HashMap<>();
        if (idp == null || idp.getClaimConfig() == null || idp.getClaimConfig().getClaimMappings() == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No claim configuration found in IdP");
            }
            return mappings;
        }

        for (ClaimMapping claimMapping : idp.getClaimConfig().getClaimMappings()) {
            if (claimMapping == null || claimMapping.getRemoteClaim() == null
                    || claimMapping.getLocalClaim() == null) {
                continue;
            }
            String remoteClaimUri = claimMapping.getRemoteClaim().getClaimUri();
            if (StringUtils.isBlank(remoteClaimUri)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Skipping claim mapping with blank remote claim URI");
                }
                continue;
            }
            mappings.put(remoteClaimUri, claimMapping.getLocalClaim().getClaimUri());

            if (LOG.isDebugEnabled()) {
                LOG.debug("Extracted claim mapping: " + remoteClaimUri + " -> "
                        + claimMapping.getLocalClaim().getClaimUri());
            }
        }
        return mappings;
    }

    private List<Map<String, Object>> buildMappedClaimsArray(
            Map<String, String> idpClaimMappings, Map<String, Object> incomingClaims) {

        List<Map<String, Object>> mappedClaimsArray = new ArrayList<>();
        for (Map.Entry<String, String> mapping : idpClaimMappings.entrySet()) {
            String remoteClaimUri = mapping.getKey();
            String localClaimUri = mapping.getValue();

            Map<String, Object> claimEntry = new HashMap<>();
            claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_IDP_CLAIM, remoteClaimUri);
            claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_LOCAL_CLAIM,
                    localClaimUri != null ? localClaimUri : "");

            if (incomingClaims.containsKey(remoteClaimUri)) {
                claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_VALUE,
                        incomingClaims.get(remoteClaimUri).toString());
                claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_STATUS, OIDCDebugConstants.CLAIM_STATUS_SUCCESSFUL);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Mapped claim: " + remoteClaimUri + " -> " + localClaimUri);
                }
            } else {
                claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_STATUS, OIDCDebugConstants.CLAIM_STATUS_NOT_MAPPED);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Claim not found in incoming claims: " + remoteClaimUri);
                }
            }
            mappedClaimsArray.add(claimEntry);
        }
        return mappedClaimsArray;
    }

    /**
     * Returns SUCCESS if all configured mappings resolved, PARTIAL if any are missing.
     * Returns SUCCESS immediately when there are no configured mappings (nothing to fail).
     */
    private String determineClaimMappingStatus(List<Map<String, Object>> mappedClaimsArray,
            Map<String, String> idpClaimMappings) {

        if (idpClaimMappings.isEmpty()) {
            return OIDCDebugConstants.STATUS_SUCCESS;
        }

        for (Map<String, Object> claim : mappedClaimsArray) {
            if (OIDCDebugConstants.CLAIM_STATUS_NOT_MAPPED.equals(
                    claim.get(OIDCDebugConstants.CLAIM_MAPPING_STATUS))) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Claim mapping status: PARTIAL.");
                }
                return OIDCDebugConstants.STATUS_PARTIAL;
            }
        }
        return OIDCDebugConstants.STATUS_SUCCESS;
    }

    private void evaluateDefaultAccountLinkingAttribute(DebugContext context,
            Map<String, Object> incomingClaims) {

        if (StringUtils.isBlank(getStringClaim(incomingClaims, OIDCDebugConstants.CLAIM_EMAIL))) {
            setAccountLinkingFailure(context, "\"email\" is missing.", OIDCDebugConstants.CLAIM_EMAIL);
        } else {
            setAccountLinkingSuccess(context);
        }
    }

    private void evaluateConfiguredAccountLinkingAttributes(DebugContext context,
            Map<String, Object> incomingClaims,
            AccountLookupAttributeMappingConfig[] accountLookupMappings) {

        for (AccountLookupAttributeMappingConfig mappingConfig : accountLookupMappings) {
            if (mappingConfig == null || StringUtils.isBlank(mappingConfig.getFederatedAttribute())) {
                continue;
            }
            if (StringUtils.isBlank(getStringClaim(incomingClaims, mappingConfig.getFederatedAttribute()))) {
                setAccountLinkingFailure(context,
                        resultBuilder.buildMissingAccountLinkingAttributeMessage(mappingConfig),
                        mappingConfig.getFederatedAttribute());
                return;
            }
        }
        setAccountLinkingSuccess(context);
    }

    private void setAccountLinkingSuccess(DebugContext context) {

        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE, null);
        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_FEDERATED_ATTRIBUTE, null);
    }

    private void setAccountLinkingFailure(DebugContext context, String message, String federatedAttribute) {

        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS, OIDCDebugConstants.STATUS_FAILED);
        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE, message);
        if (StringUtils.isNotBlank(federatedAttribute)) {
            context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_FEDERATED_ATTRIBUTE, federatedAttribute);
        }
    }

    private boolean isAccountLinkingEnabled(IdentityProvider idp) {

        if (idp == null) {
            return false;
        }
        JustInTimeProvisioningConfig jitConfig = idp.getJustInTimeProvisioningConfig();
        return jitConfig != null && jitConfig.isProvisioningEnabled() && jitConfig.isAssociateLocalUserEnabled();
    }

    /**
     * Drives the OIDC token exchange through {@link OpenIDConnectExecutor#execute} so the wire-level
     * path matches production OIDC signup. The executor returns the resolved local claims via
     * {@link ExecutorResponse#getUpdatedUserClaims()}; that map is stashed on the debug context for
     * downstream stages (claim mapping, account linking).
     */
    private boolean retrieveTokensFromCode(HttpServletRequest request, DebugContext context, String state,
            Map<String, String> authenticatorProperties) throws DebugFrameworkServerException {

        String code = request.getParameter(OIDCDebugConstants.OIDC_CODE_PARAM);
        String callbackUrl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);

        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_STARTED, "Starting OIDC token exchange.");

        IdentityProvider idp = (IdentityProvider) context.getProperty(OIDCDebugConstants.IDP_CONFIG);
        FlowExecutionContext flowContext = buildFlowExecutionContext(authenticatorProperties, code, callbackUrl,
                state, idp);

        ExecutorResponse response = executor.execute(flowContext);

        if (response != null && Constants.ExecutorStatus.STATUS_COMPLETE.equals(response.getResult())) {
            Object idToken = flowContext.getProperty(OIDCDebugConstants.ID_TOKEN);
            if (idToken instanceof String) {
                context.setProperty(OIDCDebugConstants.ID_TOKEN, idToken);
            }
            Object rawClaims = flowContext.getProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS);
            if (rawClaims instanceof Map) {
                context.setProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS, rawClaims);
            } else {
                Map<String, Object> resolvedClaims = response.getUpdatedUserClaims();
                if (resolvedClaims != null) {
                    context.setProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS, resolvedClaims);
                }
            }
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_SUCCESS, "Token received successfully.");
            return true;
        }

        String errorMessage = response != null && StringUtils.isNotBlank(response.getErrorMessage())
                ? response.getErrorMessage() : "OIDC token exchange failed.";
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_FAILED, "OIDC token exchange failed.",
                buildErrorDetails("TOKEN_EXCHANGE_ERROR", errorMessage));
        context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Token exchange error: " + errorMessage);
        context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
        resultBuilder.buildAndCacheErrorResponse("TOKEN_EXCHANGE_ERROR",
                "Token exchange error: " + errorMessage, state, context);
        return false;
    }

    /**
     * Builds a {@link FlowExecutionContext} shaped to satisfy {@link OpenIDConnectExecutor#execute}:
     * code and state in {@code userInputData}, a matching {@code state} property (to pass the state
     * check in {@code processResponse}), authenticator properties, callback URL, tenant, IdP config,
     * and a throwaway {@link FlowUser}.
     */
    private FlowExecutionContext buildFlowExecutionContext(Map<String, String> authenticatorProperties,
            String code, String callbackUrl, String state, IdentityProvider idp) {

        FlowExecutionContext flowContext = new FlowExecutionContext();
        flowContext.setAuthenticatorProperties(authenticatorProperties);
        flowContext.setPortalUrl(callbackUrl);
        flowContext.setCallbackUrl(callbackUrl);
        flowContext.setTenantDomain(IdentityTenantUtil.resolveTenantDomain());
        flowContext.setFlowUser(new FlowUser());
        if (idp != null) {
            flowContext.setExternalIdPConfig(new ExternalIdPConfig(idp));
        }

        Map<String, String> userInputs = new HashMap<>();
        userInputs.put(OIDCAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE, code);
        userInputs.put(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE, state);
        flowContext.setUserInputData(userInputs);
        flowContext.setProperty(OIDCAuthenticatorConstants.OAUTH2_PARAM_STATE, state);
        return flowContext;
    }

    private boolean validateRequiredTokenConfig(Map<String, String> properties, String state, DebugContext context)
            throws DebugFrameworkServerException {

        boolean missingEndpoint = StringUtils.isBlank(properties.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL));
        boolean missingClientId = StringUtils.isBlank(properties.get(OIDCAuthenticatorConstants.CLIENT_ID));
        boolean missingSecret = StringUtils.isBlank(properties.get(OIDCAuthenticatorConstants.CLIENT_SECRET));

        if (!missingEndpoint && !missingClientId && !missingSecret) {
            return true;
        }

        String errorCode;
        String errorDescription;
        if (missingEndpoint && missingClientId) {
            errorCode = "CONFIG_MISSING";
            errorDescription = "Token endpoint and client ID are not configured for the IdP.";
        } else if (missingEndpoint) {
            errorCode = "TOKEN_ENDPOINT_MISSING";
            errorDescription = "Token endpoint is not configured for the IdP.";
        } else if (missingClientId) {
            errorCode = "CLIENT_ID_MISSING";
            errorDescription = "Client ID is not configured for the IdP.";
        } else {
            errorCode = "CLIENT_SECRET_MISSING";
            errorDescription = "Client secret is not configured for the IdP.";
        }
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_FAILED, errorDescription);
        resultBuilder.buildAndCacheErrorResponse(errorCode, errorDescription, state, context);
        context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
        return false;
    }

    private String extractClientSecretFromIdP(IdentityProvider idp) {

        FederatedAuthenticatorConfig[] configs = idp.getFederatedAuthenticatorConfigs();
        if (configs == null) {
            return null;
        }
        for (FederatedAuthenticatorConfig config : configs) {
            if (config == null || !config.isEnabled()) {
                continue;
            }
            for (Property prop : config.getProperties()) {
                if (prop != null && OIDCAuthenticatorConstants.CLIENT_SECRET.equals(prop.getName())) {
                    return prop.getValue();
                }
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> resolveAuthenticatorProperties(DebugContext context) {

        Map<String, String> properties =
                (Map<String, String>) context.getProperty(OIDCDebugConstants.AUTHENTICATOR_PROPERTIES);
        return properties != null ? new HashMap<>(properties) : new HashMap<>();
    }

    private String getStringClaim(Map<String, Object> claims, String claimName) {

        Object value = claims.get(claimName);
        return value instanceof String ? (String) value : null;
    }

    private Map<String, Object> buildErrorDetails(String errorCode, String errorDescription) {

        Map<String, Object> details = new LinkedHashMap<>();
        if (StringUtils.isNotBlank(errorCode)) {
            details.put(OIDCDebugConstants.DIAG_ERROR_CODE, errorCode);
        }

        if (StringUtils.isNotBlank(errorDescription)) {
            details.put(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION, errorDescription);
        }
        return details;
    }
}
