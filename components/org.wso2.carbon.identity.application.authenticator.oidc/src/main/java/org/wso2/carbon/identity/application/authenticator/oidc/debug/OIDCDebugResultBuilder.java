/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.debug;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.AccountLookupAttributeMappingConfig;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkServerException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.store.DebugSessionStore;
import org.wso2.carbon.identity.debug.framework.util.DebugDiagnosticsUtil;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Builds, serializes, and persists OIDC debug results and error responses to the session store.
 * Also owns diagnostic detail builders and the diagnostic transform for API responses.
 */
public class OIDCDebugResultBuilder {

    private static final Log LOG = LogFactory.getLog(OIDCDebugResultBuilder.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * Serializes the success result map to JSON and persists it to the session store.
     */
    public void persistDebugResult(String state, DebugContext context, Map<String, Object> debugResult)
            throws DebugFrameworkServerException {

        String debugResultJson;
        try {
            debugResultJson = OBJECT_MAPPER.writeValueAsString(debugResult);
        } catch (JsonProcessingException e) {
            throw new DebugFrameworkServerException(
                    DebugFrameworkConstants.ErrorMessages.ERROR_CODE_SERVER_ERROR.getCode(),
                    DebugFrameworkConstants.ErrorMessages.ERROR_CODE_SERVER_ERROR.getMessage(),
                    "Failed to serialize debug result to JSON: " + e.getMessage(), e);
        }

        context.setProperty(OIDCDebugConstants.DEBUG_RESULT_CACHE_KEY, debugResultJson);
        context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, true);
        String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);
        persistJsonToSessionStore(debugId, state, debugResultJson);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Debug result cached and persisted for debugId: " + debugId);
        }
    }

    /**
     * Builds a structured error response, serializes it to JSON, and persists it to the session store.
     * Snapshots current diagnostics so partial progress is visible even on early failures.
     */
    public void buildAndCacheErrorResponse(String errorCode, String errorDescription,
            String state, DebugContext context) throws DebugFrameworkServerException {

        context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, Boolean.FALSE);
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put(OIDCDebugConstants.DEBUG_RESULT_SUCCESS, false);
        errorResponse.put(OIDCDebugConstants.RESULT_ERROR_CODE, errorCode);
        errorResponse.put(OIDCDebugConstants.OIDC_ERROR_DESCRIPTION_PARAM,
                StringUtils.isNotBlank(errorDescription)
                        ? errorDescription : "An error occurred during OIDC debug processing.");

        String externalRedirectUrl = (String) context.getProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
        if (StringUtils.isNotBlank(externalRedirectUrl)) {
            errorResponse.put(OIDCDebugConstants.RESULT_EXTERNAL_REDIRECT_URL, externalRedirectUrl);
        }

        errorResponse.put(OIDCDebugConstants.DEBUG_DIAGNOSTICS,
                transformDiagnostics(DebugDiagnosticsUtil.getDiagnostics(context)));

        String errorResponseJson;
        try {
            errorResponseJson = OBJECT_MAPPER.writeValueAsString(errorResponse);
        } catch (JsonProcessingException e) {
            throw new DebugFrameworkServerException(
                    DebugFrameworkConstants.ErrorMessages.ERROR_CODE_SERVER_ERROR.getCode(),
                    DebugFrameworkConstants.ErrorMessages.ERROR_CODE_SERVER_ERROR.getMessage(),
                    "Failed to serialize error response to JSON: " + e.getMessage(), e);
        }
        context.setProperty(OIDCDebugConstants.DEBUG_RESULT_CACHE_KEY, errorResponseJson);
        String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);
        persistJsonToSessionStore(debugId, state, errorResponseJson);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Error response cached for state: " + state + " with error: " + errorCode);
        }
    }

    /**
     * Appends the authorization URL, raw ID token, and diagnostics snapshot to the result map.
     */
    public void buildResultMetadata(Map<String, Object> debugResult, DebugContext context) {

        String externalRedirectUrl = (String) context.getProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
        if (StringUtils.isNotBlank(externalRedirectUrl)) {
            debugResult.put(OIDCDebugConstants.RESULT_EXTERNAL_REDIRECT_URL, externalRedirectUrl);
        }

        String idToken = (String) context.getProperty(OIDCDebugConstants.ID_TOKEN);
        if (StringUtils.isNotBlank(idToken)) {
            debugResult.put(OIDCDebugConstants.ID_TOKEN, idToken);
        }

        debugResult.put(OIDCDebugConstants.DEBUG_DIAGNOSTICS,
                transformDiagnostics(DebugDiagnosticsUtil.getDiagnostics(context)));
    }

    /**
     * Builds diagnostic details for a PARTIAL claim mapping result.
     * Returns an empty map for SUCCESS — no extra detail needed in that case.
     * Only reports the first unmapped claim; subsequent ones can be fixed iteratively.
     */
    Map<String, Object> buildClaimMappingDiagnosticDetails(String claimMappingStatus,
            List<Map<String, Object>> mappedClaimsArray) {

        if (!OIDCDebugConstants.STATUS_PARTIAL.equals(claimMappingStatus)) {
            return new LinkedHashMap<>();
        }

        for (Map<String, Object> claim : mappedClaimsArray) {
            if (!OIDCDebugConstants.CLAIM_STATUS_NOT_MAPPED.equals(
                    claim.get(OIDCDebugConstants.CLAIM_MAPPING_STATUS))) {
                continue;
            }
            Object idpClaim = claim.get(OIDCDebugConstants.CLAIM_MAPPING_IDP_CLAIM);
            Object localClaim = claim.get(OIDCDebugConstants.CLAIM_MAPPING_LOCAL_CLAIM);

            Map<String, Object> details = new LinkedHashMap<>();
            details.put(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION,
                    buildUnmappedClaimErrorDescription(
                            idpClaim != null ? idpClaim.toString() : null,
                            localClaim != null ? localClaim.toString() : null));
            return details;
        }

        return new LinkedHashMap<>();
    }

    /**
     * Builds diagnostic details for account linking events.
     * Parses the failure message to extract the specific federated attribute name so it can be
     * surfaced as a structured field in the API response rather than buried in a free-text string.
     */
    String buildMissingAccountLinkingAttributeMessage(AccountLookupAttributeMappingConfig mappingConfig) {

        String federatedAttribute = mappingConfig.getFederatedAttribute();
        String localAttribute = mappingConfig.getLocalAttribute();
        if (StringUtils.isNotBlank(localAttribute)) {
            return "Required Federated IdP attribute '" + federatedAttribute +
                    "' is missing for account linking to local attribute '" + localAttribute + "'.";
        }
        return "Required Federated IdP attribute '" + federatedAttribute + "' is missing for account linking.";
    }

    Map<String, Object> buildAccountLinkingDetails(DebugContext context) {

        Map<String, Object> details = new LinkedHashMap<>();
        Object accountLinkingMessage = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE);
        if (!(accountLinkingMessage instanceof String)
                || StringUtils.isBlank((String) accountLinkingMessage)) {
            return details;
        }
        details.put(OIDCDebugConstants.ACCOUNT_LINKING_REASON, accountLinkingMessage);

        Object federatedAttribute =
                context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_FEDERATED_ATTRIBUTE);
        if (federatedAttribute instanceof String && StringUtils.isNotBlank((String) federatedAttribute)) {
            details.put(OIDCDebugConstants.DIAG_FEDERATED_ATTRIBUTE, federatedAttribute);
        }
        return details;
    }

    /**
     * Persists the JSON result under the debugId (preferred) or state (fallback on early error paths).
     */
    private void persistJsonToSessionStore(String debugId, String state, String resultJson) {

        String storeKey = StringUtils.isNotBlank(debugId) ? debugId : state;
        if (StringUtils.isBlank(storeKey)) {
            LOG.error("Cannot persist debug result: neither debugId nor state is available.");
            return;
        }

        try {
            DebugSessionStore.getInstance().putResult(storeKey, resultJson);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Debug result persisted under key: " + storeKey);
            }
        } catch (DebugFrameworkServerException e) {
            LOG.error("Error persisting debug result to cache: " + e.getMessage(), e);
        }
    }

    private String buildUnmappedClaimErrorDescription(String unmappedIdpClaim, String unmappedLocalClaim) {

        if (StringUtils.isNotBlank(unmappedIdpClaim) && StringUtils.isNotBlank(unmappedLocalClaim)) {
            return "The IdP claim '" + unmappedIdpClaim + "' is not mapped to the IS local claim '" +
                    unmappedLocalClaim + "'.";
        }
        if (StringUtils.isNotBlank(unmappedIdpClaim)) {
            return "The IdP claim '" + unmappedIdpClaim + "' is not mapped to an IS local claim.";
        }
        if (StringUtils.isNotBlank(unmappedLocalClaim)) {
            return "The IS local claim '" + unmappedLocalClaim + "' does not have a mapped IdP claim.";
        }
        return "Couldn't map one or more IdP claims to local claims. Please review claim mappings.";
    }

    private List<Map<String, Object>> transformDiagnostics(List<Map<String, Object>> diagnostics) {

        return diagnostics.stream().map(this::transformDiagnosticEvent).collect(Collectors.toList());
    }

    /**
     * Reshapes a raw diagnostic event map for the API response:
     * promotes selected keys (errorCode, errorDescription, federatedAttribute) from the nested
     * "details" object up to the top level, and drops internal keys that must not leak to clients.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> transformDiagnosticEvent(Map<String, Object> diagnostic) {

        Map<String, Object> sanitizedEvent = new LinkedHashMap<>(diagnostic);
        Object detailsObj = sanitizedEvent.get(DebugFrameworkConstants.DIAGNOSTIC_DETAILS);
        if (!(detailsObj instanceof Map)) {
            return sanitizedEvent;
        }

        Map<String, Object> details = new LinkedHashMap<>((Map<String, Object>) detailsObj);

        Object errorCode = details.remove(OIDCDebugConstants.DIAG_ERROR_CODE);
        Object errorDescription = details.remove(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION);
        Object accountLinkingReason = details.remove(OIDCDebugConstants.ACCOUNT_LINKING_REASON);
        Object federatedAttribute = details.remove(OIDCDebugConstants.DIAG_FEDERATED_ATTRIBUTE);

        OIDCDebugConstants.DIAGNOSTIC_INTERNAL_DETAIL_KEYS.forEach(details::remove);

        if (errorCode != null) {
            sanitizedEvent.put(OIDCDebugConstants.DIAG_ERROR_CODE, errorCode);
        }
        if (errorDescription == null && accountLinkingReason != null) {
            errorDescription = accountLinkingReason;
        }
        if (errorDescription != null) {
            sanitizedEvent.put(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION, errorDescription);
        }
        if (federatedAttribute != null) {
            sanitizedEvent.put(OIDCDebugConstants.DIAG_FEDERATED_ATTRIBUTE, federatedAttribute);
        }

        if (details.isEmpty()) {
            sanitizedEvent.remove(DebugFrameworkConstants.DIAGNOSTIC_DETAILS);
        } else {
            sanitizedEvent.put(DebugFrameworkConstants.DIAGNOSTIC_DETAILS, details);
        }
        return sanitizedEvent;
    }
}
