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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationContextCache;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationContextCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationContextCacheKey;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants.ErrorMessages;
import org.wso2.carbon.identity.debug.framework.cache.DebugSessionCache;
import org.wso2.carbon.identity.debug.framework.core.DebugProcessor;
import org.wso2.carbon.identity.debug.framework.extension.DebugCallbackHandler;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OAuth-style debug callback handler owned by the OIDC protocol bundle.
 */
public class OIDCDebugCallbackHandler implements DebugCallbackHandler {

    private static final Log LOG = LogFactory.getLog(OIDCDebugCallbackHandler.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final String CONTEXT_KEY_CONNECTION_ID = "connectionId";
    private static final String CONTEXT_KEY_RESOURCE_NAME = "resourceName";
    private static final String REQUEST_KEY_CONNECTION_ID = "connectionId";
    private static final String REQUEST_KEY_IDP_NAME = "idpName";
    private static final String CONTEXT_KEY_PROTOCOL = "protocol";

    private final DebugProcessor processor;
    private final Set<String> supportedProtocols;

    public OIDCDebugCallbackHandler(DebugProcessor processor) {

        this(processor, OIDCDebugConstants.PROTOCOL_TYPE, DebugFrameworkConstants.PROTOCOL_TYPE_GOOGLE,
                DebugFrameworkConstants.PROTOCOL_TYPE_GITHUB);
    }

    public OIDCDebugCallbackHandler(DebugProcessor processor, String... supportedProtocols) {

        this.processor = processor;
        TreeSet<String> normalizedProtocols = new TreeSet<>();
        if (supportedProtocols != null) {
            Arrays.stream(supportedProtocols)
                    .filter(StringUtils::isNotBlank)
                    .map(protocol -> protocol.trim().toLowerCase(Locale.ENGLISH))
                    .forEach(normalizedProtocols::add);
        }
        this.supportedProtocols = Collections.unmodifiableSet(normalizedProtocols);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String state = request.getParameter(DebugFrameworkConstants.OIDC_STATE_PARAM);
        if (state == null || !state.startsWith(DebugFrameworkConstants.DEBUG_PREFIX)) {
            return false;
        }

        boolean hasCallbackParams = request.getParameter(DebugFrameworkConstants.OIDC_CODE_PARAM) != null
                || request.getParameter(DebugFrameworkConstants.OIDC_ERROR_PARAM) != null;
        if (!hasCallbackParams) {
            return false;
        }

        return isSupportedProtocol(state);
    }

    @Override
    public boolean handleCallback(HttpServletRequest request, HttpServletResponse response) {

        if (!canHandle(request)) {
            return false;
        }

        try {
            processDebugFlowCallback(request, response);
        } catch (IOException e) {
            LOG.error("Error processing debug flow callback", e);
            if (!response.isCommitted()) {
                sendIOErrorResponse(response);
            }
        } catch (RuntimeException e) {
            LOG.error("Unexpected runtime error while processing debug flow callback", e);
            if (!response.isCommitted()) {
                sendIOErrorResponse(response);
            }
        }

        return true;
    }

    private boolean isSupportedProtocol(String state) {

        if (CollectionUtils.isEmpty(supportedProtocols)) {
            return true;
        }

        try {
            Map<String, Object> cachedContext = DebugSessionCache.getInstance().get(state);
            if (cachedContext == null || cachedContext.isEmpty()) {
                return supportedProtocols.contains(OIDCDebugConstants.PROTOCOL_TYPE.toLowerCase(Locale.ENGLISH));
            }

            Object protocol = cachedContext.get(CONTEXT_KEY_PROTOCOL);
            if (protocol == null) {
                return supportedProtocols.contains(OIDCDebugConstants.PROTOCOL_TYPE.toLowerCase(Locale.ENGLISH));
            }

            return supportedProtocols.contains(protocol.toString().trim().toLowerCase(Locale.ENGLISH));
        } catch (Exception e) {
            LOG.debug("Unable to resolve cached debug protocol for state: " + state, e);
            return supportedProtocols.contains(OIDCDebugConstants.PROTOCOL_TYPE.toLowerCase(Locale.ENGLISH));
        }
    }

    private void processDebugFlowCallback(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String code = request.getParameter(DebugFrameworkConstants.OIDC_CODE_PARAM);
        String state = request.getParameter(DebugFrameworkConstants.OIDC_STATE_PARAM);
        String error = request.getParameter(DebugFrameworkConstants.OIDC_ERROR_PARAM);
        String sessionDataKey = request.getParameter(DebugFrameworkConstants.SESSION_DATA_KEY_PARAM);

        if (handleOAuthError(error, response)) {
            return;
        }

        AuthenticationContext context = retrieveOrCreateContext(code, state, sessionDataKey);
        if (context == null) {
            handleMissingContext(response);
            return;
        }

        setContextProperties(context, code, state, sessionDataKey);
        if (processor == null) {
            LOG.error("No suitable DebugProcessor found for OIDC callback");
            if (!response.isCommitted()) {
                String connectionId = extractConnectionId(context, request);
                String description = String.format(ErrorMessages.ERROR_CODE_EXECUTOR_NOT_FOUND.getDescription(),
                        connectionId != null ? connectionId : "unknown");
                sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        ErrorMessages.ERROR_CODE_EXECUTOR_NOT_FOUND.getCode(),
                        description);
            }
            return;
        }

        if (!response.isCommitted()) {
            processor.processCallback(request, response, context);
        }
    }

    private boolean handleOAuthError(String error, HttpServletResponse response) {

        if (error == null) {
            return false;
        }
        LOG.error("OAuth error in debug callback.");
        if (!response.isCommitted()) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "OAUTH_ERROR", "OAuth error occurred.");
        }
        return true;
    }

    private AuthenticationContext retrieveOrCreateContext(String code, String state, String sessionDataKey) {

        AuthenticationContext context = null;

        if (sessionDataKey != null) {
            context = retrieveDebugContextFromCache(sessionDataKey);
        }

        if (context == null && code != null && state != null) {
            context = createDebugContextForCallback(state);
        }

        return context;
    }

    private void handleMissingContext(HttpServletResponse response) {

        LOG.error("Cannot process debug callback: missing context and/or OAuth parameters");
        if (!response.isCommitted()) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                    "MISSING_CONTEXT", "Authentication context not found");
        }
    }

    private void setContextProperties(AuthenticationContext context, String code, String state, String sessionDataKey) {

        if (context == null) {
            LOG.warn("Cannot set context properties: context is null");
            return;
        }
        if (code != null) {
            context.setProperty(DebugFrameworkConstants.DEBUG_OIDC_CODE, code);
        }
        if (state != null) {
            context.setProperty(DebugFrameworkConstants.DEBUG_OIDC_STATE, state);
        }
        if (sessionDataKey != null) {
            context.setProperty(DebugFrameworkConstants.DEBUG_SESSION_DATA_KEY, sessionDataKey);
        }
        context.setProperty(DebugFrameworkConstants.DEBUG_CALLBACK_TIMESTAMP, System.currentTimeMillis());
        context.setProperty(DebugFrameworkConstants.DEBUG_CALLBACK_PROCESSED, DebugFrameworkConstants.TRUE);
    }

    private String extractConnectionId(AuthenticationContext context, HttpServletRequest request) {

        String connectionId = extractConnectionIdFromContext(context);
        return connectionId != null ? connectionId : extractConnectionIdFromRequest(request);
    }

    private String extractConnectionIdFromContext(AuthenticationContext context) {

        if (context == null) {
            return null;
        }
        return firstNonBlankString(
                context.getProperty(CONTEXT_KEY_CONNECTION_ID),
                context.getProperty(CONTEXT_KEY_RESOURCE_NAME),
                context.getProperty(DebugFrameworkConstants.DEBUG_CONNECTION_ID));
    }

    private String extractConnectionIdFromRequest(HttpServletRequest request) {

        if (request == null) {
            return null;
        }
        return firstNonBlankString(
                request.getParameter(REQUEST_KEY_CONNECTION_ID),
                request.getParameter(REQUEST_KEY_IDP_NAME));
    }

    private AuthenticationContext createDebugContextForCallback(String state) {

        AuthenticationContext context = new AuthenticationContext();

        String debugId = extractDebugIdFromState(state);
        if (debugId != null) {
            context.setContextIdentifier(DebugFrameworkConstants.DEBUG_PREFIX + debugId);
        } else {
            context.setContextIdentifier("debug-callback-" + System.currentTimeMillis());
        }

        context.setProperty(DebugFrameworkConstants.DEBUG_IDENTIFIER_PARAM, DebugFrameworkConstants.TRUE);
        context.setProperty(DebugFrameworkConstants.DEBUG_FLOW_TYPE, DebugFrameworkConstants.FLOW_TYPE_CALLBACK);
        context.setProperty(DebugFrameworkConstants.DEBUG_CONTEXT_CREATED, DebugFrameworkConstants.TRUE);
        context.setProperty(DebugFrameworkConstants.DEBUG_CREATION_TIMESTAMP, System.currentTimeMillis());

        cacheDebugContext(context);
        return context;
    }

    private AuthenticationContext retrieveDebugContextFromCache(String sessionDataKey) {

        try {
            AuthenticationContextCacheKey cacheKey = new AuthenticationContextCacheKey(sessionDataKey);
            AuthenticationContextCacheEntry cacheEntry = AuthenticationContextCache.getInstance()
                    .getValueFromCache(cacheKey);
            if (cacheEntry != null) {
                return cacheEntry.getContext();
            }
        } catch (RuntimeException e) {
            LOG.error("Error retrieving debug context from cache: " + e.getMessage(), e);
        }
        return null;
    }

    private void cacheDebugContext(AuthenticationContext context) {

        AuthenticationContextCacheKey cacheKey = new AuthenticationContextCacheKey(context.getContextIdentifier());
        AuthenticationContextCacheEntry cacheEntry = new AuthenticationContextCacheEntry(context);
        AuthenticationContextCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    private String extractDebugIdFromState(String state) {

        if (state == null || !state.startsWith(DebugFrameworkConstants.DEBUG_PREFIX)) {
            return null;
        }
        return state.substring(DebugFrameworkConstants.DEBUG_PREFIX.length());
    }

    private String firstNonBlankString(Object... values) {

        if (values == null) {
            return null;
        }

        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String stringValue = String.valueOf(value);
            if (StringUtils.isNotBlank(stringValue)) {
                return stringValue;
            }
        }
        return null;
    }

    private void sendErrorResponse(HttpServletResponse response, int status, String errorCode, String message) {

        try {
            response.setStatus(status);
            response.setContentType("application/json");
            Map<String, Object> errorResponse = new LinkedHashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", errorCode);
            errorResponse.put("message", message);
            OBJECT_MAPPER.writeValue(response.getWriter(), errorResponse);
        } catch (IOException e) {
            LOG.error("Error sending error response", e);
        }
    }

    private void sendIOErrorResponse(HttpServletResponse response) {

        sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "IO_ERROR", "Error processing debug callback");
    }
}
