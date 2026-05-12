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
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugConstants;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants.ErrorMessages;
import org.wso2.carbon.identity.debug.framework.core.DebugProcessor;
import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkException;
import org.wso2.carbon.identity.debug.framework.extension.DebugCallbackHandler;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.store.DebugSessionStore;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OAuth-style debug callback handler owned by the OIDC protocol bundle.
 * This handler processes callbacks for OIDC and related protocols (e.g., Google, GitHub) during the debug flow.
 */
public class OIDCDebugCallbackHandler implements DebugCallbackHandler {

    private static final Log LOG = LogFactory.getLog(OIDCDebugCallbackHandler.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final DebugProcessor processor;
    private final Set<String> supportedProtocols;

    /**
     * Default constructor for {@link OIDCDebugCallbackHandler}.
     * Registers support for OIDC, Google, and GitHub protocols.
     * Google and GitHub currently share the same OAuth2/OIDC callback handling flow.
     *
     * @param processor {@link DebugProcessor} to be used for processing callbacks.
     */
    public OIDCDebugCallbackHandler(DebugProcessor processor) {

        this(processor, OIDCDebugConstants.PROTOCOL_TYPE, IdpDebugConstants.PROTOCOL_TYPE_GOOGLE,
                IdpDebugConstants.PROTOCOL_TYPE_GITHUB);
    }

    /**
     * Constructor for {@link OIDCDebugCallbackHandler} with specific supported protocols.
     *
     * @param processor          {@link DebugProcessor} to be used for processing callbacks.
     * @param supportedProtocols Array of protocol types supported by this handler.
     */
    public OIDCDebugCallbackHandler(DebugProcessor processor, String... supportedProtocols) {

        this.processor = processor;
        Set<String> normalizedProtocols = new HashSet<>();
        if (supportedProtocols != null) {
            Arrays.stream(supportedProtocols)
                    .filter(StringUtils::isNotBlank)
                    .map(protocol -> protocol.trim().toLowerCase(Locale.ENGLISH))
                    .forEach(normalizedProtocols::add);
        }
        this.supportedProtocols = Collections.unmodifiableSet(normalizedProtocols);
    }

    /**
     * Checks if this handler can process the given OIDC callback request.
     *
     * @param request {@link HttpServletRequest} representing the callback.
     * @return True if the request is a valid debug OIDC callback for a supported protocol.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        String state = request.getParameter(OIDCDebugConstants.OIDC_STATE_PARAM);
        String sessionDataKey = request.getParameter(DebugFrameworkConstants.SESSION_DATA_KEY_PARAM);

        boolean isDebugState = state != null && state.startsWith(DebugFrameworkConstants.DEBUG_PREFIX);

        if (!isDebugState) {
            return false;
        }

        return isSupportedProtocol(isDebugState ? state : sessionDataKey);
    }

    /**
     * Processes the OIDC debug callback.
     *
     * @param request  {@link HttpServletRequest} representing the callback.
     * @param response {@link HttpServletResponse} to send the response.
     * @return True if the callback was successfully handled, false otherwise.
     */
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
            // Return false to signal that the callback was not successfully handled,
            // allowing the framework to try other handlers or surface the error.
            return false;
        }

        return true;
    }

    private boolean isSupportedProtocol(String state) {

        if (CollectionUtils.isEmpty(supportedProtocols)) {
            return true;
        }

        try {
            Map<String, Object> cachedContext = DebugSessionStore.getInstance().get(state);
            if (cachedContext == null || cachedContext.isEmpty()) {
                return false;
            }

            Object protocol = cachedContext.get(OIDCDebugConstants.CONTEXT_PROTOCOL);
            if (protocol == null) {
                return false;
            }

            return supportedProtocols.contains(protocol.toString().trim().toLowerCase(Locale.ENGLISH));
        } catch (DebugFrameworkException e) {
            LOG.debug("Unable to resolve cached debug protocol for state: " + state, e);
            return false;
        }
    }

    private void processDebugFlowCallback(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String code = request.getParameter(OIDCDebugConstants.OIDC_CODE_PARAM);
        String state = request.getParameter(OIDCDebugConstants.OIDC_STATE_PARAM);
        String error = request.getParameter(OIDCDebugConstants.OIDC_ERROR_PARAM);
        String sessionDataKey = request.getParameter(DebugFrameworkConstants.SESSION_DATA_KEY_PARAM);

        if (handleOAuthError(error, response)) {
            return;
        }

        String identifier = (state != null && state.startsWith(DebugFrameworkConstants.DEBUG_PREFIX))
                ? state : sessionDataKey;
        DebugContext context = retrieveOrCreateContext(identifier);
        setContextProperties(context, code, state);
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

    private DebugContext retrieveOrCreateContext(String state) {

        try {
            Map<String, Object> cachedContextMap = DebugSessionStore.getInstance().get(state);
            if (cachedContextMap != null && !cachedContextMap.isEmpty()) {
                return DebugContext.buildFromMap(cachedContextMap);
            }
        } catch (DebugFrameworkException e) {
            LOG.debug("Error retrieving debug context from session store for state: " + state, e);
        }

        DebugContext context = new DebugContext();
        context.setProperty(DebugFrameworkConstants.DEBUG_IDENTIFIER_PARAM, DebugFrameworkConstants.TRUE_VALUE);
        context.setProperty(DebugFrameworkConstants.DEBUG_FLOW_TYPE, DebugFrameworkConstants.FLOW_TYPE_CALLBACK);
        context.setProperty(DebugFrameworkConstants.DEBUG_CONTEXT_CREATED, DebugFrameworkConstants.TRUE_VALUE);
        context.setProperty(DebugFrameworkConstants.DEBUG_CREATION_TIMESTAMP, System.currentTimeMillis());

        return context;
    }

    private void setContextProperties(DebugContext context, String code, String state) {

        if (StringUtils.isNotBlank(code)) {
            context.setProperty(DebugFrameworkConstants.DEBUG_PROTOCOL_CODE, code);
        }
        if (StringUtils.isNotBlank(state)) {
            context.setProperty(DebugFrameworkConstants.DEBUG_PROTOCOL_STATE, state);
        }
    }

    private String extractConnectionId(DebugContext context, HttpServletRequest request) {

        String connectionId = (String) context.getProperty("connectionId");
        if (StringUtils.isBlank(connectionId)) {
            connectionId = request.getParameter("idpId");
        }
        return connectionId;
    }

    private void sendErrorResponse(HttpServletResponse response, int status, String errorCode, String message) {

        try {
            response.setStatus(status);
            response.setContentType("application/json; charset=UTF-8");
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
