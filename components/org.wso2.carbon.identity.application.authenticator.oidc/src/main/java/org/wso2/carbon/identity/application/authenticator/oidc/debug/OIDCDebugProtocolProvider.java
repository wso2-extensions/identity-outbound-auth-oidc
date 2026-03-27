/*
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

import org.wso2.carbon.identity.debug.framework.core.DebugContextProvider;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.core.DebugProcessor;
import org.wso2.carbon.identity.debug.framework.extension.DebugCallbackHandler;
import org.wso2.carbon.identity.debug.framework.extension.DebugProtocolProvider;

/**
 * OIDC/OIDC implementation of DebugProtocolProvider.
 * 
 * Registered with OSGi by OpenIDConnectAuthenticatorServiceComponent to
 * advertise
 * the OIDC module's debug capabilities (context provider, executor, processor,
 * and callback handler).
 * 
 * The debug-framework remains agnostic of specific protocol implementations;
 * it simply uses whatever DebugProtocolProvider services are registered at
 * runtime.
 */
public class OIDCDebugProtocolProvider implements DebugProtocolProvider {

    private final DebugContextProvider contextProvider = new OIDCContextProvider();
    private final DebugExecutor executor = new OIDCDebugExecutor();
    private final DebugProcessor processor = new OIDCDebugProcessor();
    private final DebugCallbackHandler callbackHandler = new OIDCDebugCallbackHandler(processor);

    /**
     * Gets the protocol type identifier.
     *
     * @return "OIDC".
     */
    @Override
    public String getProtocolType() {

        return OIDCDebugConstants.PROTOCOL_TYPE;
    }

    /**
     * Gets the OIDC/OIDC context provider.
     * The context provider resolves OIDC/OIDC configuration and creates the debug
     * context.
     *
     * @return OIDCContextProvider instance.
     */
    @Override
    public DebugContextProvider getContextProvider() {

        return contextProvider;
    }

    /**
     * Gets the OIDC/OIDC executor.
     * The executor generates the OIDC Authorization URL with PKCE support.
     *
     * @return OIDCDebugExecutor instance.
     */
    @Override
    public DebugExecutor getExecutor() {

        return executor;
    }

    /**
     * Gets the OIDC/OIDC processor.
     * The processor handles OIDC authorization code callbacks and token exchange.
     *
     * @return OIDCDebugProcessor instance.
     */
    @Override
    public DebugProcessor getProcessor() {

        return processor;
    }

    /**
     * Gets the OIDC callback handler.
     *
     * @return OIDCDebugCallbackHandler instance.
     */
    @Override
    public DebugCallbackHandler getCallbackHandler() {

        return callbackHandler;
    }

    /**
     * Checks if this provider supports the given protocol type.
     *
     * @param protocolType The protocol type to check.
     * @return true if protocolType is "OIDC/OIDC" (case-insensitive), false
     *         otherwise.
     */
    @Override
    public boolean supports(String protocolType) {

        return OIDCDebugConstants.PROTOCOL_TYPE.equalsIgnoreCase(protocolType);
    }
}
