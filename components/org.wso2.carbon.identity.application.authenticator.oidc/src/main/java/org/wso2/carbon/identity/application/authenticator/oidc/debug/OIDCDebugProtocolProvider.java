/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

import org.wso2.carbon.identity.debug.framework.extension.DebugContextProvider;
import org.wso2.carbon.identity.debug.framework.extension.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.extension.DebugProcessor;
import org.wso2.carbon.identity.debug.framework.extension.DebugProtocolProvider;

/**
 * OAuth2/OIDC implementation of DebugProtocolProvider.
 * 
 * Registered with OSGi by OpenIDConnectAuthenticatorServiceComponent to
 * advertise
 * the OIDC module's debug capabilities (context provider, executor, and
 * processor).
 * 
 * This approach eliminates the need for reflection-based class loading
 * (Class.forName) in DebugProtocolRouter. Instead, DebugProtocolRouter
 * discovers
 * providers dynamically via OSGi service lookups.
 * 
 * The debug-framework remains agnostic of specific protocol implementations;
 * it simply uses whatever DebugProtocolProvider services are registered at
 * runtime.
 */
public class OIDCDebugProtocolProvider implements DebugProtocolProvider {

    private final DebugContextProvider contextProvider = new OAuth2ContextProvider();
    private final DebugExecutor executor = new OAuth2DebugExecutor();
    private final DebugProcessor processor = new OAuth2DebugProcessor();

    /**
     * Gets the protocol type identifier.
     *
     * @return "OAuth2/OIDC".
     */
    @Override
    public String getProtocolType() {

        return OAuth2DebugConstants.PROTOCOL_TYPE;
    }

    /**
     * Gets the OAuth2/OIDC context provider.
     * The context provider resolves OAuth2/OIDC configuration and creates the debug
     * context.
     *
     * @return OAuth2ContextProvider instance.
     */
    @Override
    public DebugContextProvider getContextProvider() {

        return contextProvider;
    }

    /**
     * Gets the OAuth2/OIDC executor.
     * The executor generates the OAuth2 Authorization URL with PKCE support.
     *
     * @return OAuth2DebugExecutor instance.
     */
    @Override
    public DebugExecutor getExecutor() {

        return executor;
    }

    /**
     * Gets the OAuth2/OIDC processor.
     * The processor handles OAuth2 authorization code callbacks and token exchange.
     *
     * @return OAuth2DebugProcessor instance.
     */
    @Override
    public DebugProcessor getProcessor() {

        return processor;
    }

    /**
     * Checks if this provider supports the given protocol type.
     *
     * @param protocolType The protocol type to check.
     * @return true if protocolType is "OAuth2/OIDC" (case-insensitive), false
     *         otherwise.
     */
    @Override
    public boolean supports(String protocolType) {

        return OAuth2DebugConstants.PROTOCOL_TYPE.equalsIgnoreCase(protocolType);
    }
}
