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

import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.core.DebugContextProvider;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.core.DebugProcessor;
import org.wso2.carbon.identity.debug.framework.extension.DebugCallbackHandler;
import org.wso2.carbon.identity.debug.framework.extension.DebugProtocolProvider;

/**
 * OIDC implementation of DebugProtocolProvider.
 */
public class OIDCDebugProtocolProvider implements DebugProtocolProvider {

    private final DebugContextProvider contextProvider = new OIDCContextProvider();
    private final DebugExecutor executor = new OIDCDebugExecutor();
    private final DebugProcessor processor = new OIDCDebugProcessor();
    private final DebugCallbackHandler callbackHandler = new OIDCDebugCallbackHandler(processor,
            OIDCDebugConstants.PROTOCOL_TYPE, DebugFrameworkConstants.PROTOCOL_TYPE_GOOGLE,
            DebugFrameworkConstants.PROTOCOL_TYPE_GITHUB);

            
    /**
     * Returns the protocol type supported by this provider.
     *
     * @return Protocol type identifier.
     */
    @Override
    public String getProtocolType() {

        return OIDCDebugConstants.PROTOCOL_TYPE;
    }

    /**
     * Returns the context provider for OIDC debug operations.
     *
     * @return DebugContextProvider instance.
     */
    @Override
    public DebugContextProvider getContextProvider() {

        return contextProvider;
    }

    /**
     * Returns the executor for OIDC debug flow execution.
     *
     * @return DebugExecutor instance.
     */
    @Override
    public DebugExecutor getExecutor() {

        return executor;
    }

    /**
     * Returns the processor for OIDC debug result processing.
     *
     * @return DebugProcessor instance.
     */
    @Override
    public DebugProcessor getProcessor() {

        return processor;
    }

    /**
     * Returns the callback handler for OIDC debug operations.
     *
     * @return DebugCallbackHandler instance.
     */
    @Override
    public DebugCallbackHandler getCallbackHandler() {

        return callbackHandler;
    }

    /**
     * Checks if this provider supports the specified protocol type.
     *
     * @param protocolType The protocol type to check.
     * @return True if supported, false otherwise.
     */
    @Override
    public boolean supports(String protocolType) {

        return OIDCDebugConstants.PROTOCOL_TYPE.equalsIgnoreCase(protocolType);
    }
}
