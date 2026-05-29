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

import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor;
import org.wso2.carbon.identity.debug.framework.core.DebugContextProvider;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.core.DebugProcessor;
import org.wso2.carbon.identity.debug.framework.extension.DebugCallbackHandler;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugProcessor;
import org.wso2.carbon.identity.debug.idp.extension.IdpDebugTypeProvider;

/**
 * OIDC implementation of IdpDebugTypeProvider.
 */
public class OIDCDebugTypeProvider implements IdpDebugTypeProvider {

    private final DebugContextProvider contextProvider;
    private final DebugExecutor executor;
    private final IdpDebugProcessor processor;
    private final DebugCallbackHandler callbackHandler;

    public OIDCDebugTypeProvider() {

        this(OIDCDebugProcessor.createDefaultExecutor());
    }

    private OIDCDebugTypeProvider(OpenIDConnectExecutor oidcExecutor) {

        this(new OIDCContextProvider(oidcExecutor), new OIDCDebugExecutor(), new OIDCDebugProcessor(oidcExecutor));
    }

    public OIDCDebugTypeProvider(DebugContextProvider contextProvider, DebugExecutor executor,
                                 IdpDebugProcessor processor) {

        this.contextProvider = contextProvider;
        this.executor = executor;
        this.processor = processor;
        this.callbackHandler = new OIDCDebugCallbackHandler(processor);
    }

    @Override
    public boolean supportsAuthenticator(String authenticatorName) {

        return OIDCDebugConstants.OPENID_CONNECT.equals(authenticatorName)
                || OIDCDebugConstants.GOOGLE_OIDC.equals(authenticatorName)
                || OIDCDebugConstants.GITHUB_OIDC.equals(authenticatorName);
    }

    @Override
    public String getTypeIdentifier() {

        return OIDCDebugConstants.IDP_TYPE_IDENTIFIER;
    }

    @Override
    public DebugContextProvider getContextProvider() {

        return contextProvider;
    }

    @Override
    public DebugExecutor getExecutor() {

        return executor;
    }

    public DebugProcessor getProcessor() {

        return processor;
    }

    @Override
    public DebugCallbackHandler getCallbackHandler() {

        return callbackHandler;
    }
}
