/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.oidc.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.OAuth2ContextProvider;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.OAuth2Executer;
import org.wso2.carbon.identity.debug.framework.core.DebugContextProvider;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;

/**
 * OIDC Authenticator component for registering debug services.
 * Note: Debug request coordination is now handled by the consolidated
 * DebugRequestCoordinator in the debug-framework module, which is
 * automatically discovered via reflection in CommonAuthenticationHandler.
 * OAuth2-specific logic is handled by OAuth2DebugProcessor.
 */
@Component(
        name = "org.wso2.carbon.identity.application.authenticator.oidc.internal.component",
        immediate = true
)
public class OIDCAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(OIDCAuthenticatorServiceComponent.class);

    /**
     * Activate the OIDC Authenticator Service Component.
     *
     * @param ctxt The component context.
     */
    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            // Register OAuth2Executer as DebugExecutor service
            OAuth2Executer oauth2Executor = new OAuth2Executer();
            ctxt.getBundleContext().registerService(
                new String[]{DebugExecutor.class.getName()}, 
                oauth2Executor, 
                null
            );
            if (log.isDebugEnabled()) {
                log.debug("OAuth2Executer registered as DebugExecutor service");
            }
            
            // Register OAuth2ContextProvider as DebugContextProvider service
            OAuth2ContextProvider oauth2ContextProvider = new OAuth2ContextProvider();
            ctxt.getBundleContext().registerService(
                new String[]{DebugContextProvider.class.getName()}, 
                oauth2ContextProvider, 
                null
            );
            if (log.isDebugEnabled()) {
                log.debug("OAuth2ContextProvider registered as DebugContextProvider service");
            }
            
            if (log.isDebugEnabled()) {
                log.debug("OIDC Authenticator component activated with debug services registered");
            }
        } catch (Exception e) {
            log.error("Error activating OIDC Authenticator service component: " + e.getMessage(), e);
        }
    }

    /**
     * Deactivate the OIDC Authenticator Service Component.
     *
     * @param ctxt The component context.
     */
    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("OIDC Authenticator component deactivated");
        }
    }
}
