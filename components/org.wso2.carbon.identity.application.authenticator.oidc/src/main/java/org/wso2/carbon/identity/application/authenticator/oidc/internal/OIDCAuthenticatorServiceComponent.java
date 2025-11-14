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
            // Note: OAuth2-specific debug processing is handled by OAuth2DebugProcessor
            // which is called by the consolidated DebugRequestCoordinator from the framework.
            // The framework's DebugRequestCoordinator will be automatically discovered via reflection
            // in CommonAuthenticationHandler.handleDebugFlow() method.
            if (log.isDebugEnabled()) {
                log.debug("OIDC Authenticator component activated. Debug processing via framework.");
            }
        } catch (Exception e) {
            // Log any issues during activation, but don't fail the component
            if (log.isDebugEnabled()) {
                log.debug("OIDC Authenticator activation completed: " + e.getMessage());
            }
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
