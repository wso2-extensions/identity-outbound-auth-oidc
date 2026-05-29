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

import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkServerException;
import org.wso2.carbon.identity.debug.framework.extension.DebugCallbackHandler;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugProcessor;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Handles the OIDC authorization code callback for the debug flow.
 */
public class OIDCDebugCallbackHandler implements DebugCallbackHandler {

    private final IdpDebugProcessor processor;

    public OIDCDebugCallbackHandler(IdpDebugProcessor processor) {

        this.processor = processor;
    }

    @Override
    public boolean handleCallback(HttpServletRequest request, HttpServletResponse response,
            Map<String, Object> sessionData) throws DebugFrameworkServerException {

        DebugContext context = DebugContext.buildContextFromMap(sessionData);
        processor.processCallback(request, response, context);
        return true;
    }
}
