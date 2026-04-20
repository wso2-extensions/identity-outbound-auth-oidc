/*
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

package org.wso2.carbon.identity.application.authenticator.oidc.debug.util;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.debug.framework.core.DebugDiagnosticsUtil;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;

import java.util.List;
import java.util.Map;

/**
 * Backward-compatible OIDC diagnostics bridge.
 */
public final class OIDCDebugDiagnosticsUtil {

    private OIDCDebugDiagnosticsUtil() {

    }

    /**
     * Records a diagnostic event for a debug context.
     *
     * @param context The debug context.
     * @param stage The diagnostic stage.
     * @param status The diagnostic status.
     * @param message The diagnostic message.
     */
    public static void recordEvent(DebugContext context, String stage, String status, String message) {

        DebugDiagnosticsUtil.recordEvent(context, stage, status, message);
    }

    /**
     * Records a diagnostic event with details for a debug context.
     *
     * @param context The debug context.
     * @param stage The diagnostic stage.
     * @param status The diagnostic status.
     * @param message The diagnostic message.
     * @param details Additional event details.
     */
    public static void recordEvent(DebugContext context, String stage, String status, String message,
            Map<String, Object> details) {

        DebugDiagnosticsUtil.recordEvent(context, stage, status, message, details);
    }

    /**
     * Records a diagnostic event for an authentication context.
     *
     * @param context The authentication context.
     * @param stage The diagnostic stage.
     * @param status The diagnostic status.
     * @param message The diagnostic message.
     */
    public static void recordEvent(AuthenticationContext context, String stage, String status, String message) {

        DebugDiagnosticsUtil.recordEvent(context, stage, status, message);
    }

    /**
     * Records a diagnostic event with details for an authentication context.
     *
     * @param context The authentication context.
     * @param stage The diagnostic stage.
     * @param status The diagnostic status.
     * @param message The diagnostic message.
     * @param details Additional event details.
     */
    public static void recordEvent(AuthenticationContext context, String stage, String status, String message,
            Map<String, Object> details) {

        DebugDiagnosticsUtil.recordEvent(context, stage, status, message, details);
    }

    /**
     * Returns diagnostics recorded in the debug context.
     *
     * @param context The debug context.
     * @return Diagnostic events.
     */
    public static List<Map<String, Object>> getDiagnostics(DebugContext context) {

        return DebugDiagnosticsUtil.getDiagnostics(context);
    }

    /**
     * Returns diagnostics recorded in the authentication context.
     *
     * @param context The authentication context.
     * @return Diagnostic events.
     */
    public static List<Map<String, Object>> getDiagnostics(AuthenticationContext context) {

        return DebugDiagnosticsUtil.getDiagnostics(context);
    }
}
