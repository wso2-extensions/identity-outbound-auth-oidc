/*
 *
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 *
 */

package org.wso2.carbon.identity.application.authenticator.oidc.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;

/**
 *
 */
public class OpenIDConnectAuthenticatorUtil {

    /**
     * This method returns the current federated authenticator name. If there is no external IdP, then the current
     * authenticator name is returned.
     *
     * @param context Authentication context.
     * @return Federated authenticator name.
     */
    public static String getFederatedAuthenticatorName(AuthenticationContext context) {

        if (context == null) {
            return StringUtils.EMPTY;
        }
        if (context.getExternalIdP() == null) {
            return context.getCurrentAuthenticator();
        }
        return context.getExternalIdP().getIdPName();
    }
}
