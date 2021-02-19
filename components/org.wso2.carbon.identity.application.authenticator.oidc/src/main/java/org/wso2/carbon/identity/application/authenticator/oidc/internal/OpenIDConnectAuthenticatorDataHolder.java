/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.internal;

import org.wso2.carbon.identity.application.authentication.framework.ServerSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.user.core.service.RealmService;

public class OpenIDConnectAuthenticatorDataHolder {

    private static OpenIDConnectAuthenticatorDataHolder instance = new OpenIDConnectAuthenticatorDataHolder();

    private RealmService realmService;

    private ClaimMetadataManagementService claimMetadataManagementService;

    private ServerSessionManagementService serverSessionManagementService;

    private UserSessionManagementService userSessionManagementService;

    private OpenIDConnectAuthenticatorDataHolder() {

    }

    public static OpenIDConnectAuthenticatorDataHolder getInstance() {

        return instance;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public ClaimMetadataManagementService getClaimMetadataManagementService() {

        return claimMetadataManagementService;
    }

    public void setClaimMetadataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        this.claimMetadataManagementService = claimMetadataManagementService;
    }

    public ServerSessionManagementService getServerSessionManagementService() {

        return serverSessionManagementService;
    }

    public void setServerSessionManagementService(
            ServerSessionManagementService serverSessionManagementService) {

        this.serverSessionManagementService = serverSessionManagementService;
    }

    public UserSessionManagementService getUserSessionManagementService() {

        return userSessionManagementService;
    }

    public void setUserSessionManagementService(
            UserSessionManagementService userSessionManagementService) {

        this.userSessionManagementService = userSessionManagementService;
    }
}
