/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.oidc.LogoutException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.AnalyticsAttributes.SESSION_ID;
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.IDP_NAME;

public class SessionInfoDAO {

    private static final Log log = LogFactory.getLog(SessionInfoDAO.class);

    /**
     * Retrieve the session details of a given OIDC sid from the database.
     *
     * @param oidcSId Session Id of the OIDC Logout Request.
     * @return Map of session details.
     * @throws LogoutException If DB execution fails.
     */
    public Map<String, String> getSessionDetails(String oidcSId) throws LogoutException {

        final String query = "SELECT * FROM IDN_FED_AUTH_SESSION_MAPPING WHERE IDP_SESSION_ID = ?";

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, oidcSId);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                Map<String, String> sessionDetails = new HashMap<>();
                if (resultSet.next()) {
                    sessionDetails.put(SESSION_ID, resultSet.getString("SESSION_ID"));
                    sessionDetails.put(IDP_NAME, resultSet.getString("IDP_NAME"));
                }
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved session id: " + resultSet.getString("SESSION_ID") +
                            " for federated idp session id: " + oidcSId);
                }
                return sessionDetails;
            }
        } catch (SQLException e) {
            throw new LogoutException("Unable to retrieve session details from the database with OIDC sid: "
                    + oidcSId, e);
        }
    }
}
