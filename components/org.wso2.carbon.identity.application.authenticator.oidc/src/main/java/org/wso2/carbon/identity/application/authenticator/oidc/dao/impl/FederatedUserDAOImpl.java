/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.oidc.dao.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.oidc.LogoutServerException;
import org.wso2.carbon.identity.application.authenticator.oidc.dao.FederatedUserDAO;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Access the federated user information.
 */
public class FederatedUserDAOImpl implements FederatedUserDAO {

    private static final Log log = LogFactory.getLog(FederatedUserDAO.class);

    /**
     * Get the userId of the federated user by the username.
     *
     * @param username - username of the federated user.
     * @return userId of the federated user.
     * @throws LogoutServerException
     */
    public String getUserIdbyUsername(String username) throws LogoutServerException {

        final String query = "SELECT USER_ID FROM IDN_AUTH_USER WHERE USER_NAME = ?";
        String userId = null;

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, username);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    userId = resultSet.getString("USER_ID");
                }
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved user id : " + resultSet.getString("USER_ID") +
                            " for username : " + username);
                }
                return userId;
            }
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error getting user id for federated user by username", e);
            }
            throw new LogoutServerException("Error getting user id for federated user by username", e);
        }
    }
}
