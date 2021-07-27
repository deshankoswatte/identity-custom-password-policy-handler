/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.custom.password.policy.handler.validator.impl;

import org.apache.commons.codec.digest.DigestUtils;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.custom.password.policy.handler.constants.CustomPasswordPolicyHandlerConstants;
import org.wso2.carbon.identity.custom.password.policy.handler.exception.CustomPasswordPolicyHandlerException;
import org.wso2.carbon.identity.custom.password.policy.handler.validator.PasswordValidator;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * A singleton class to restrict the use of common passwords.
 */
public class CommonPasswordValidator implements PasswordValidator {

    private static final CommonPasswordValidator commonPasswordValidator = new CommonPasswordValidator();

    /**
     * Private constructor so this class cannot be instantiated by other classes.
     */
    private CommonPasswordValidator() {

    }

    /**
     * Retrieve the singleton instance of the CommonPasswordValidator.
     *
     * @return An instance of the CommonPasswordValidator.
     */
    public static CommonPasswordValidator getInstance() {

        return commonPasswordValidator;
    }

    /**
     * Initialize the repository/database with the common password records.
     *
     * @throws CustomPasswordPolicyHandlerException If there is an error while creating a table to store the common
     *                                              passwords.
     */
    public void initializeData() throws CustomPasswordPolicyHandlerException {

        boolean tableExists = false;

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        ResultSet resultSet;
        try {
            resultSet = connection.getMetaData().getTables(
                    null, null, CustomPasswordPolicyHandlerConstants.TABLE_NAME, null
            );
            if (resultSet.next()) {
                tableExists = true;
            }
        } catch (SQLException exception) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new CustomPasswordPolicyHandlerException("An error occurred while initializing the common " +
                    "password data repository.", exception);
        }

        if (Boolean.parseBoolean(System.getProperty("enableCustomPasswordInsert")) || !tableExists) {
            PreparedStatement prepStmtCrt = null;

            try {
                // Create the SQL table if it does not exist.
                prepStmtCrt = connection.prepareStatement(
                        CustomPasswordPolicyHandlerConstants.CREATE_COMMON_PASSWORD_STORE
                );
                prepStmtCrt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                insertData();
            } catch (SQLException exception) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CustomPasswordPolicyHandlerException("An error occurred while initializing the common " +
                        "password data repository.", exception);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmtCrt);
            }
        }
    }

    /**
     * Extract the common passwords from the txt file and append them to the DB table.
     *
     * @throws CustomPasswordPolicyHandlerException If there is an error while inserting data to the DB table or if
     *                                              there is an error while reading the commonpasswords txt file.
     */
    private void insertData() throws CustomPasswordPolicyHandlerException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        try (PreparedStatement prepStmtIns = connection.prepareStatement(
                CustomPasswordPolicyHandlerConstants.INSERT_VALUES_TO_COMMON_PASSWORD_STORE)) {
            // Insert values and replace duplicates.
            String password;
            BufferedReader bufferedReader = new BufferedReader(new FileReader(
                    CustomPasswordPolicyHandlerConstants.PASSWORD_FILE_PATH
            ));
            while ((password = bufferedReader.readLine()) != null) {

                String passwordMd5 = DigestUtils.md5Hex(password).toUpperCase();
                prepStmtIns.setString(1, passwordMd5);
                prepStmtIns.addBatch();
            }
            prepStmtIns.executeBatch();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException exception) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new CustomPasswordPolicyHandlerException("An error occurred while adding the common " +
                    "password data to the DB table.", exception);
        } catch (IOException exception) {
            throw new CustomPasswordPolicyHandlerException("An error occurred while reading the common " +
                    "password data from the txt file.", exception);
        }
    }

    /**
     * Checks whether the user credential contains any of the common passwords
     * that reside in the repository.
     *
     * @param credential The password of the user.
     * @return True if the password does not match any record in the common password
     * repository, false if else.
     */
    @Override
    public boolean validateCredentials(String credential) {

        String credentialMd5 = DigestUtils.md5Hex(credential).toUpperCase();
        PreparedStatement prepStmtCheck = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        try {
            prepStmtCheck = connection.prepareStatement(
                    CustomPasswordPolicyHandlerConstants.SELECT_COMMON_PASSWORDS_LIKE
            );
            prepStmtCheck.setString(1, credentialMd5);

            ResultSet resultSet = prepStmtCheck.executeQuery();
            return !resultSet.next();
        } catch (SQLException exception) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            exception.printStackTrace();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmtCheck);
        }
        return true;
    }

    /**
     * Destroy the common password records and the DB table itself.
     *
     * @throws CustomPasswordPolicyHandlerException If an error occurs while dropping the DB table
     */
    public void destroyData() throws CustomPasswordPolicyHandlerException {

        if (Boolean.parseBoolean(System.getProperty("enableCustomPasswordDelete"))) {
            PreparedStatement prepStmtDes = null;
            Connection connection = IdentityDatabaseUtil.getDBConnection(true);
            try {
                prepStmtDes = connection.prepareStatement(
                        CustomPasswordPolicyHandlerConstants.DROP_COMMON_PASSWORD_STORE
                );
                prepStmtDes.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException exception) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new CustomPasswordPolicyHandlerException("An error occurred while removing the common " +
                        "password repository data from the database.", exception);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmtDes);
            }
        }
    }
}
