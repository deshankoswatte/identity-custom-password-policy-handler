package com.wso2.password.policy.handler.validator.impl;

import com.wso2.common.constant.Constants;
import com.wso2.common.exception.WSO2Exception;
import com.wso2.password.policy.handler.util.PasswordPolicyHandlerUtils;
import com.wso2.password.policy.handler.validator.AbstractPasswordValidator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * A singleton class to restrict the use of common passwords based on a DB.
 */
public class DBBasedCommonPasswordValidator extends AbstractPasswordValidator {

    private static final Log log = LogFactory.getLog(DBBasedCommonPasswordValidator.class);
    private static final DBBasedCommonPasswordValidator dbBasedCommonPasswordValidator =
            new DBBasedCommonPasswordValidator();

    /**
     * Private constructor so this class cannot be instantiated by other classes.
     */
    private DBBasedCommonPasswordValidator() {

    }

    /**
     * Retrieve the singleton instance of the DBBasedCommonPasswordValidator.
     *
     * @return An instance of the DBBasedCommonPasswordValidator.
     */
    public static DBBasedCommonPasswordValidator getInstance() {

        return dbBasedCommonPasswordValidator;
    }

    /**
     * Initialize the repository/database with the common password records.
     *
     * @throws WSO2Exception If there is an error while creating a table to store the common
     *                       passwords or while adding common passwords to the table.
     */
    @Override
    public void initializeData() throws WSO2Exception {

        boolean tableExists = false;

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        ResultSet resultSet;
        try {
            resultSet = connection.getMetaData().getTables(
                    null, null, Constants.TABLE_NAME, null
            );
            if (resultSet.next()) {
                tableExists = true;
            }
        } catch (SQLException exception) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new WSO2Exception(
                    Constants.ErrorMessages.ERROR_INITIALIZING_COMMON_PASSWORDS_REPOSITORY.getCode(),
                    Constants.ErrorMessages.ERROR_INITIALIZING_COMMON_PASSWORDS_REPOSITORY.getMessage(),
                    exception
            );
        }

        if (Boolean.parseBoolean(System.getProperty("enableCustomPasswordInsert")) || !tableExists) {
            PreparedStatement prepStmtCrt = null;

            try {
                // Create the SQL table if it does not exist.
                prepStmtCrt = connection.prepareStatement(
                        Constants.CREATE_COMMON_PASSWORD_STORE
                );
                prepStmtCrt.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
                insertData();
            } catch (SQLException exception) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new WSO2Exception(
                        Constants.ErrorMessages.ERROR_INITIALIZING_COMMON_PASSWORDS_REPOSITORY.getCode(),
                        Constants.ErrorMessages.ERROR_INITIALIZING_COMMON_PASSWORDS_REPOSITORY.getMessage(),
                        exception
                );
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmtCrt);
            }
        }
    }

    /**
     * Extract the common passwords from the txt file and append them to the DB table.
     *
     * @throws WSO2Exception If there is an error while inserting data to the DB table or if
     *                       there is an error while reading the commonpasswords txt file.
     */
    private void insertData() throws WSO2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        try (PreparedStatement prepStmtIns = connection.prepareStatement(
                Constants.INSERT_VALUES_TO_COMMON_PASSWORD_STORE);
             BufferedReader bufferedReader = Files.newBufferedReader(Paths.get(
                     PasswordPolicyHandlerUtils.getCommonPasswordFilePath()), StandardCharsets.UTF_8)) {

            // Insert values and replace duplicates.
            String password;
            while ((password = bufferedReader.readLine()) != null) {

                prepStmtIns.setString(1, password);
                prepStmtIns.addBatch();
            }
            prepStmtIns.executeBatch();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException exception) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new WSO2Exception(
                    Constants.ErrorMessages.ERROR_ADDING_COMMON_PASSWORDS_TO_DB.getCode(),
                    Constants.ErrorMessages.ERROR_ADDING_COMMON_PASSWORDS_TO_DB.getMessage(),
                    exception
            );
        } catch (IOException exception) {
            throw new WSO2Exception(
                    Constants.ErrorMessages.ERROR_READING_FROM_COMMON_PASSWORDS_FILE.getCode(),
                    Constants.ErrorMessages.ERROR_READING_FROM_COMMON_PASSWORDS_FILE.getMessage(),
                    exception
            );
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

        PreparedStatement prepStmtCheck = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        ResultSet resultSet = null;

        try {
            prepStmtCheck = connection.prepareStatement(
                    Constants.SELECT_COMMON_PASSWORDS_LIKE
            );
            prepStmtCheck.setString(1, ("%" + credential + "%"));

            resultSet = prepStmtCheck.executeQuery();
            if (log.isDebugEnabled()) {
                log.debug(String.format("A match exists in the database: %b", !resultSet.next()));
            }

            return !resultSet.next();
        } catch (SQLException exception) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            log.error("An error occurred while validating the password against the common passwords repository.",
                    exception);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmtCheck);
            if (resultSet != null) {
                try {
                    resultSet.close();
                } catch (SQLException exception) {
                    log.error("An error occurred while closing the result set.", exception);
                }
            }
        }
        return true;
    }

    /**
     * Destroy the common password records and the DB table itself.
     *
     * @throws WSO2Exception If an error occurs while dropping the DB table
     */
    public void destroyData() throws WSO2Exception {

        if (Boolean.parseBoolean(System.getProperty("enableCustomPasswordDelete"))) {
            PreparedStatement prepStmtDes = null;
            Connection connection = IdentityDatabaseUtil.getDBConnection(true);
            try {
                prepStmtDes = connection.prepareStatement(
                        Constants.DROP_COMMON_PASSWORD_STORE
                );
                prepStmtDes.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException exception) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new WSO2Exception(
                        Constants.ErrorMessages.ERROR_REMOVING_COMMON_PASSWORDS_FROM_DB.getCode(),
                        Constants.ErrorMessages.ERROR_REMOVING_COMMON_PASSWORDS_FROM_DB.getMessage(),
                        exception
                );
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmtDes);
            }
        }
    }
}
