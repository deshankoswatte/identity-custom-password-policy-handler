package com.wso2.custom.identity.password.policy.handler.validator.impl;

import com.wso2.custom.identity.password.policy.handler.validator.AbstractPasswordValidator;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import com.wso2.custom.identity.password.policy.handler.constants.CustomPasswordPolicyHandlerConstants;
import com.wso2.custom.identity.password.policy.handler.exception.CustomPasswordPolicyHandlerException;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * A singleton class to restrict the use of common passwords based on a DB.
 */
public class DBBasedCommonPasswordValidator extends AbstractPasswordValidator {

    private static final DBBasedCommonPasswordValidator dbBasedCommonPasswordValidator = new DBBasedCommonPasswordValidator();

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

                prepStmtIns.setString(1, password);
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

        PreparedStatement prepStmtCheck = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        try {
            prepStmtCheck = connection.prepareStatement(
                    CustomPasswordPolicyHandlerConstants.SELECT_COMMON_PASSWORDS_LIKE
            );
            prepStmtCheck.setString(1, ("%" + credential + "%"));

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
