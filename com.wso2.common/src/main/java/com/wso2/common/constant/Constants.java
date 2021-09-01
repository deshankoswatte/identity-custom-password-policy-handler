package com.wso2.common.constant;

import org.wso2.carbon.utils.CarbonUtils;

/**
 * This class consists of the constants that are used throughout the password policy handler module.
 */
public class Constants {

    // Constants defining the configuration details for the common password restriction process.
    public static final String CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION =
            "customPasswordPolicyHandler.enableCommonPasswordRestriction";
    public static final String CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DISPLAYED_NAME =
            "Enable Common Password Restriction";
    public static final String CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DESCRIPTION =
            "Enable to restrict the use of common passwords.";
    public static final boolean CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DEFAULT_VALUE = false;

    // Constants defining the configuration details for the claim based password restriction process.
    public static final String CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION =
            "customPasswordPolicyHandler.enableClaimBasedPasswordRestriction";
    public static final String CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DISPLAYED_NAME =
            "Enable Claim Based Password Restriction";
    public static final String CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DESCRIPTION =
            "Enable to restrict the use of claim based passwords.";
    public static final boolean CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DEFAULT_VALUE = false;
    public static final String CONFIG_RESTRICTED_CLAIMS = "customPasswordPolicyHandler.restrictedClaims";
    public static final String CONFIG_RESTRICTED_CLAIMS_DISPLAYED_NAME = "Restricted Claims";
    public static final String CONFIG_RESTRICTED_CLAIMS_DESCRIPTION =
            "Claims which the values are restricted to be used as passwords.";

    // SQL Queries related to the custom password policy handler component.
    public static final String TABLE_NAME = "IDN_COMMON_PASSWORD_STORE";
    public static final String CREATE_COMMON_PASSWORD_STORE =
            "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                    "PASSWORD VARCHAR(255) NOT NULL," +
                    "PRIMARY KEY (PASSWORD));";
    public static final String INSERT_VALUES_TO_COMMON_PASSWORD_STORE =
            "REPLACE INTO " + TABLE_NAME + " (PASSWORD) VALUES (?);";
    public static final String SELECT_COMMON_PASSWORDS_LIKE =
            "SELECT PASSWORD FROM " + TABLE_NAME + " WHERE PASSWORD LIKE ?";
    public static final String DROP_COMMON_PASSWORD_STORE =
            "DROP TABLE IF EXISTS " + TABLE_NAME + ";";

    // Common passwords text file location related constants.
    public static final String PASSWORD_FILE_NAME = "commonpasswords.txt";
    public static final String PASSWORD_FILE_DIR = CarbonUtils.getCarbonHome()
            + "/repository/deployment/server/commonpasswords/";
    public static final String PASSWORD_FILE_PATH = PASSWORD_FILE_DIR + PASSWORD_FILE_NAME;

    /**
     * Enum class defined for the custom password policy handler component specific error messages.
     */
    public enum ErrorMessages {

        // General error codes.
        ERROR_CODE_USERNAME_OR_PASSWORD_NOT_FOUND(
                "40002", "The username or the updated credential could not be found."
        ),
        ERROR_READING_FROM_COMMON_PASSWORDS_FILE(
                "40002", "An error occurred while reading the common password data from the text file."
        ),
        ERROR_INITIALIZING_COMMON_PASSWORDS_REPOSITORY(
                "40002", "An error occurred while initializing the common password data repository."
        ),
        ERROR_ADDING_COMMON_PASSWORDS_TO_DB(
                "40002", "An error occurred while adding the common password data to the DB table."
        ),
        ERROR_REMOVING_COMMON_PASSWORDS_FROM_DB(
                "40002",
                "An error occurred while removing the common password repository data from the database."
        ),
        ERROR_EMPTY_USER_STORE_MANAGER(
                "40002",
                "The user store manager is empty."
        ),
        ERROR_RETRIEVING_CLAIM_URIS(
                "40002",
                "An error occurred while retrieving the claim uris."
        ),
        ERROR_RETRIEVING_USER_CLAIMS(
                "40002",
                "An error occurred while retrieving the user claims."
        ),
        // Error code enforced when the password either contains a common password or a user claim.
        ERROR_CODE_VALIDATING_COMMON_PASSWORD_POLICY(
                "40002",
                "The new password is vulnerable for security issues since it is a commonly used password. " +
                        "Please use another password instead."
        ),
        ERROR_CODE_VALIDATING_USER_ATTRIBUTE_PASSWORD_POLICY(
                "40002", "The new password is vulnerable for security issues since it contains user " +
                "attributes. Please use another password instead."
        );

        // Instance variables for the error code and message.
        private final String code;
        private final String message;

        // Constructor to instantiate an instance of the enum.
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        // Getter methods that provides access to instance variable values for other classes.
        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        // ErrorMessages class representation through a string.
        @Override
        public String toString() {

            return code + " - " + message;
        }
    }
}
