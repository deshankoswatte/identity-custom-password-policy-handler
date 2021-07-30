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

package org.wso2.carbon.identity.custom.password.policy.handler.constants;

import org.wso2.carbon.utils.CarbonUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * This class consists of the constants that are used throughout the custom password policy handler component.
 */
public class CustomPasswordPolicyHandlerConstants {

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
    public static final List<String> CONFIG_RESTRICTED_CLAIMS_DEFAULT_VALUE = new ArrayList<>();

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
            + "/repository/deployment/server/commonpasswords";
    public static final String PASSWORD_FILE_PATH = PASSWORD_FILE_DIR + "/" + PASSWORD_FILE_NAME;

    /**
     * Enum class defined for the custom password policy handler component specific error messages.
     */
    public enum ErrorMessages {

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
