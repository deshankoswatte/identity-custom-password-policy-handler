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

import org.wso2.carbon.identity.custom.password.policy.handler.constants.CustomPasswordPolicyHandlerConstants;
import org.wso2.carbon.identity.custom.password.policy.handler.exception.CustomPasswordPolicyHandlerException;
import org.wso2.carbon.identity.custom.password.policy.handler.validator.AbstractPasswordValidator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Vector;

/**
 * A singleton class to restrict the use of common passwords based on a file.
 */
public class FileBasedCommonAbstractPasswordValidator extends AbstractPasswordValidator {

    private static final FileBasedCommonAbstractPasswordValidator fileBasedCommonPasswordValidator =
            new FileBasedCommonAbstractPasswordValidator();
    private List<String> commonPasswordsList = new Vector<>();

    /**
     * Private constructor so this class cannot be instantiated by other classes.
     */
    private FileBasedCommonAbstractPasswordValidator() {

    }

    /**
     * Retrieve the singleton instance of the FileBasedCommonPasswordValidator.
     *
     * @return An instance of the FileBasedCommonPasswordValidator.
     */
    public static FileBasedCommonAbstractPasswordValidator getInstance() {

        return fileBasedCommonPasswordValidator;
    }

    /**
     * Initialize the repository/database with the common password records.
     *
     * @throws CustomPasswordPolicyHandlerException If there is an error while reading the common
     *                                              passwords.
     */
    public void initializeData() throws CustomPasswordPolicyHandlerException {

        try {
            commonPasswordsList = Files.readAllLines(Paths.get(CustomPasswordPolicyHandlerConstants.PASSWORD_FILE_PATH),
                    StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new CustomPasswordPolicyHandlerException("An error occurred while reading the common " +
                    "password data from the txt file.", exception);
        }
    }

    /**
     * Checks whether the user credential contains any of the common passwords
     * that reside in the commonPasswordsList.
     *
     * @param credential The password of the user.
     * @return True if the password does not match any record in the commonPasswordsList
     * , false if else.
     */
    @Override
    public boolean validateCredentials(String credential) {

        for (String commonPassword : commonPasswordsList) {
            if (credential.contains(commonPassword) || commonPassword.contains(credential)) {
                return false;
            }
        }
        return true;
    }
}
