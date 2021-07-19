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

import org.wso2.carbon.identity.custom.password.policy.handler.validator.PasswordValidator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A singleton class to restrict the use of common passwords.
 */
public class CommonPasswordValidator implements PasswordValidator {

    private List<String> commonPasswords = new ArrayList<>();
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
     */
    public void initializeData() {

        commonPasswords = Arrays.asList("123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
                "111111", "1234567", "dragon");
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

        return !commonPasswords.contains(credential);
    }
}
