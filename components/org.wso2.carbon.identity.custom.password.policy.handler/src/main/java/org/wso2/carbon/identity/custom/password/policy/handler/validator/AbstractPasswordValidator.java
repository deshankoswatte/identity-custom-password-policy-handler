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

package org.wso2.carbon.identity.custom.password.policy.handler.validator;

import org.wso2.carbon.identity.custom.password.policy.handler.exception.CustomPasswordPolicyHandlerException;

/**
 * PasswordValidator abstract class which helps to build several versions of it. This is an abstract class instead of
 * an interface since it helps to override and overload easily.
 */
public abstract class AbstractPasswordValidator {

    /**
     * Initialize the data required for the validator.
     *
     * @throws CustomPasswordPolicyHandlerException If an error occurs while initializing the required data.
     */
    public void initializeData() throws CustomPasswordPolicyHandlerException {

    }

    /**
     * Validates credentials based on custom criterias.
     *
     * @param credential The password of the user to be validated.
     * @return True if the validation is successful, false if else.
     */
    public abstract boolean validateCredentials(String credential);

}
