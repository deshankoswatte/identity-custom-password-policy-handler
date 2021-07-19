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
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.Map;

/**
 * A singleton class to restrict the use of claim based passwords.
 */
public class ClaimBasedPasswordValidator implements PasswordValidator {

    private Map<String, String> userClaims;
    private static final ClaimBasedPasswordValidator claimBasedPasswordValidator = new ClaimBasedPasswordValidator();

    /**
     * Private constructor so this class cannot be instantiated by other classes.
     */
    private ClaimBasedPasswordValidator() {

    }

    /**
     * Retrieve the singleton instance of the ClaimBasedPasswordValidator.
     *
     * @return An instance of the ClaimBasedPasswordValidator.
     */
    public static ClaimBasedPasswordValidator getInstance() {

        return claimBasedPasswordValidator;
    }

    /**
     * Initialize the user claims with the provided arguments.
     *
     * @param eventProperties Properties belonging to the triggered event.
     * @param userName        Username of the user.
     * @throws IdentityEventException If there is a problem while loading claims.
     */
    public void initializeData(Map<String, Object> eventProperties, String userName) throws IdentityEventException {

        UserStoreManager userStoreManager = (UserStoreManager) eventProperties
                .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);

        String[] currentClaims;
        try {
            currentClaims = userStoreManager.getClaimManager().getAllClaimUris();
        } catch (UserStoreException e) {
            throw new IdentityEventException("Error while retrieving the claim uris.", e);
        }

        try {
            userClaims = eventProperties.get(IdentityEventConstants.EventProperty.USER_CLAIMS) == null ?
                    userStoreManager.getUserClaimValues(userName, currentClaims, "default") :
                    (Map<String, String>) eventProperties.get(IdentityEventConstants.EventProperty.USER_CLAIMS);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new IdentityEventException("Error while retrieving the claims bind to the user.", e);
        }
    }

    /**
     * Checks whether the user credential contains any of the claim values
     * that corresponds to the user.
     *
     * @param credential The password of the user.
     * @return True if the password does not match any record based on the user
     * claims, false if else.
     */
    @Override
    public boolean validateCredentials(String credential) {

        for (Map.Entry<String, String> entry : userClaims.entrySet()) {
            if (credential.contains(entry.getValue())) {
                return false;
            }
        }
        return true;
    }
}
