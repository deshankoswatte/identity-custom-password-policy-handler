package com.wso2.password.policy.handler.validator;

import com.wso2.common.exception.WSO2Exception;

/**
 * PasswordValidator abstract class which helps to build several versions of it. This is an abstract class instead of
 * an interface since it helps to override and overload easily.
 */
public abstract class AbstractPasswordValidator {

    /**
     * Initialize the data required for the validator.
     *
     * @throws WSO2Exception If an error occurs while initializing the required data.
     */
    public void initializeData() throws WSO2Exception {

    }

    /**
     * Validates credentials based on custom criterias.
     *
     * @param credential The password of the user to be validated.
     * @return True if the validation is successful, false if else.
     */
    public abstract boolean validateCredentials(String credential);

}
