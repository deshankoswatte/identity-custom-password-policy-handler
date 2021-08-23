package com.wso2.custom.identity.password.policy.handler.validator.impl;

import com.wso2.custom.identity.password.policy.handler.constants.CustomPasswordPolicyHandlerConstants;
import com.wso2.custom.identity.password.policy.handler.exception.CustomPasswordPolicyHandlerException;
import com.wso2.custom.identity.password.policy.handler.validator.AbstractPasswordValidator;
import org.apache.commons.lang.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Vector;

/**
 * A singleton class to restrict the use of common passwords based on a file.
 */
public class FileBasedCommonPasswordValidator extends AbstractPasswordValidator {

    private static final FileBasedCommonPasswordValidator fileBasedCommonPasswordValidator =
            new FileBasedCommonPasswordValidator();
    private List<String> commonPasswordsList = new Vector<>();

    /**
     * Private constructor so this class cannot be instantiated by other classes.
     */
    private FileBasedCommonPasswordValidator() {

    }

    /**
     * Retrieve the singleton instance of the FileBasedCommonPasswordValidator.
     *
     * @return An instance of the FileBasedCommonPasswordValidator.
     */
    public static FileBasedCommonPasswordValidator getInstance() {

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
            String processedCommonPassword = StringUtils.deleteWhitespace(commonPassword.toLowerCase());
            if (credential.contains(processedCommonPassword) || processedCommonPassword.contains(credential)) {
                return false;
            }
        }
        return true;
    }
}
