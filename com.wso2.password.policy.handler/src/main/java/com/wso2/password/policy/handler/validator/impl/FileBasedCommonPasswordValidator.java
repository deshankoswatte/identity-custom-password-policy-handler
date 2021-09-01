package com.wso2.password.policy.handler.validator.impl;

import com.wso2.common.constant.Constants;
import com.wso2.common.exception.WSO2Exception;
import com.wso2.password.policy.handler.validator.AbstractPasswordValidator;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Locale;
import java.util.Vector;

/**
 * A singleton class to restrict the use of common passwords based on a file.
 */
public class FileBasedCommonPasswordValidator extends AbstractPasswordValidator {

    private static final Log log = LogFactory.getLog(FileBasedCommonPasswordValidator.class);
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
     * @throws WSO2Exception If there is an error while reading the common
     *                       passwords.
     */
    @Override
    public void initializeData() throws WSO2Exception {

        try {
            commonPasswordsList = Files.readAllLines(Paths.get(Constants.PASSWORD_FILE_PATH), StandardCharsets.UTF_8);
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
     * that reside in the commonPasswordsList.
     *
     * @param credential The password of the user.
     * @return True if the password does not match any record in the commonPasswordsList
     * , false if else.
     */
    @Override
    public boolean validateCredentials(String credential) {

        for (String commonPassword : commonPasswordsList) {
            String processedCommonPassword = StringUtils.deleteWhitespace(commonPassword.toLowerCase(Locale.ROOT));
            if (credential.contains(processedCommonPassword) || processedCommonPassword.contains(credential)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format(
                            "There is a match between the credential: %s and a common password: %s.",
                            credential, processedCommonPassword));
                }
                return false;
            }
        }
        return true;
    }
}
