package com.wso2.password.policy.handler.validator.impl;

import com.wso2.common.constant.Constants;
import com.wso2.common.exception.WSO2Exception;
import com.wso2.password.policy.handler.validator.AbstractPasswordValidator;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A singleton class to restrict the use of claim based passwords.
 */
public class ClaimBasedPasswordValidator extends AbstractPasswordValidator {

    private static final Log log = LogFactory.getLog(ClaimBasedPasswordValidator.class);
    private Map<String, String> userClaims;
    private List<String> restrictedClaims;
    private static final ClaimBasedPasswordValidator claimBasedPasswordValidator = new ClaimBasedPasswordValidator();

    /**
     * Private constructor so this class cannot be instantiated by other classes.
     */
    private ClaimBasedPasswordValidator() {

        userClaims = new HashMap<>();
        restrictedClaims = new ArrayList<>();
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
     * @param eventProperties  Properties belonging to the triggered event.
     * @param restrictedClaims Claims which the values are restricted to be used as passwords.
     * @param userName         Username of the user.
     * @throws WSO2Exception If there is a problem while loading claims or if the user store manager is null.
     */
    public void initializeData(Map<String, Object> eventProperties, List<String> restrictedClaims, String userName)
            throws WSO2Exception {

        this.restrictedClaims = restrictedClaims;
        UserStoreManager userStoreManager = eventProperties.get(
                IdentityEventConstants.EventProperty.USER_STORE_MANAGER) == null ? null :
                (UserStoreManager) eventProperties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        if (userStoreManager == null) {
            throw new WSO2Exception(
                    Constants.ErrorMessages.ERROR_EMPTY_USER_STORE_MANAGER.getCode(),
                    Constants.ErrorMessages.ERROR_EMPTY_USER_STORE_MANAGER.getMessage()
            );
        }

        String[] currentClaims;
        try {
            currentClaims = userStoreManager.getClaimManager().getAllClaimUris();
        } catch (UserStoreException exception) {
            throw new WSO2Exception(
                    Constants.ErrorMessages.ERROR_RETRIEVING_CLAIM_URIS.getCode(),
                    Constants.ErrorMessages.ERROR_RETRIEVING_CLAIM_URIS.getMessage(),
                    exception
            );
        }

        try {
            userClaims = eventProperties.get(IdentityEventConstants.EventProperty.USER_CLAIMS) == null ?
                    userStoreManager.getUserClaimValues(userName, currentClaims, "default") :
                    (Map<String, String>) eventProperties.get(IdentityEventConstants.EventProperty.USER_CLAIMS);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new WSO2Exception(
                    Constants.ErrorMessages.ERROR_RETRIEVING_USER_CLAIMS.getCode(),
                    Constants.ErrorMessages.ERROR_RETRIEVING_USER_CLAIMS.getMessage(),
                    e
            );
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
            String processedEntryValue = StringUtils.deleteWhitespace(entry.getValue().toLowerCase(Locale.ROOT));
            if (restrictedClaims.contains(entry.getKey()) &&
                    (credential.contains(processedEntryValue) || processedEntryValue.contains(credential))) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("There is a match between the credential: %s and claim value: %s.",
                            credential, processedEntryValue));
                }
                return false;
            }
        }
        return true;
    }
}
