package com.wso2.custom.identity.password.policy.handler.validator.impl;

import com.wso2.custom.identity.password.policy.handler.validator.AbstractPasswordValidator;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.List;
import java.util.Map;

/**
 * A singleton class to restrict the use of claim based passwords.
 */
public class ClaimBasedPasswordValidator extends AbstractPasswordValidator {

    private Map<String, String> userClaims;
    private List<String> restrictedClaims;
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
     * @param eventProperties  Properties belonging to the triggered event.
     * @param restrictedClaims Claims which the values are restricted to be used as passwords.
     * @param userName         Username of the user.
     * @throws IdentityEventException If there is a problem while loading claims.
     */
    public void initializeData(Map<String, Object> eventProperties, List<String> restrictedClaims, String userName)
            throws IdentityEventException {

        this.restrictedClaims = restrictedClaims;
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
            if (restrictedClaims.contains(entry.getKey()) &&
                    (credential.contains(entry.getValue()) || (entry.getValue()).contains(credential))) {
                return false;
            }
        }
        return true;
    }
}