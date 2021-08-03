package com.wso2.custom.identity.password.policy.handler.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.base.IdentityException;
import com.wso2.custom.identity.password.policy.handler.constants.CustomPasswordPolicyHandlerConstants;
import org.wso2.carbon.identity.event.IdentityEventException;

/**
 * Exposes the utility functions required by the custom password policy handler component.
 */
public class CustomPasswordPolicyHandlerUtils {

    /**
     * Builds an IdentityEventException from a given error context.
     *
     * @param error The context of the error.
     * @param data  Data that is coupled with the error.
     * @return An IdentityEventException built from the given arguments.
     */
    public static IdentityEventException handleEventException(CustomPasswordPolicyHandlerConstants.ErrorMessages error,
                                                              String data) {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }
        return IdentityException.error(IdentityEventException.class, error.getCode(), errorDescription);
    }
}
