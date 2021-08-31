package com.wso2.password.policy.handler.util;

import com.wso2.common.constant.Constants;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.event.IdentityEventException;

/**
 * Exposes the utility functions required by the custom password policy handler component.
 */
public class PasswordPolicyHandlerUtils {

    private PasswordPolicyHandlerUtils() {

    }

    /**
     * Builds an IdentityEventException from a given error context.
     *
     * @param error The context of the error.
     * @param data  Data that is coupled with the error.
     * @return An IdentityEventException built from the given arguments.
     */
    public static IdentityEventException handleEventException(Constants.ErrorMessages error,
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
