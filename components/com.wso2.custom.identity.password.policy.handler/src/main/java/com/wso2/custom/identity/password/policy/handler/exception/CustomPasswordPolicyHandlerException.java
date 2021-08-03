package com.wso2.custom.identity.password.policy.handler.exception;

import org.wso2.carbon.identity.base.IdentityException;

public class CustomPasswordPolicyHandlerException extends IdentityException {

    public CustomPasswordPolicyHandlerException(String message, Throwable cause) {

        super(message, cause);
    }
}
