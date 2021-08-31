package com.wso2.password.policy.handler.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;

/**
 * Data holder for the custom password policy handler component.
 */
public class WSO2PasswordPolicyHandlerMgtDataHolder {

    private static final WSO2PasswordPolicyHandlerMgtDataHolder instance = new WSO2PasswordPolicyHandlerMgtDataHolder();
    private IdentityGovernanceService identityGovernanceService;
    private BundleContext bundleContext;

    private WSO2PasswordPolicyHandlerMgtDataHolder() {

    }

    public static WSO2PasswordPolicyHandlerMgtDataHolder getInstance() {

        return instance;
    }

    public IdentityGovernanceService getIdentityGovernanceService() {

        return identityGovernanceService;
    }

    public void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        this.identityGovernanceService = identityGovernanceService;
    }

    public BundleContext getBundleContext() {

        return bundleContext;
    }

    public void setBundleContext(BundleContext bundleContext) {

        this.bundleContext = bundleContext;
    }
}
