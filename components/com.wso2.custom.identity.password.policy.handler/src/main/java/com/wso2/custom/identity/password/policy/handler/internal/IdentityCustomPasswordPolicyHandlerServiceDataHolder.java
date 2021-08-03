package com.wso2.custom.identity.password.policy.handler.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;

/**
 * Data holder for the custom password policy handler component.
 */
public class IdentityCustomPasswordPolicyHandlerServiceDataHolder {

    private static final IdentityCustomPasswordPolicyHandlerServiceDataHolder instance = new IdentityCustomPasswordPolicyHandlerServiceDataHolder();
    private IdentityGovernanceService identityGovernanceService;
    private BundleContext bundleContext;

    private IdentityCustomPasswordPolicyHandlerServiceDataHolder() {

    }

    public static IdentityCustomPasswordPolicyHandlerServiceDataHolder getInstance() {

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
