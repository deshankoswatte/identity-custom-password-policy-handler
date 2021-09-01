package com.wso2.password.policy.handler.internal;

import com.wso2.password.policy.handler.PasswordPolicyHandler;
import com.wso2.password.policy.handler.validator.impl.DBBasedCommonPasswordValidator;
import com.wso2.password.policy.handler.validator.impl.FileBasedCommonPasswordValidator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;

/**
 * OSGi service component which registers the password policy event handler and sets the bundle context.
 */
@Component(
        name = "com.wso2.password.policy.handler.internal.WSO2PasswordPolicyHandlerMgtComponent",
        immediate = true)
public class WSO2PasswordPolicyHandlerMgtComponent {

    private static final Log log = LogFactory.getLog(WSO2PasswordPolicyHandlerMgtComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            WSO2PasswordPolicyHandlerMgtDataHolder.getInstance().setBundleContext(bundleContext);
            context.getBundleContext().registerService(AbstractEventHandler.class.getName(),
                    new PasswordPolicyHandler(), null);

            if (Boolean.parseBoolean(System.getProperty("enableDBBasedCommonPasswordValidator"))) {
                // Initialize the common password data DB repository.
                DBBasedCommonPasswordValidator.getInstance().initializeData();
            } else {
                // Initialize the common password data using a file as storage.
                FileBasedCommonPasswordValidator.getInstance().initializeData();
            }
            if (log.isDebugEnabled()) {
                log.debug("The password policy handler mgt component is enabled.");
            }
        } catch (Throwable throwable) {
            log.error("Error while activating the password policy handler mgt component.", throwable);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (Boolean.parseBoolean(System.getProperty("enableDBBasedCommonPasswordValidator"))) {
            try {
                // Destroy the common password data repository.
                DBBasedCommonPasswordValidator.getInstance().destroyData();
            } catch (Throwable throwable) {
                log.error("Error while deactivating the password policy handler mgt component.", throwable);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("The password policy handler mgt component is de-activated.");
        }
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {

        if (log.isDebugEnabled()) {
            log.debug("Setting Identity Governance Service.");
        }
        WSO2PasswordPolicyHandlerMgtDataHolder.getInstance().setIdentityGovernanceService(idpManager);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {

        if (log.isDebugEnabled()) {
            log.debug("UnSetting Identity Governance Service.");
        }
        WSO2PasswordPolicyHandlerMgtDataHolder.getInstance().setIdentityGovernanceService(null);
    }
}
