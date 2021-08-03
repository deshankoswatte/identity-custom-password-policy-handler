package com.wso2.custom.identity.password.policy.handler.internal;

import com.wso2.custom.identity.password.policy.handler.validator.impl.DBBasedCommonPasswordValidator;
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
import com.wso2.custom.identity.password.policy.handler.handler.CustomPasswordPolicyHandler;
import com.wso2.custom.identity.password.policy.handler.validator.impl.FileBasedCommonPasswordValidator;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;

/**
 * OSGi service component which registers the custom password policy event handler and sets the bundle context.
 */
@Component(
        name = "com.wso2.custom.identity.password.policy.handler.internal.IdentityCustomPasswordPolicyServiceComponent",
        immediate = true)
public class IdentityCustomPasswordPolicyHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(IdentityCustomPasswordPolicyHandlerServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            if (log.isDebugEnabled()) {
                log.debug("The custom password policy handler service component is enabled.");
            }
            BundleContext bundleContext = context.getBundleContext();
            IdentityCustomPasswordPolicyHandlerServiceDataHolder.getInstance().setBundleContext(bundleContext);

            CustomPasswordPolicyHandler handler = new CustomPasswordPolicyHandler();
            context.getBundleContext().registerService(AbstractEventHandler.class.getName(), handler, null);

            if (Boolean.parseBoolean(System.getProperty("enableDBBasedCommonPasswordValidator"))) {
                // Initialize the common password data DB repository.
                DBBasedCommonPasswordValidator.getInstance().initializeData();
            } else {
                // Initialize the common password data using a file as storage.
                FileBasedCommonPasswordValidator.getInstance().initializeData();
            }

        } catch (Throwable throwable) {
            log.error("Error while activating the custom password policy handler service component.", throwable);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (Boolean.parseBoolean(System.getProperty("enableDBBasedCommonPasswordValidator"))) {
            try {
                // Destroy the common password data repository.
                DBBasedCommonPasswordValidator.getInstance().destroyData();
            } catch (Throwable throwable) {
                log.error("Error while deactivating the custom password policy handler service component.", throwable);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("The custom password policy handler service component is de-activated.");
        }
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {

        IdentityCustomPasswordPolicyHandlerServiceDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {

        IdentityCustomPasswordPolicyHandlerServiceDataHolder.getInstance().setIdentityGovernanceService(idpManager);
    }
}
