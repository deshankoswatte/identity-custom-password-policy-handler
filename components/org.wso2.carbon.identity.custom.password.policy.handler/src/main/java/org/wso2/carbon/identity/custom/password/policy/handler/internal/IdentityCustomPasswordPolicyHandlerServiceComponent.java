/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.custom.password.policy.handler.internal;

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
import org.wso2.carbon.identity.custom.password.policy.handler.handler.CustomPasswordPolicyHandler;
import org.wso2.carbon.identity.custom.password.policy.handler.validator.impl.CommonPasswordValidator;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;

/**
 * OSGi service component which registers the custom password policy event handler and sets the bundle context.
 */
@Component(
        name = "org.wso2.carbon.identity.custom.password.policy.handler.internal.IdentityCustomPasswordPolicyServiceComponent",
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

            // Initialize the common password data repository.
            CommonPasswordValidator.getInstance().initializeData();
        } catch (Exception e) {
            log.error("Error while activating the custom password policy handler service component.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

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
