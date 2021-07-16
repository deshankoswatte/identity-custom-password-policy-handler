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

package org.wso2.carbon.identity.custom.password.policy.handler.handler;

import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.custom.password.policy.handler.constants.CustomPasswordPolicyHandlerConstants;
import org.wso2.carbon.identity.custom.password.policy.handler.internal.IdentityCustomPasswordPolicyHandlerServiceDataHolder;
import org.wso2.carbon.identity.custom.password.policy.handler.validator.impl.CommonPasswordValidator;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class CustomPasswordPolicyHandler extends AbstractEventHandler implements IdentityConnectorConfig {

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();

        String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        String credential = (String) eventProperties.get(IdentityEventConstants.EventProperty.CREDENTIAL);

        Property[] identityProperties;
        try {
            identityProperties = IdentityCustomPasswordPolicyHandlerServiceDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving password policy properties.", e);
        }

        if (!CommonPasswordValidator.getInstance().validateCredentials(credential)) {

            throw new IdentityEventException("The new password is vulnerable for security issues. Please use another password.");
        }
    }

    @Override
    public void init(InitConfig configuration) throws IdentityRuntimeException {

        super.init(configuration);
        IdentityCustomPasswordPolicyHandlerServiceDataHolder.getInstance().getBundleContext().registerService
                (IdentityConnectorConfig.class.getName(), this, null);
    }

    @Override
    public String getName() {

        return "customPasswordPolicyHandler";
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return 50;
    }

    @Override
    public String getFriendlyName() {

        return "Password Validator";
    }

    @Override
    public String getCategory() {

        return "Custom Password Policy Handler";
    }

    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    @Override
    public int getOrder() {

        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(
                CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION,
                CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DISPLAYED_NAME
        );
        nameMapping.put(
                CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION,
                CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DISPLAYED_NAME
        );

        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(
                CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION,
                CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DESCRIPTION
        );
        descriptionMapping.put(
                CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION,
                CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DESCRIPTION
        );

        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION);
        properties.add(CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION);

        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION,
                configs.getModuleProperties().getProperty(
                        CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION));
        defaultProperties.put(CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION,
                configs.getModuleProperties().getProperty(
                        CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION));

        Properties properties = new Properties();
        properties.putAll(defaultProperties);

        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) throws IdentityGovernanceException {

        return null;
    }
}
