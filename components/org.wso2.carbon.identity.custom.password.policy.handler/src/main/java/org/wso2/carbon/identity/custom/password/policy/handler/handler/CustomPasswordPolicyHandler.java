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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.custom.password.policy.handler.constants.CustomPasswordPolicyHandlerConstants;
import org.wso2.carbon.identity.custom.password.policy.handler.internal.IdentityCustomPasswordPolicyHandlerServiceDataHolder;
import org.wso2.carbon.identity.custom.password.policy.handler.util.CustomPasswordPolicyHandlerUtils;
import org.wso2.carbon.identity.custom.password.policy.handler.validator.impl.CommonPasswordValidator;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class CustomPasswordPolicyHandler extends AbstractEventHandler implements IdentityConnectorConfig {

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();

        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        Property[] identityProperties;
        try {
            identityProperties = IdentityCustomPasswordPolicyHandlerServiceDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving password policy properties.", e);
        }

        boolean isCommonPasswordRestrictionEnabled =
                CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DEFAULT_VALUE;
        boolean isClaimBasedPasswordRestrictionEnabled =
                CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DEFAULT_VALUE;
        for (Property property : identityProperties) {
            if (property.getName().equals(
                    CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION)) {
                String value = property.getValue();
                isCommonPasswordRestrictionEnabled = StringUtils.isBlank(value) ? isCommonPasswordRestrictionEnabled :
                        Boolean.parseBoolean(value);
            }
            if (property.getName().equals(
                    CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION)) {
                String value = property.getValue();
                isClaimBasedPasswordRestrictionEnabled = StringUtils.isBlank(value) ?
                        isClaimBasedPasswordRestrictionEnabled : Boolean.parseBoolean(value);
            }
        }

        if (isCommonPasswordRestrictionEnabled | isClaimBasedPasswordRestrictionEnabled) {

            String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
            Object rawCredential = eventProperties.get(IdentityEventConstants.EventProperty.CREDENTIAL);
            String credential = rawCredential instanceof StringBuffer ? rawCredential.toString() : (String) rawCredential;

            if (isCommonPasswordRestrictionEnabled) {
                if (!CommonPasswordValidator.getInstance().validateCredentials(credential)) {

                    throw CustomPasswordPolicyHandlerUtils.handleEventException(
                            CustomPasswordPolicyHandlerConstants.ErrorMessages.ERROR_CODE_VALIDATING_PASSWORD_POLICY, null
                    );
                }
            }

            if (isClaimBasedPasswordRestrictionEnabled) {
                UserStoreManager userStoreManager = (UserStoreManager) eventProperties
                        .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);

                String[] currentClaims;
                try {
                    currentClaims = userStoreManager.getClaimManager().getAllClaimUris();
                } catch (UserStoreException e) {
                    throw new IdentityEventException("Error while retrieving the claim uris.", e);
                }

                Map<String, String> userClaims;
                try {
                    userClaims = userStoreManager.getUserClaimValues(userName, currentClaims,
                            "default");
                } catch (org.wso2.carbon.user.core.UserStoreException e) {
                    throw new IdentityEventException("Error while retrieving the claims bind to the user.", e);
                }

                for (Map.Entry<String, String> entry : userClaims.entrySet()) {
                    if (credential.contains(entry.getValue())) {
                        throw CustomPasswordPolicyHandlerUtils.handleEventException(
                                CustomPasswordPolicyHandlerConstants.ErrorMessages.ERROR_CODE_VALIDATING_PASSWORD_POLICY, null
                        );
                    }
                }
            }
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
