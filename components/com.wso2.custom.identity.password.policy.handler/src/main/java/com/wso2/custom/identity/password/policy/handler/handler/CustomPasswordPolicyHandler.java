package com.wso2.custom.identity.password.policy.handler.handler;

import com.wso2.custom.identity.password.policy.handler.constants.CustomPasswordPolicyHandlerConstants;
import com.wso2.custom.identity.password.policy.handler.internal.IdentityCustomPasswordPolicyHandlerServiceDataHolder;
import com.wso2.custom.identity.password.policy.handler.util.CustomPasswordPolicyHandlerUtils;
import com.wso2.custom.identity.password.policy.handler.validator.impl.ClaimBasedPasswordValidator;
import com.wso2.custom.identity.password.policy.handler.validator.impl.DBBasedCommonPasswordValidator;
import com.wso2.custom.identity.password.policy.handler.validator.impl.FileBasedCommonPasswordValidator;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.ArrayList;
import java.util.Arrays;
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
        List<String> restrictedClaims = CustomPasswordPolicyHandlerConstants.CONFIG_RESTRICTED_CLAIMS_DEFAULT_VALUE;
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
            if (property.getName().equals(CustomPasswordPolicyHandlerConstants.CONFIG_RESTRICTED_CLAIMS)) {
                String value = property.getValue().replaceAll("[\\[\\]]", "");
                restrictedClaims = StringUtils.isBlank(value) ?
                        restrictedClaims : Arrays.asList(value.split(", "));
            }
        }

        if (isCommonPasswordRestrictionEnabled | isClaimBasedPasswordRestrictionEnabled) {

            String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
            Object rawCredential = eventProperties.get(IdentityEventConstants.EventProperty.CREDENTIAL);
            String credential = rawCredential instanceof StringBuffer ? rawCredential.toString() : (String) rawCredential;

            if (isCommonPasswordRestrictionEnabled) {
                if (Boolean.parseBoolean(System.getProperty("enableDBBasedCommonPasswordValidator"))) {
                    if (!DBBasedCommonPasswordValidator.getInstance().validateCredentials(credential)) {

                        throw CustomPasswordPolicyHandlerUtils.handleEventException(
                                CustomPasswordPolicyHandlerConstants.ErrorMessages.ERROR_CODE_VALIDATING_COMMON_PASSWORD_POLICY, null
                        );
                    }
                } else {
                    if (!FileBasedCommonPasswordValidator.getInstance().validateCredentials(credential)) {

                        throw CustomPasswordPolicyHandlerUtils.handleEventException(
                                CustomPasswordPolicyHandlerConstants.ErrorMessages.ERROR_CODE_VALIDATING_COMMON_PASSWORD_POLICY, null
                        );
                    }
                }
            }

            if (isClaimBasedPasswordRestrictionEnabled && restrictedClaims.size() > 0) {
                ClaimBasedPasswordValidator claimBasedPasswordValidator = ClaimBasedPasswordValidator.getInstance();
                claimBasedPasswordValidator.initializeData(eventProperties, restrictedClaims, userName);
                if (!claimBasedPasswordValidator.validateCredentials(credential)) {

                    throw CustomPasswordPolicyHandlerUtils.handleEventException(
                            CustomPasswordPolicyHandlerConstants.ErrorMessages.ERROR_CODE_VALIDATING_USER_ATTRIBUTE_PASSWORD_POLICY, null
                    );
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
        nameMapping.put(
                CustomPasswordPolicyHandlerConstants.CONFIG_RESTRICTED_CLAIMS,
                CustomPasswordPolicyHandlerConstants.CONFIG_RESTRICTED_CLAIMS_DISPLAYED_NAME
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
        descriptionMapping.put(
                CustomPasswordPolicyHandlerConstants.CONFIG_RESTRICTED_CLAIMS,
                CustomPasswordPolicyHandlerConstants.CONFIG_RESTRICTED_CLAIMS_DESCRIPTION
        );

        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION);
        properties.add(CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION);
        properties.add(CustomPasswordPolicyHandlerConstants.CONFIG_RESTRICTED_CLAIMS);

        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) {

        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION,
                configs.getModuleProperties().getProperty(
                        CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION));
        defaultProperties.put(CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION,
                configs.getModuleProperties().getProperty(
                        CustomPasswordPolicyHandlerConstants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION));
        defaultProperties.put(CustomPasswordPolicyHandlerConstants.CONFIG_RESTRICTED_CLAIMS,
                configs.getModuleProperties().getProperty(
                        CustomPasswordPolicyHandlerConstants.CONFIG_RESTRICTED_CLAIMS));

        Properties properties = new Properties();
        properties.putAll(defaultProperties);

        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) {

        return null;
    }
}
