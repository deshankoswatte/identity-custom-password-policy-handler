package com.wso2.password.policy.handler;

import com.wso2.common.constant.Constants;
import com.wso2.common.exception.WSO2Exception;
import com.wso2.password.policy.handler.internal.WSO2PasswordPolicyHandlerMgtDataHolder;
import com.wso2.password.policy.handler.util.PasswordPolicyHandlerUtils;
import com.wso2.password.policy.handler.validator.impl.ClaimBasedPasswordValidator;
import com.wso2.password.policy.handler.validator.impl.DBBasedCommonPasswordValidator;
import com.wso2.password.policy.handler.validator.impl.FileBasedCommonPasswordValidator;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.common.model.Property;
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
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * Handler which enforces the custom password policies on password update events.
 */
public class PasswordPolicyHandler extends AbstractEventHandler implements IdentityConnectorConfig {

    /**
     * Handles the password update event which is captured by this handler.
     *
     * @param event The password update event which has been captured by the handler.
     * @throws IdentityEventException If there is an error while handling the captured password update event.
     */
    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();

        String tenantDomain = eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN) == null ? null :
                (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        if (StringUtils.isBlank(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        Property[] identityProperties;
        try {
            identityProperties = WSO2PasswordPolicyHandlerMgtDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("An error occurred while retrieving password policy properties.", e);
        }

        boolean isCommonPasswordRestrictionEnabled =
                Constants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DEFAULT_VALUE;
        boolean isClaimBasedPasswordRestrictionEnabled =
                Constants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DEFAULT_VALUE;
        List<String> restrictedClaims = new ArrayList<>();
        for (Property property : identityProperties) {
            if (property.getName().equals(
                    Constants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION)) {
                String value = property.getValue();
                isCommonPasswordRestrictionEnabled = StringUtils.isBlank(value) ? isCommonPasswordRestrictionEnabled :
                        Boolean.parseBoolean(value);
            }
            if (property.getName().equals(
                    Constants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION)) {
                String value = property.getValue();
                isClaimBasedPasswordRestrictionEnabled = StringUtils.isBlank(value) ?
                        isClaimBasedPasswordRestrictionEnabled : Boolean.parseBoolean(value);
            }
            if (property.getName().equals(Constants.CONFIG_RESTRICTED_CLAIMS)) {
                String value = property.getValue().replaceAll("[\\[\\]]", "");
                restrictedClaims = StringUtils.isBlank(value) ?
                        restrictedClaims : Arrays.asList(value.split(", "));
            }
        }

        if (isCommonPasswordRestrictionEnabled || isClaimBasedPasswordRestrictionEnabled) {

            String userName = eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME) == null ? null :
                    (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
            Object rawCredential = eventProperties.get(IdentityEventConstants.EventProperty.CREDENTIAL);
            if (StringUtils.isBlank(userName) || rawCredential == null) {
                throw PasswordPolicyHandlerUtils.handleEventException(
                        Constants.ErrorMessages.ERROR_CODE_USERNAME_OR_PASSWORD_NOT_FOUND, null
                );
            }
            String credential = rawCredential instanceof StringBuffer ? rawCredential.toString() :
                    (String) rawCredential;
            credential = StringUtils.deleteWhitespace(credential.toLowerCase(Locale.ROOT));

            if (isCommonPasswordRestrictionEnabled) {
                if (Boolean.parseBoolean(System.getProperty("enableDBBasedCommonPasswordValidator"))) {
                    if (!DBBasedCommonPasswordValidator.getInstance().validateCredentials(credential)) {

                        throw PasswordPolicyHandlerUtils.handleEventException(
                                Constants.ErrorMessages.ERROR_CODE_VALIDATING_COMMON_PASSWORD_POLICY, null
                        );
                    }
                } else {
                    if (!FileBasedCommonPasswordValidator.getInstance().validateCredentials(credential)) {

                        throw PasswordPolicyHandlerUtils.handleEventException(
                                Constants.ErrorMessages.ERROR_CODE_VALIDATING_COMMON_PASSWORD_POLICY, null
                        );
                    }
                }
            }

            if (isClaimBasedPasswordRestrictionEnabled && restrictedClaims.isEmpty()) {
                ClaimBasedPasswordValidator claimBasedPasswordValidator = ClaimBasedPasswordValidator.getInstance();
                try {
                    claimBasedPasswordValidator.initializeData(eventProperties, restrictedClaims, userName);
                } catch (WSO2Exception e) {
                    throw new IdentityEventException(e.getErrorCode(), e.getMessage(), e);
                }
                if (!claimBasedPasswordValidator.validateCredentials(credential)) {

                    throw PasswordPolicyHandlerUtils.handleEventException(
                            Constants.ErrorMessages.ERROR_CODE_VALIDATING_USER_ATTRIBUTE_PASSWORD_POLICY, null
                    );
                }
            }
        }
    }

    /**
     * Initializes the configurations required for the event handler.
     *
     * @param configuration Initialization configuration.
     */
    @Override
    public void init(InitConfig configuration) {

        super.init(configuration);
        WSO2PasswordPolicyHandlerMgtDataHolder.getInstance().getBundleContext().registerService
                (IdentityConnectorConfig.class.getName(), this, null);
    }

    /**
     * Retrieves the name of the event handler.
     *
     * @return Name of the event handler.
     */
    @Override
    public String getName() {

        return "customPasswordPolicyHandler";
    }

    /**
     * Retrieves the priority of the event handler.
     *
     * @param messageContext The message context.
     * @return Priority of the event handler.
     */
    @Override
    public int getPriority(MessageContext messageContext) {

        return 50;
    }

    /**
     * Retrieves the friendly name of the connector configuration.
     *
     * @return Friendly name of the connector configuration.
     */
    @Override
    public String getFriendlyName() {

        return "Password Validator";
    }

    /**
     * Retrieves the category of the connector configuration.
     *
     * @return Category of the connector configuration.
     */
    @Override
    public String getCategory() {

        return "Custom Password Policy Handler";
    }

    /**
     * Retrieves the sub category of the connector configuration.
     *
     * @return Sub category of the connector configuration.
     */
    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    /**
     * Retrieves the order of the connector configuration.
     *
     * @return Order of the connector configuration.
     */
    @Override
    public int getOrder() {

        return 0;
    }

    /**
     * Retrieves the property name mappings of the connector configuration.
     *
     * @return Property name mappings of the connector configuration.
     */
    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(
                Constants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION,
                Constants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DISPLAYED_NAME
        );
        nameMapping.put(
                Constants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION,
                Constants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DISPLAYED_NAME
        );
        nameMapping.put(
                Constants.CONFIG_RESTRICTED_CLAIMS,
                Constants.CONFIG_RESTRICTED_CLAIMS_DISPLAYED_NAME
        );

        return nameMapping;
    }

    /**
     * Retrieves the property description mappings of the connector configuration.
     *
     * @return Property description mappings of the connector configuration.
     */
    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(
                Constants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION,
                Constants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DESCRIPTION
        );
        descriptionMapping.put(
                Constants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION,
                Constants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DESCRIPTION
        );
        descriptionMapping.put(
                Constants.CONFIG_RESTRICTED_CLAIMS,
                Constants.CONFIG_RESTRICTED_CLAIMS_DESCRIPTION
        );

        return descriptionMapping;
    }

    /**
     * Retrieves the property names of the connector configuration.
     *
     * @return Property names of the connector configuration.
     */
    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(Constants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION);
        properties.add(Constants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION);
        properties.add(Constants.CONFIG_RESTRICTED_CLAIMS);

        return properties.toArray(new String[0]);
    }

    /**
     * Retrieves the default property values of the connector configuration.
     *
     * @return Deafult property values of the connector configuration.
     */
    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) {

        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(Constants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION,
                configs.getModuleProperties().getProperty(
                        Constants.CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION));
        defaultProperties.put(Constants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION,
                configs.getModuleProperties().getProperty(
                        Constants.CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION));
        defaultProperties.put(Constants.CONFIG_RESTRICTED_CLAIMS,
                configs.getModuleProperties().getProperty(
                        Constants.CONFIG_RESTRICTED_CLAIMS));

        Properties properties = new Properties();
        properties.putAll(defaultProperties);

        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) {

        return null;
    }
}
