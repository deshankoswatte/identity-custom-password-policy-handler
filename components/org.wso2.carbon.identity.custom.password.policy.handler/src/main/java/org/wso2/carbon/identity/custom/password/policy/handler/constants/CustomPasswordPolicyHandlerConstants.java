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

package org.wso2.carbon.identity.custom.password.policy.handler.constants;

public class CustomPasswordPolicyHandlerConstants {

    public static final String CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION =
            "customPasswordPolicyHandler.enableCommonPasswordRestriction";
    public static final String CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DISPLAYED_NAME =
            "Enable Common Password Restriction";
    public static final String CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DESCRIPTION =
            "Enable to restrict the use of common passwords.";
    public static final boolean CONFIG_ENABLE_COMMON_PASSWORD_RESTRICTION_DEFAULT_VALUE = false;

    public static final String CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION =
            "customPasswordPolicyHandler.enableClaimBasedPasswordRestriction";
    public static final String CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DISPLAYED_NAME =
            "Enable Claim Based Password Restriction";
    public static final String CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DESCRIPTION =
            "Enable to restrict the use of claim based passwords.";
    public static final boolean CONFIG_ENABLE_CLAIM_BASED_PASSWORD_RESTRICTION_DEFAULT_VALUE = false;
}
