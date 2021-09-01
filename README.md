# identity-custom-password-policy-handler

A custom event handler to restrict the use of common passwords and claim value based passwords.

## Prepare

### WSO2 Identity Server

Find and open the `deployment.toml` file located at `<IS_HOME>/repository/conf/` and append the following lines to
register the event handler, and it's subscriptions.

```
[[event_handler]]
name= "customPasswordPolicyHandler"
subscriptions =["PRE_UPDATE_CREDENTIAL", "PRE_UPDATE_CREDENTIAL_BY_ADMIN", "PRE_ADD_USER"]
[event_handler.properties]
enableCommonPasswordRestriction = true
enableClaimBasedPasswordRestriction = true
restrictedClaims = ["http://wso2.org/claims/username", "http://wso2.org/claims/fullname", ...]
```

### Clone and Build

Clone and build the project by executing the following commands sequentially:

```
git clone https://github.com/deshankoswatte/identity-custom-password-policy-handler.git
mvn clean install
```

### Deploy

1. After a successfully building the project, copy
   the `com.wso2.password.policy.handler-1.0.0-SNAPSHOT.jar`
   artifact from the target folder and paste it inside `<IS HOME>/repository/components/dropins` folder.
2. Then, copy the `commonpasswords.txt` file from `target/classes` and paste it
   in `<IS HOME>/repository/deployment/server/commonpasswords`
   (Note: You should create the directory `commonpasswords` if it does not exist).

You can add the following to the `<IS HOME>/bin/wso2server.sh` based on your requirement **(if you want to use the
DB-based common password validator only)**:

- `-DenableDBBasedCommonPasswordValidator=true \` - If you want to activate the DB-based common password validator.
- `-DenableCustomPasswordInsert=true \` - If you have inserted new data to the `commonpasswords.txt` file.
- `-DenableCustomPasswordDelete=true \` - If you want to drop the common password repository on component deactivation.

## Run

Start your WSO2 Identity Server by executing the command `sh wso2server.sh` from your `<IS HOME>/bin` folder.

## Test

### Scenario Reproduction Steps

1. Create a user/Update a user's password with a common password such as `1234` or a claim related password such as the
   username itself.
2. The user will get a prompt saying that the password contains security vulnerabilities hence requiring to use another
   password instead.

### Tested Environment Details

```
Operating System - Ubuntu 20.04
Java Version - 1.8
Identity Server Versions - IS-5.11.0
```