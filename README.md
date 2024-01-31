# LdapPasswordRotationService

![coverage](docs/img/coverage.svg)
[![Linux](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/linux.yml/badge.svg)](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/linux.yml)
[![macOs](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/macos.yml/badge.svg)](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/macos.yml)
[![Windows](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/windows.yml/badge.svg)](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/windows.yml)

![Python <=3.7](https://img.shields.io/badge/python-<=3.7-red.svg)

[![Python 3.8](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/python3.8.yml/badge.svg)](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/python3.8.yml)
[![Python 3.9](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/python3.9.yml/badge.svg)](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/python3.9.yml)
[![Python 3.10](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/python3.10.yml/badge.svg)](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/python3.10.yml)
[![Python 3.11](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/python3.11.yml/badge.svg)](https://github.com/DanielRDias/ldap-password-rotation/actions/workflows/python3.11.yml)

![Python >=3.12](https://img.shields.io/badge/python->=3.12-yellow.svg)

The LDAP Password Rotation Service offers a lambda function that integrates with AWS Secrets Manager and can update the user password to a new random password and update it in AWS Secrets Manager.

The AWS Lambda Function expects to receive a key/value (JSON) secret from AWS Secrets Manager, with a field with the user in which the password should be rotated and the current password. The username has to be the user principal name used to authenticate with LDAP.

## Quick Start

You'll need to have [Python (>=3.8)](https://www.python.org/) with [pipenv](https://github.com/pypa/pipenv), [NodeJS (>=16)](https://nodejs.org/) with [npm (>=8)](https://www.npmjs.com/) installed, and [AWS CLI](https://aws.amazon.com/cli/).

Optional: [Make](https://www.gnu.org/software/make/)

1. Make sure your default AWS credentials are configured to the environment where you want to deploy this project
2. Update the config file for the environment (located in the config folder) you want to deploy
   1. `config/serverless.dev.yml` for the development environment
3. Setup the project
   1. `make setup`
4. Deploy the project
   1. Run `make deploy stage=dev` to deploy with the `config/serverless.dev.yml` configurations
5. Create AWS Secrets Manager secret

```bash
aws secretsmanager create-secret \
    --name MyTestSecret \
    --description "My test secret created with the CLI." \
    --secret-string "{\"username\":\"example@example.com\",\"password\":\"EXAMPL3-P4ssw0rd\"}"
```

6. Create secret rotation

```bash
aws secretsmanager rotate-secret \
    --secret-id MyTestSecret \
    --rotation-lambda-arn arn:aws:lambda:eu-central-1:1234566789012:function:LdapPasswordRotation-dev-app \
    --rotation-rules "{\"ScheduleExpression\": \"rate(10 days)\"}"
```

7. Check that the secret has a rotation lambda configured
   1. `aws secretsmanager describe-secret --secret-id MyTestSecret`

8. Check that your secret password was rotated
   1. `aws secretsmanager get-secret-value --secret-id MyTestSecret`

## Make commands

We have a Makefile file with targets to:

- Setup the project `make setup`
- Test `make test` or `make test-log`
- Deploy `make deploy --stage=dev/qa/prod`
- Undeploy `make undeploy --stage=dev/qa/prod`

In case you don't have [Make](https://www.gnu.org/software/make/) you can still open our `Makefile` and run the commands manually.

### How to setup and test

1. Run `make setup` to build and setup your local environment.
2. Run `make requirements` to generate requirements.txt and requirements-dev.txt files.
3. Run `make test` to test or `make test-log` to test and print the execution logs.

### How to Deploy

1. Update the config file for the environment (located in the config folder) you want to deploy.
   1. `config/serverless.dev.yml` for the development environment
2. Run `make deploy stage=dev|qa|prod` to deploy to dev, qa or prod environment.

### FAQ

* The password isn't updating:
  * Go to AWS > Lambda > Functions > LdapPasswordRotation
    * Open Monitoring > "View CloudWatch logs"
      * Error Message: `check_inputs: Invalid character in`
        * Check if your current user or password has any of the `EXCLUDE_CHARACTERS`
        * Update the `EXCLUDE_CHARACTERS` rules to your needs
      * Error Message: `setSecret: Failed to update the password`
        * Some AD systems limit how often you can rotate the password. For example, you might not be able to change it more than once a day.
