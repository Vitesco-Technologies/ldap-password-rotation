# LdapPasswordRotationService

![coverage](docs/img/coverage.svg)
[![Linux](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/linux.yml/badge.svg)](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/linux.yml)
[![macOs](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/macos.yml/badge.svg)](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/macos.yml)
[![Windows](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/windows.yml/badge.svg)](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/windows.yml)

![Python <3.9](https://img.shields.io/badge/python-<3.9-red.svg)

[![Python 3.9](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/python3.9.yml/badge.svg)](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/python3.9.yml)
[![Python 3.10](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/python3.10.yml/badge.svg)](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/python3.10.yml)
[![Python 3.11](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/python3.11.yml/badge.svg)](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/python3.11.yml)
[![Python 3.12](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/python3.12.yml/badge.svg)](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/python3.12.yml)
[![Python 3.13](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/python3.13.yml/badge.svg)](https://github.com/Vitesco-Technologies/ldap-password-rotation/actions/workflows/python3.13.yml)

![Python >3.13](https://img.shields.io/badge/python->3.13-yellow.svg)

The LDAP Password Rotation Service offers a lambda function that integrates with AWS Secrets Manager and can update the user password to a new random password and update it in AWS Secrets Manager.

The AWS Lambda Function expects to receive a key/value (JSON) secret from AWS Secrets Manager, with a field with the user in which the password should be rotated and the current password. The username has to be the user principal name used to authenticate with LDAP.

## Quick Start

You'll need to have [Python (>=3.9)](https://www.python.org/) with [uv](https://docs.astral.sh/uv/), [Bun](https://bun.sh/) installed, and [AWS CLI](https://aws.amazon.com/cli/).

Optional: [Make](https://www.gnu.org/software/make/)

1. Make sure your default AWS credentials are configured to the environment where you want to deploy this project
1. Update the config file for the environment (located in the config folder) you want to deploy
   1. `config/serverless.dev.yml` for the development environment
1. Setup the project
   1. `make setup`
   1. This creates the local Python environment with uv and installs the Serverless Framework dependencies with Bun.
1. Deploy the project
   1. Run `make deploy stage=dev` to deploy with the `config/serverless.dev.yml` configurations
1. Create AWS Secrets Manager secret

```bash
aws secretsmanager create-secret \
    --name MyTestSecret \
    --description "My test secret created with the CLI." \
    --secret-string "{\"username\":\"example@example.com\",\"password\":\"EXAMPL3-P4ssw0rd\"}"
```

1. Create secret rotation

```bash
aws secretsmanager rotate-secret \
    --secret-id MyTestSecret \
    --rotation-lambda-arn arn:aws:lambda:eu-central-1:1234566789012:function:LdapPasswordRotation-dev-app \
    --rotation-rules "{\"ScheduleExpression\": \"rate(10 days)\"}"
```

1. Check that the secret has a rotation lambda configured
   1. `aws secretsmanager describe-secret --secret-id MyTestSecret`

1. Check that your secret password was rotated
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
4. If you need to refresh the Python and Node lockfiles, run `make update`.

### How to Deploy

1. Update the config file for the environment (located in the config folder) you want to deploy.
   1. `config/serverless.dev.yml` for the development environment
2. Run `make deploy stage=dev|qa|prod` to deploy to dev, qa or prod environment.

### FAQ

- The password isn't updating: go to AWS > Lambda > Functions > LdapPasswordRotation and open Monitoring > "View CloudWatch logs".
- If the error message is `check_inputs: Invalid character in`, check whether your current user or password contains any of the `EXCLUDE_CHARACTERS` and update those rules to your needs.
- If the error message is `setSecret: Failed to update the password`, your AD system may limit how often you can rotate the password. For example, it might not allow more than one password change per day.
