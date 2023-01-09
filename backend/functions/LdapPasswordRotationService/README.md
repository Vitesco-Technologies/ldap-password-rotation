# LdapPasswordRotationService

The LDAP Password Rotation Service offers a lambda function that integrates with AWS Secrets Manager and can update the user password to a new random password and update it in AWS Secrets Manager.

The AWS Lambda Function expects to receive a key/value (JSON) secret from AWS Secrets Manager, with a field with the user in which the password should be rotated and the current password. The username needs to use the "distinguishedName" format (cn=user,dc=example,dc=com)
You can find it by going to <https://ldapsearch.vitesco.io/>, searching for "all attributes," and checking the value of the `distinguishedName`.
The "username" doesn't need to be called "username" in the secrets manager. Instead, you can configure the function to check different field names for the username. Alternatively, you can specify multiple "username" fields with other formats, and the order that the function selects the username is the following:

1. DICT_KEY_BIND_DN
2. DICT_KEY_USERPRINCIPALNAME
3. DICT_KEY_USERNAME

## Requirments

You'll need to have Python with pipenv and NodeJS with npm installed.

Optional: [Make](https://www.gnu.org/software/make/)

We have a Makefile file with targets to:

- Setup the project `make setup`
- Test `make test` or `make test-log`
- Deploy `make deploy --stage=dev/qa/prod`
- Undeploy `make undeploy --stage=dev/qa/prod`

In case you don't have [Make](https://www.gnu.org/software/make/) you can still open our `Makefile` and run the commands manually.

### How to setup and test

1. Run `make setup` to build and setup your local environment
2. Run `make test` to test or `make test-log` to test and print the execution logs.

### How to Deploy

1. Update the config file for the environment (located in the config folder) you want to deploy.
   1. `config/serverless.dev.yml` for the development environment
2. Run `make deploys stage=dev|qa|prod` to deploy to dev, qa or prod environment.
