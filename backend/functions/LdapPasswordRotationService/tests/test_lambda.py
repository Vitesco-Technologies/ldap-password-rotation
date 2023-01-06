import pytest
import ldap3
import boto3
import os
import json

from moto import mock_secretsmanager, mock_lambda, settings, mock_s3
from moto.core import DEFAULT_ACCOUNT_ID as ACCOUNT_ID
from botocore.exceptions import ClientError, ParamValidationError
from ldap_test import LdapServer

from src import lambda_function


@pytest.fixture(scope="function", autouse=True)
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "eu-central-1"


@pytest.fixture(scope="function", autouse=True)
def lambda_env():
    lambda_function.DICT_KEY_USERNAME = "username"
    lambda_function.DICT_KEY_PASSWORD = "password"
    lambda_function.DICT_KEY_USERPRINCIPALNAME = "userPrincipalName"
    lambda_function.DICT_KEY_BIND_DN = "bind_dn"
    lambda_function.SECRETS_MANAGER_REGION = "eu-central-1"
    lambda_function.EXCLUDE_CHARACTERS = "/'\"\\"


@pytest.fixture(scope="function", autouse=True)
def lambda_ldap_env(ldap_config):
    lambda_function.LDAP_SERVER_LIST = '["localhost"]'
    lambda_function.LDAP_SERVER_PORT = ldap_config['port']
    # Currently ldap_test doesn't support SSL
    lambda_function.LDAP_USE_SSL = False


@ pytest.fixture(scope="function")
def ldap_server():
    server = LdapServer()
    try:
        server.start()
    except Exception as e:
        raise e
    else:
        yield server
        server.stop()


@ pytest.fixture(scope="function")
def ldap_config(ldap_server, lambda_env):
    config = ldap_server.config
    config[lambda_function.DICT_KEY_USERNAME] = "testuser"
    config[lambda_function.DICT_KEY_USERPRINCIPALNAME] = config[lambda_function.DICT_KEY_BIND_DN]
    yield config


@ pytest.fixture(scope="function")
def secretsmanager(aws_credentials):
    with mock_secretsmanager():
        yield boto3.client("secretsmanager", region_name="eu-central-1")


@ pytest.fixture(scope="function")
def mock_secrets(secretsmanager, ldap_config):
    secret_dict = {
        lambda_function.DICT_KEY_USERNAME: ldap_config[lambda_function.DICT_KEY_USERNAME],
        lambda_function.DICT_KEY_PASSWORD: ldap_config[lambda_function.DICT_KEY_PASSWORD],
        lambda_function.DICT_KEY_USERPRINCIPALNAME: ldap_config[lambda_function.DICT_KEY_USERPRINCIPALNAME],
        lambda_function.DICT_KEY_BIND_DN: ldap_config[lambda_function.DICT_KEY_BIND_DN]
    }
    secret_dict_no_user = {
        lambda_function.DICT_KEY_PASSWORD: ldap_config['password']
    }
    secret_dict_no_pw = {
        lambda_function.DICT_KEY_USERNAME: ldap_config[lambda_function.DICT_KEY_USERNAME],
    }
    secret_string = ldap_config['password']
    secret_test = secretsmanager.create_secret(
        Name="ldap-test", SecretString=json.dumps(secret_dict))
    secret_test_no_user = secretsmanager.create_secret(
        Name="ldap-test-no-user", SecretString=json.dumps(secret_dict_no_user))
    secret_test_no_pw = secretsmanager.create_secret(
        Name="ldap-test-no-pw", SecretString=json.dumps(secret_dict_no_pw))
    secret_test_string = secretsmanager.create_secret(
        Name="ldap-test-string", SecretString="secret_string")

    yield secret_test, secret_test_no_user, secret_test_no_pw, secret_test_string


def test_ldap_config(ldap_config):
    # Checks if ldap_test settings change
    assert ldap_config == {
        'base': {
            'attributes': {'dc': 'example'},
            'dn': 'dc=example,dc=com',
            'objectclass': ['domain']
        },
        lambda_function.DICT_KEY_USERNAME: 'testuser',
        lambda_function.DICT_KEY_BIND_DN: 'cn=admin,dc=example,dc=com',
        lambda_function.DICT_KEY_USERPRINCIPALNAME: 'cn=admin,dc=example,dc=com',
        lambda_function.DICT_KEY_PASSWORD: 'password',
        'port': 10389
    }


def test_ldap_conn_wrong(ldap_server, ldap_config):
    srv = ldap3.Server(
        'localhost',
        port=int(lambda_function.LDAP_SERVER_PORT),
        use_ssl=lambda_function.LDAP_USE_SSL
    )
    conn_wrong = ldap3.Connection(
        srv,
        user=ldap_config['bind_dn'],
        password="wrong"
    )
    conn_wrong.bind()
    assert conn_wrong.result.get('result') != 0
    assert conn_wrong.result.get('description') == "invalidCredentials"


def test_ldap_conn(ldap_server, ldap_config):
    # Checks if ldap_test connection works
    srv = ldap3.Server(
        'localhost',
        port=int(lambda_function.LDAP_SERVER_PORT),
        use_ssl=lambda_function.LDAP_USE_SSL
    )
    conn = ldap3.Connection(
        srv,
        user=ldap_config['bind_dn'],
        password=ldap_config['password']
    )
    conn.bind()
    assert conn.result.get('result') == 0


def test_check_inputs(ldap_config):
    username, password, user_principal_name, bind_dn = lambda_function.check_inputs(
        ldap_config)

    assert username is ldap_config[lambda_function.DICT_KEY_USERNAME]
    assert password is ldap_config[lambda_function.DICT_KEY_PASSWORD]
    assert user_principal_name is ldap_config[lambda_function.DICT_KEY_USERPRINCIPALNAME]
    assert bind_dn is ldap_config[lambda_function.DICT_KEY_BIND_DN]


def test_check_inputs_invalid_password(ldap_config):
    dict_arg = ldap_config
    dict_arg['password'] = lambda_function.EXCLUDE_CHARACTERS
    with pytest.raises(ValueError) as e:
        lambda_function.check_inputs(dict_arg)
    assert "invalid character in password" in str(e.value).lower()


def test_check_inputs_invalid_user(ldap_config):
    dict_arg = ldap_config
    dict_arg[lambda_function.DICT_KEY_USERNAME] = lambda_function.EXCLUDE_CHARACTERS
    with pytest.raises(ValueError) as e:
        lambda_function.check_inputs(dict_arg)
    assert "invalid character in user" in str(e.value).lower()


def test_check_bind_user(ldap_config):
    dict_arg = ldap_config
    dict_arg.pop(lambda_function.DICT_KEY_USERPRINCIPALNAME, None)
    dict_arg.pop(lambda_function.DICT_KEY_BIND_DN, None)
    assert lambda_function.check_bind_user(
        dict_arg) == ldap_config[lambda_function.DICT_KEY_USERNAME]


def test_check_bind_userprincipal(ldap_config):
    dict_arg = ldap_config
    dict_arg.pop(lambda_function.DICT_KEY_BIND_DN, None)
    assert lambda_function.check_bind_user(
        dict_arg) == ldap_config[lambda_function.DICT_KEY_USERPRINCIPALNAME]


def test_check_bind_userdnl(ldap_config):
    dict_arg = ldap_config
    assert lambda_function.check_bind_user(
        dict_arg) == ldap_config[lambda_function.DICT_KEY_BIND_DN]


def test_check_bind_user_invalid(ldap_config):
    dict_arg = ldap_config
    dict_arg[lambda_function.DICT_KEY_USERNAME] = ""
    dict_arg[lambda_function.DICT_KEY_USERPRINCIPALNAME] = ""
    dict_arg[lambda_function.DICT_KEY_BIND_DN] = ""
    with pytest.raises(ValueError) as e:
        lambda_function.check_bind_user(dict_arg)
    assert "Invalid bind user" in str(e.value)


def test_ldap_connection(ldap_config):
    conn = lambda_function.ldap_connection(ldap_config)
    assert conn.result.get('result') == 0


def test_ldap_connection_wrong_pw(ldap_config):
    dict_arg = ldap_config
    dict_arg['password'] = "wrong"
    with pytest.raises(ValueError) as e:
        conn = lambda_function.ldap_connection(dict_arg)
    assert "ldap bind failed" in str(e.value).lower()


def test_get_secret_dict(secretsmanager, mock_secrets):
    secret_test, secret_test_no_user, secret_test_no_pw, secret_test_string = mock_secrets
    secret_dict = lambda_function.get_secret_dict(
        secrets_manager_client=secretsmanager,
        arn=secret_test["ARN"],
        stage="AWSCURRENT",
        token=None)
    secret_value = secretsmanager.get_secret_value(SecretId=secret_test["ARN"])
    assert secret_dict == json.loads(secret_value["SecretString"])

    with pytest.raises(KeyError) as e:
        secret_dict = lambda_function.get_secret_dict(
            secrets_manager_client=secretsmanager,
            arn=secret_test_no_user["ARN"],
            stage="AWSCURRENT",
            token=None)
    assert f"{lambda_function.DICT_KEY_USERNAME} key is missing".lower() in str(
        e.value).lower()

    with pytest.raises(KeyError) as e:
        secret_dict = lambda_function.get_secret_dict(
            secrets_manager_client=secretsmanager,
            arn=secret_test_no_pw["ARN"],
            stage="AWSCURRENT",
            token=None)
    assert f"{lambda_function.DICT_KEY_PASSWORD} key is missing".lower() in str(
        e.value).lower()

    with pytest.raises(ValueError) as e:
        secret_dict = lambda_function.get_secret_dict(
            secrets_manager_client=secretsmanager,
            arn=secret_test_string["ARN"],
            stage="AWSCURRENT",
            token=None)
    assert f"invalid secret format" in str(e.value).lower()
