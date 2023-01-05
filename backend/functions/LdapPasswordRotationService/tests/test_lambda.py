import pytest
import ldap3
import boto3
import os
import json

from moto import mock_secretsmanager, mock_lambda, settings
from moto.core import DEFAULT_ACCOUNT_ID as ACCOUNT_ID
from botocore.exceptions import ClientError, ParamValidationError
from ldap_test import LdapServer

from src import lambda_function


@pytest.fixture(autouse=True)
def lambda_env(ldap_config):
    lambda_function.DICT_KEY_USERNAME = "bind_dn"
    lambda_function.DICT_KEY_PASSWORD = "password"
    lambda_function.DICT_KEY_USERPRINCIPALNAME = "userPrincipalName"
    lambda_function.DICT_KEY_BIND_DN = "ldap_default_bind_dn"
    lambda_function.SECRETS_MANAGER_REGION = "eu-central-1"
    lambda_function.EXCLUDE_CHARACTERS = "/'\"\\"
    lambda_function.LDAP_SERVER_LIST = '["localhost"]'
    lambda_function.LDAP_SERVER_PORT = ldap_config['port']
    # Currently ldap_test doesn't support SSL
    lambda_function.LDAP_USE_SSL = False


@pytest.fixture
def ldap_server():
    server = LdapServer()
    try:
        server.start()
    except Exception as e:
        raise e
    else:
        yield server
        server.stop()


@pytest.fixture
def ldap_config(ldap_server):
    config = ldap_server.config
    yield config


@pytest.fixture
def secretsmanager(ldap_server):
    secret_dict = {
        "username": ldap_config['bind_dn'],
        "password": ldap_config['password'],
        "userPrincipalName": ldap_config['bind_dn'],
        "ldap_default_bind_dn": ldap_config['bind_dn']
    }
    with mock_secretsmanager:
        conn = boto3.client("secretsmanager",
                            region_name=lambda_function.SECRETS_MANAGER_REGION)
        conn.create_secret(Name="ldap-test-password",
                           SecretString=json.loads(secret_dict))
        yield conn


def test_ldap_config(ldap_config):
    # Checks if ldap_test settings change
    assert ldap_config == {
        'base': {
            'attributes': {'dc': 'example'},
            'dn': 'dc=example,dc=com',
            'objectclass': ['domain']
        },
        'bind_dn': 'cn=admin,dc=example,dc=com',
        'password': 'password',
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

    assert username is ldap_config['bind_dn']
    assert password is ldap_config['password']
    assert user_principal_name is None
    assert bind_dn is None


def test_check_inputs_invalid_password(ldap_config):
    dict_arg = ldap_config
    dict_arg['password'] = lambda_function.EXCLUDE_CHARACTERS
    with pytest.raises(ValueError) as e:
        lambda_function.check_inputs(dict_arg)
    assert "Invalid character in password" in str(e.value)


def test_check_bind_user(ldap_config):
    dict_arg = ldap_config
    dict_arg[lambda_function.DICT_KEY_USERNAME] = "test_username"
    dict_arg.pop(lambda_function.DICT_KEY_USERPRINCIPALNAME, None)
    dict_arg.pop(lambda_function.DICT_KEY_BIND_DN, None)
    assert lambda_function.check_bind_user(dict_arg) == "test_username"


def test_check_bind_userprincipal(ldap_config):
    dict_arg = ldap_config
    dict_arg[lambda_function.DICT_KEY_USERNAME] = "test_username"
    dict_arg[lambda_function.DICT_KEY_USERPRINCIPALNAME] = "test_userprincipal"
    dict_arg.pop(lambda_function.DICT_KEY_BIND_DN, None)
    assert lambda_function.check_bind_user(dict_arg) == "test_userprincipal"


def test_check_bind_userdnl(ldap_config):
    dict_arg = ldap_config
    dict_arg[lambda_function.DICT_KEY_USERNAME] = "test_username"
    dict_arg[lambda_function.DICT_KEY_USERPRINCIPALNAME] = "test_userprincipal"
    dict_arg[lambda_function.DICT_KEY_BIND_DN] = "test_userdn"
    assert lambda_function.check_bind_user(dict_arg) == "test_userdn"


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
    assert "ldap bind failed" in str(e.value)
