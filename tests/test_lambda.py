import json
import logging
import os
from uuid import uuid4

import boto3
import ldap3
import mock
import pytest
from moto import mock_lambda, mock_secretsmanager
from src import lambda_function

from .utilities import lambda_util
from .utilities.ldap_test import LdapServer

_region = "eu-central-1"

# server is defined as global to allow us to update it when we mock
# ldap3.extend.microsoft.modifyPassword.ad_modify_password with mock_ad_modify_password
_server = LdapServer()

logger = logging.getLogger()
logger.setLevel(logging.INFO)

############
# fixtures #
############


@pytest.fixture(scope="function", autouse=True)
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = _region


@pytest.fixture(scope="function", autouse=True)
def lambda_env():
    lambda_function.SECRETS_MANAGER_KEY_USERNAME = "bind_dn"
    lambda_function.SECRETS_MANAGER_KEY_PASSWORD = "password"
    lambda_function.SECRETS_MANAGER_REGION = _region
    lambda_function.EXCLUDE_CHARACTERS = "/'\"\\"
    lambda_function.LDAP_BASE_DN = "dc=example,dc=com"
    lambda_function.LDAP_USER_AUTH_ATTRIBUTE = "userPrincipalName"
    lambda_function.SECRETS_MANAGER_KEY_DN = "ldap_bind_dn"


@pytest.fixture(scope="function", autouse=True)
def lambda_ldap_env(ldap_config):
    lambda_function.LDAP_SERVER_LIST = '["localhost"]'
    lambda_function.LDAP_SERVER_PORT = ldap_config["port"]
    # Currently ldap_test doesn't support SSL
    lambda_function.LDAP_USE_SSL = False


@pytest.fixture(scope="function")
def ldap_server(config=None):
    if config is None:
        config = {
            "port": 10389,
            "bind_dn": "cn=admin,dc=example,dc=com",
            "password": "password",
            "base": {
                "attributes": {"dc": "example"},
                "dn": "dc=example,dc=com",
                "objectclass": ["domain"],
            },
            "entries": [
                {
                    "objectclass": "domain",
                    "dn": "dc=users,dc=example,dc=com",
                    "attributes": {"dc": "users"},
                },
                {
                    "objectclass": "organization",
                    "dn": "o=foocompany,dc=users,dc=example,dc=com",
                    "attributes": {"o": "foocompany"},
                },
                {
                    "objectclass": "user",
                    "dn": "cn=users,dc=example,dc=com",
                    "attributes": {
                        "o": "foocompany",
                        "userPrincipalName": "cn=admin,dc=example,dc=com",
                    },
                },
            ],
        }
    global _server
    _server = LdapServer(config)
    _server.start()
    yield _server
    _server.stop()


@pytest.fixture(scope="function")
def ldap_config(ldap_server, lambda_env):
    config = ldap_server.config
    yield config


@pytest.fixture(scope="function")
def secretsmanager(aws_credentials):
    with mock_secretsmanager():
        yield boto3.client("secretsmanager", region_name=_region)


@pytest.fixture(scope="function")
def lambda_conn(aws_credentials):
    with mock_lambda():
        yield boto3.client("lambda", region_name=_region)


@pytest.fixture(scope="function")
def lambda_func(lambda_conn):
    func = lambda_conn.create_function(
        FunctionName="testFunction",
        Runtime="python3.9",
        Role=lambda_util.get_role_name(),
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": lambda_util.get_lambda_zip_file()},
        Description="Secret rotator",
        Timeout=3,
        MemorySize=128,
        Publish=True,
    )
    yield func


@pytest.fixture(scope="function")
def mock_secrets(secretsmanager, ldap_config):
    secret_dict = {
        lambda_function.SECRETS_MANAGER_KEY_USERNAME: ldap_config[
            lambda_function.SECRETS_MANAGER_KEY_USERNAME
        ],
        lambda_function.SECRETS_MANAGER_KEY_PASSWORD: ldap_config[
            lambda_function.SECRETS_MANAGER_KEY_PASSWORD
        ],
        lambda_function.SECRETS_MANAGER_KEY_DN: "cn=outdated,dc=example,dc=com",
    }
    secret_SECRETS_MANAGER_wrong_pw = {
        lambda_function.SECRETS_MANAGER_KEY_USERNAME: ldap_config[
            lambda_function.SECRETS_MANAGER_KEY_USERNAME
        ],
        lambda_function.SECRETS_MANAGER_KEY_PASSWORD: "wrong",
    }
    secret_SECRETS_MANAGER_no_user = {
        lambda_function.SECRETS_MANAGER_KEY_PASSWORD: ldap_config["password"]
    }
    secret_SECRETS_MANAGER_no_pw = {
        lambda_function.SECRETS_MANAGER_KEY_USERNAME: ldap_config[
            lambda_function.SECRETS_MANAGER_KEY_USERNAME
        ],
    }

    mock_secrets = {
        "secret_test": secretsmanager.create_secret(
            Name="ldap-test", SecretString=json.dumps(secret_dict)
        ),
        "secret_test_wrong_pw": secretsmanager.create_secret(
            Name="ldap-test-wrong-pw",
            SecretString=json.dumps(secret_SECRETS_MANAGER_wrong_pw),
        ),
        "secret_test_no_user": secretsmanager.create_secret(
            Name="ldap-test-no-user",
            SecretString=json.dumps(secret_SECRETS_MANAGER_no_user),
        ),
        "secret_test_no_pw": secretsmanager.create_secret(
            Name="ldap-test-no-pw",
            SecretString=json.dumps(secret_SECRETS_MANAGER_no_pw),
        ),
        "secret_test_string": secretsmanager.create_secret(
            Name="ldap-test-string", SecretString="secret_string"
        ),
    }

    yield mock_secrets


@pytest.fixture(scope="function")
def mock_secret_strings(secretsmanager, mock_secrets):
    yield {
        key: secretsmanager.get_secret_value(SecretId=secret["ARN"])["SecretString"]
        for (key, secret) in mock_secrets.items()
    }


@pytest.fixture(scope="function")
def get_event(request, mock_secrets):
    client_request_token = str(uuid4())
    event = {
        "ClientRequestToken": client_request_token,
        "SecretId": mock_secrets["secret_test"]["ARN"],
        "Step": request.param,
    }
    return event


##################
# fixtures tests #
##################


def test_ldap_config(ldap_config):
    # Checks if ldap_test settings change
    assert ldap_config == {
        "port": 10389,
        lambda_function.SECRETS_MANAGER_KEY_USERNAME: "cn=admin,dc=example,dc=com",
        lambda_function.SECRETS_MANAGER_KEY_PASSWORD: "password",
        "base": {
            "attributes": {"dc": "example"},
            "dn": "dc=example,dc=com",
            "objectclass": ["domain"],
        },
        "entries": [
            {
                "objectclass": "domain",
                "dn": "dc=users,dc=example,dc=com",
                "attributes": {"dc": "users"},
            },
            {
                "objectclass": "organization",
                "dn": "o=foocompany,dc=users,dc=example,dc=com",
                "attributes": {"o": "foocompany"},
            },
            {
                "objectclass": "user",
                "dn": "cn=users,dc=example,dc=com",
                "attributes": {
                    "o": "foocompany",
                    "userPrincipalName": "cn=admin,dc=example,dc=com",
                },
            },
        ],
    }


def test_ldap_conn_wrong(ldap_server, ldap_config):
    srv = ldap3.Server(
        "localhost",
        port=int(lambda_function.LDAP_SERVER_PORT),
        use_ssl=lambda_function.LDAP_USE_SSL,
    )
    conn_wrong = ldap3.Connection(srv, user=ldap_config["bind_dn"], password="wrong")
    conn_wrong.bind()
    assert conn_wrong.result.get("result") != 0
    assert conn_wrong.result.get("description") == "invalidCredentials"


def test_ldap_conn(ldap_server, ldap_config):
    # Checks if ldap_test connection works
    srv = ldap3.Server(
        "localhost",
        port=int(lambda_function.LDAP_SERVER_PORT),
        use_ssl=lambda_function.LDAP_USE_SSL,
    )
    conn = ldap3.Connection(
        srv, user=ldap_config["bind_dn"], password=ldap_config["password"]
    )
    conn.bind()
    assert conn.result.get("result") == 0


##########################
# Helper functions tests #
##########################


def test_check_inputs(ldap_config):
    username, password = lambda_function.check_inputs(ldap_config)

    assert username is ldap_config[lambda_function.SECRETS_MANAGER_KEY_USERNAME]
    assert password is ldap_config[lambda_function.SECRETS_MANAGER_KEY_PASSWORD]


def test_check_inputs_invalid_password(ldap_config):
    dict_arg = ldap_config
    dict_arg["password"] = lambda_function.EXCLUDE_CHARACTERS
    with pytest.raises(ValueError) as e:
        lambda_function.check_inputs(dict_arg)
    assert "invalid character in password" in str(e.value).lower()


def test_check_inputs_invalid_user(ldap_config):
    dict_arg = ldap_config
    dict_arg[
        lambda_function.SECRETS_MANAGER_KEY_USERNAME
    ] = lambda_function.EXCLUDE_CHARACTERS
    with pytest.raises(ValueError) as e:
        lambda_function.check_inputs(dict_arg)
    assert "invalid character in user" in str(e.value).lower()


def test_get_user_dn(ldap_server, ldap_config):
    conn = lambda_function.ldap_connection(ldap_config)
    result = lambda_function.get_user_dn(
        conn=conn,
        user=ldap_config[lambda_function.SECRETS_MANAGER_KEY_USERNAME],
        base_dn=lambda_function.LDAP_BASE_DN,
    )
    assert result == "cn=users,dc=example,dc=com"


def test_get_user_dn_wrong(ldap_server, ldap_config):
    conn = lambda_function.ldap_connection(ldap_config)
    with pytest.raises(ValueError) as e:
        lambda_function.get_user_dn(
            conn=conn,
            user="wrong",
            base_dn=lambda_function.LDAP_BASE_DN,
        )
    assert "user dn not found" in str(e.value).lower()


def test_ldap_connection(ldap_config):
    conn = lambda_function.ldap_connection(ldap_config)
    assert conn.result.get("result") == 0


def test_ldap_connection_wrong_pw(ldap_config):
    dict_arg = ldap_config
    dict_arg["password"] = "wrong"
    with pytest.raises(ValueError) as e:
        lambda_function.ldap_connection(dict_arg)
    assert "ldap bind failed" in str(e.value).lower()


def test_get_secret_dict(secretsmanager, mock_secrets, mock_secret_strings):
    secret_dict = lambda_function.get_secret_dict(
        secrets_manager_client=secretsmanager,
        arn=mock_secrets["secret_test"]["ARN"],
        stage="AWSCURRENT",
        token=None,
    )
    assert secret_dict == json.loads(mock_secret_strings["secret_test"])

    with pytest.raises(KeyError) as e:
        secret_dict = lambda_function.get_secret_dict(
            secrets_manager_client=secretsmanager,
            arn=mock_secrets["secret_test_no_user"]["ARN"],
            stage="AWSCURRENT",
            token=None,
        )
    assert (
        f"{lambda_function.SECRETS_MANAGER_KEY_USERNAME} key is missing".lower()
        in str(e.value).lower()
    )

    with pytest.raises(KeyError) as e:
        secret_dict = lambda_function.get_secret_dict(
            secrets_manager_client=secretsmanager,
            arn=mock_secrets["secret_test_no_pw"]["ARN"],
            stage="AWSCURRENT",
            token=None,
        )
    assert (
        f"{lambda_function.SECRETS_MANAGER_KEY_PASSWORD} key is missing".lower()
        in str(e.value).lower()
    )

    with pytest.raises(ValueError) as e:
        secret_dict = lambda_function.get_secret_dict(
            secrets_manager_client=secretsmanager,
            arn=mock_secrets["secret_test_string"]["ARN"],
            stage="AWSCURRENT",
            token=None,
        )
    assert "invalid secret format" in str(e.value).lower()


def test_execute_ldap_command_current(mock_secret_strings):
    result = lambda_function.execute_ldap_command(
        json.loads(mock_secret_strings["secret_test"]), None
    )
    assert result is lambda_function.LDAP_BIND_CURRENT_CREDS_SUCCESSFUL


def test_execute_ldap_command_pending(mock_secret_strings):
    result = lambda_function.execute_ldap_command(
        None, json.loads(mock_secret_strings["secret_test"])
    )
    assert result is lambda_function.LDAP_BIND_PENDING_CREDS_SUCCESSFUL


def test_execute_ldap_command_both(mock_secret_strings):
    result = lambda_function.execute_ldap_command(
        json.loads(mock_secret_strings["secret_test"]),
        json.loads(mock_secret_strings["secret_test"]),
    )
    assert result is lambda_function.LDAP_BIND_PENDING_CREDS_SUCCESSFUL


def test_execute_ldap_command_none():
    with pytest.raises(ValueError) as e:
        lambda_function.execute_ldap_command(None, None)
    assert "unexpected value" in str(e.value).lower()


def test_execute_ldap_command_only_current_valid(mock_secret_strings):
    result = lambda_function.execute_ldap_command(
        json.loads(mock_secret_strings["secret_test"]),
        json.loads(mock_secret_strings["secret_test_wrong_pw"]),
    )
    assert result is lambda_function.LDAP_BIND_CURRENT_CREDS_SUCCESSFUL


def test_execute_ldap_command_both_invalid(mock_secret_strings):
    with pytest.raises(ValueError) as e:
        lambda_function.execute_ldap_command(
            json.loads(mock_secret_strings["secret_test_wrong_pw"]),
            json.loads(mock_secret_strings["secret_test_wrong_pw"]),
        )
    assert "ldap bind failed" in str(e.value).lower()


############################
# Main functionalicy tests #
############################


@pytest.mark.parametrize("get_event", ["createSecret"], indirect=True)
def test_lambda_rotation_not_enabled(secretsmanager, get_event, lambda_func):
    with pytest.raises(ValueError) as e:
        lambda_function.lambda_handler(get_event, {})
    assert "not enabled for rotation" in str(e.value).lower()


@pytest.mark.parametrize("get_event", ["createSecret"], indirect=True)
def test_lambda_rotation_wrong_token(secretsmanager, get_event, lambda_func):
    client_request_token = get_event["ClientRequestToken"]
    secret_id = get_event["SecretId"]
    secretsmanager.rotate_secret(
        SecretId=secret_id,
        ClientRequestToken=client_request_token,
        RotationLambdaARN=lambda_func["FunctionArn"],
        RotationRules=dict(AutomaticallyAfterDays=60, Duration="1h"),
        RotateImmediately=False,
    )
    wrong_client_request_token = str(uuid4())
    get_event["ClientRequestToken"] = wrong_client_request_token
    with pytest.raises(ValueError) as e:
        lambda_function.lambda_handler(get_event, {})
    assert "no stage for rotation of secret" in str(e.value).lower()


def mock_ad_modify_password(conn, bind_user, new_password, old_password):
    global _server
    if _server.config["password"] == old_password:
        _server.config["password"] = new_password
        config = _server.config
        _server.stop()
        _server = LdapServer(config)
        _server.start()
        return True
    else:
        raise ValueError("Wrong Password")


@pytest.mark.parametrize("get_event", ["createSecret"], indirect=True)
def test_lambda_full_rotation(secretsmanager, get_event, lambda_func, ldap_server):

    create_secret = get_event.copy()
    set_secret = get_event.copy()
    test_secret = get_event.copy()
    finish_secret = get_event.copy()
    set_secret["Step"] = "setSecret"
    test_secret["Step"] = "testSecret"
    finish_secret["Step"] = "finishSecret"

    client_request_token = get_event["ClientRequestToken"]
    secret_id = get_event["SecretId"]

    # Create secret tests
    secretsmanager.rotate_secret(
        SecretId=secret_id,
        ClientRequestToken=client_request_token,
        RotationLambdaARN=lambda_func["FunctionArn"],
        RotationRules=dict(AutomaticallyAfterDays=60, Duration="1h"),
        RotateImmediately=False,
    )

    try:
        old_secret_pending = json.loads(
            secretsmanager.get_secret_value(
                SecretId=secret_id, VersionStage="AWSPENDING"
            )["SecretString"]
        )
    except Exception:
        old_secret_pending = {"password": ""}

    lambda_function.lambda_handler(create_secret, {})

    secret_current = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_id, VersionStage="AWSCURRENT")[
            "SecretString"
        ]
    )
    new_secret_pending = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_id, VersionStage="AWSPENDING")[
            "SecretString"
        ]
    )

    assert new_secret_pending["password"] != old_secret_pending["password"]
    assert new_secret_pending["password"] != secret_current["password"]
    assert (
        new_secret_pending[lambda_function.SECRETS_MANAGER_KEY_DN]
        is not secret_current[lambda_function.SECRETS_MANAGER_KEY_DN]
    )
    assert (
        new_secret_pending[lambda_function.SECRETS_MANAGER_KEY_DN]
        is not secret_current[lambda_function.SECRETS_MANAGER_KEY_DN]
    )

    with mock.patch(
        "ldap3.extend.microsoft.modifyPassword.ad_modify_password",
        side_effect=mock_ad_modify_password,
    ):
        # Set secret tests
        old_config_pw = ldap_server.config["password"]

        lambda_function.lambda_handler(set_secret, {})

        new_config_pw = ldap_server.config["password"]

        assert old_config_pw != new_config_pw
        assert new_config_pw == new_secret_pending["password"]

    try:
        lambda_function.lambda_handler(test_secret, {})
    except Exception:
        pytest.fail("Unexpected Error Testing the new secret")

    lambda_function.lambda_handler(finish_secret, {})

    new_secret_current = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_id, VersionStage="AWSCURRENT")[
            "SecretString"
        ]
    )
    assert new_secret_current["password"] == new_config_pw
    assert (
        new_secret_current[lambda_function.SECRETS_MANAGER_KEY_DN]
        == "cn=users,dc=example,dc=com"
    )


@pytest.mark.parametrize("get_event", ["createSecret"], indirect=True)
def test_lambda_rotation_no_dn(secretsmanager, get_event, lambda_func, ldap_server):
    _SECRETS_MANAGER_KEY_DN = lambda_function.SECRETS_MANAGER_KEY_DN
    lambda_function.SECRETS_MANAGER_KEY_DN = ""

    create_secret = get_event.copy()
    set_secret = get_event.copy()
    test_secret = get_event.copy()
    finish_secret = get_event.copy()
    set_secret["Step"] = "setSecret"
    test_secret["Step"] = "testSecret"
    finish_secret["Step"] = "finishSecret"

    client_request_token = get_event["ClientRequestToken"]
    secret_id = get_event["SecretId"]

    # Create secret tests
    secretsmanager.rotate_secret(
        SecretId=secret_id,
        ClientRequestToken=client_request_token,
        RotationLambdaARN=lambda_func["FunctionArn"],
        RotationRules=dict(AutomaticallyAfterDays=60, Duration="1h"),
        RotateImmediately=False,
    )

    try:
        old_secret_pending = json.loads(
            secretsmanager.get_secret_value(
                SecretId=secret_id, VersionStage="AWSPENDING"
            )["SecretString"]
        )
    except Exception:
        old_secret_pending = {"password": ""}

    lambda_function.lambda_handler(create_secret, {})

    secret_current = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_id, VersionStage="AWSCURRENT")[
            "SecretString"
        ]
    )
    new_secret_pending = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_id, VersionStage="AWSPENDING")[
            "SecretString"
        ]
    )

    assert new_secret_pending["password"] != old_secret_pending["password"]
    assert new_secret_pending["password"] != secret_current["password"]
    assert (
        new_secret_pending[_SECRETS_MANAGER_KEY_DN]
        == old_secret_pending[_SECRETS_MANAGER_KEY_DN]
    )
    assert (
        new_secret_pending[_SECRETS_MANAGER_KEY_DN]
        == secret_current[_SECRETS_MANAGER_KEY_DN]
    )

    with mock.patch(
        "ldap3.extend.microsoft.modifyPassword.ad_modify_password",
        side_effect=mock_ad_modify_password,
    ):
        # Set secret tests
        old_config_pw = ldap_server.config["password"]

        lambda_function.lambda_handler(set_secret, {})

        new_config_pw = ldap_server.config["password"]

        assert old_config_pw != new_config_pw
        assert new_config_pw == new_secret_pending["password"]

    try:
        lambda_function.lambda_handler(test_secret, {})
    except Exception:
        pytest.fail("Unexpected Error Testing the new secret")

    lambda_function.lambda_handler(finish_secret, {})

    new_secret_current = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_id, VersionStage="AWSCURRENT")[
            "SecretString"
        ]
    )
    assert new_secret_current["password"] == new_config_pw
    assert (
        new_secret_current[_SECRETS_MANAGER_KEY_DN] == "cn=outdated,dc=example,dc=com"
    )


@pytest.mark.parametrize("get_event", ["createSecret"], indirect=True)
def test_lambda_rotation_ad_error(secretsmanager, get_event, lambda_func, ldap_server):

    create_secret = get_event.copy()
    set_secret = get_event.copy()
    test_secret = get_event.copy()
    finish_secret = get_event.copy()
    set_secret["Step"] = "setSecret"
    test_secret["Step"] = "testSecret"
    finish_secret["Step"] = "finishSecret"

    client_request_token = get_event["ClientRequestToken"]
    secret_id = get_event["SecretId"]

    # Create secret tests
    secretsmanager.rotate_secret(
        SecretId=secret_id,
        ClientRequestToken=client_request_token,
        RotationLambdaARN=lambda_func["FunctionArn"],
        RotationRules=dict(AutomaticallyAfterDays=60, Duration="1h"),
        RotateImmediately=False,
    )

    lambda_function.lambda_handler(create_secret, {})
    with mock.patch(
        "ldap3.extend.microsoft.modifyPassword.ad_modify_password", return_value=False
    ):
        with pytest.raises(ValueError) as e:
            lambda_function.lambda_handler(set_secret, {})
        assert "unable to reset the users password" in str(e.value).lower()


@pytest.mark.parametrize("get_event", ["createSecret"], indirect=True)
def test_lambda_full_rotation_duplicated_events(
    secretsmanager, get_event, lambda_func, ldap_server
):

    create_secret = get_event.copy()
    set_secret = get_event.copy()
    test_secret = get_event.copy()
    finish_secret = get_event.copy()
    set_secret["Step"] = "setSecret"
    test_secret["Step"] = "testSecret"
    finish_secret["Step"] = "finishSecret"

    client_request_token = get_event["ClientRequestToken"]
    secret_id = get_event["SecretId"]

    # Create secret tests
    secretsmanager.rotate_secret(
        SecretId=secret_id,
        ClientRequestToken=client_request_token,
        RotationLambdaARN=lambda_func["FunctionArn"],
        RotationRules=dict(AutomaticallyAfterDays=60, Duration="1h"),
        RotateImmediately=False,
    )

    try:
        old_secret_pending = json.loads(
            secretsmanager.get_secret_value(
                SecretId=secret_id, VersionStage="AWSPENDING"
            )["SecretString"]
        )
    except Exception:
        old_secret_pending = {"password": ""}

    lambda_function.lambda_handler(create_secret, {})
    lambda_function.lambda_handler(create_secret, {})

    secret_current = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_id, VersionStage="AWSCURRENT")[
            "SecretString"
        ]
    )
    new_secret_pending = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_id, VersionStage="AWSPENDING")[
            "SecretString"
        ]
    )

    assert new_secret_pending["password"] is not old_secret_pending["password"]
    assert new_secret_pending["password"] is not secret_current["password"]

    with mock.patch(
        "ldap3.extend.microsoft.modifyPassword.ad_modify_password",
        side_effect=mock_ad_modify_password,
    ):
        # Set secret tests
        old_config_pw = ldap_server.config["password"]

        lambda_function.lambda_handler(set_secret, {})
        lambda_function.lambda_handler(set_secret, {})

        new_config_pw = ldap_server.config["password"]

        assert old_config_pw != new_config_pw
        assert new_config_pw == new_secret_pending["password"]

    try:
        lambda_function.lambda_handler(test_secret, {})
        lambda_function.lambda_handler(test_secret, {})
    except Exception:
        pytest.fail("Unexpected Error Testing the new secret")

    lambda_function.lambda_handler(finish_secret, {})

    new_secret_current = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_id, VersionStage="AWSCURRENT")[
            "SecretString"
        ]
    )
    assert new_config_pw == new_secret_current["password"]

    lambda_function.lambda_handler(create_secret, {})
    lambda_function.lambda_handler(set_secret, {})
    lambda_function.lambda_handler(test_secret, {})
    lambda_function.lambda_handler(finish_secret, {})

    secret_after_duplicate_events = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_id, VersionStage="AWSCURRENT")[
            "SecretString"
        ]
    )

    assert new_secret_current["password"] == secret_after_duplicate_events["password"]
