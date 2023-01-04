import json
import logging
import os

import boto3
from ldap3 import Connection, Server, extend

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DICT_KEY_USERNAME = os.environ.get("DICT_KEY_USERNAME") or "user"
DICT_KEY_PASSWORD = os.environ.get("DICT_KEY_PASSWORD") or "password"
DICT_KEY_EMAIL = os.environ.get("DICT_KEY_EMAIL") or "email"
DICT_KEY_BIND_DN = os.environ.get("DICT_KEY_BIND_DN") or "ldap_default_bind_dn"
DICT_KEY_OBFUSCATED_PASSWORD = os.environ.get(
    "DICT_KEY_OBFUSCATED_PASSWORD") or "obfuscated_password"

SECRETS_MANAGER_ENDPOINT = os.environ.get(
    "SECRETS_MANAGER_ENDPOINT") or "https://secretsmanager.eu-central-1.amazonaws.com"
EXCLUDE_CHARACTERS = os.environ.get("EXCLUDE_CHARACTERS") or "/'\"\\"
LDAP_SERVER_NAME = os.environ.get(
    "LDAP_SERVER_NAME") or "ldaps://vt1dceuc1001.vt1.vitesco.com:636"
LDAP_BIND_CURRENT_CREDS_SUCCESSFUL = "LDAP_BIND_USING_CURRENT_CREDS_SUCCESSFUL"
LDAP_BIND_PENDING_CREDS_SUCCESSFUL = "LDAP_BIND_USING_PENDING_CREDS_SUCCESSFUL"


def lambda_handler(event, context):
    """Secrets Manager Rotation Template
    Rotates a password for a LDAP user account. This is the main lambda entry point.
    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)
        context (LambdaContext): The Lambda runtime information
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not properly configured for rotation
        KeyError: If the event parameters do not contain the expected keys
    """
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    logger.info(f"Step: {step}.")

    # TODO: Set ldap3 Server and Tls instead of server string.
    ldap_server = LDAP_SERVER_NAME

    # Setup the client
    secrets_manager_client = boto3.client('secretsmanager',
                                          endpoint_url=SECRETS_MANAGER_ENDPOINT)

    if step == "test":
        current_dict = get_secret_dict(secrets_manager_client, arn, "AWSCURRENT")
        print(current_dict)
        status = execute_ldap_command(current_dict, None, ldap_server)
        print(status)
        return

    # Make sure the version is staged correctly
    metadata = secrets_manager_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error(f"Secret {arn} is not enabled for rotation")
        raise ValueError(f"Secret {arn} is not enabled for rotation")
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error(
            f"Secret version {token} has no stage for rotation of secret {arn}.")
        raise ValueError(
            f"Secret version {token} has no stage for rotation of secret {arn}.")
    if "AWSCURRENT" in versions[token]:
        logger.info(
            f"Secret version {token} already set as AWSCURRENT for secret {arn}.")
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error(
            f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}."
        )
        raise ValueError(
            f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}."
        )

    current_dict = get_secret_dict(secrets_manager_client, arn, "AWSCURRENT")

    if step == "createSecret":
        create_secret(secrets_manager_client, arn, token, current_dict, ldap_server)

    elif step == "setSecret":
        # Get the pending secret and update password in Directory Services
        pending_dict = get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
        if current_dict[DICT_KEY_USERNAME] != pending_dict[DICT_KEY_USERNAME]:
            logger.error(
                f"Username {current_dict[DICT_KEY_USERNAME]} in current dict "
                f"does not match username {pending_dict[DICT_KEY_USERNAME]} in pending dict"
            )
            raise ValueError(
                f"Username {current_dict[DICT_KEY_USERNAME]} in current dict "
                f"does not match username {pending_dict[DICT_KEY_USERNAME]} in pending dict"
            )
        set_secret(current_dict, pending_dict, ldap_server)

    elif step == "testSecret":
        pending_dict = get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
        test_secret(pending_dict, ldap_server)

    elif step == "finishSecret":
        finish_secret(secrets_manager_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(secrets_manager_client, arn, token, current_dict, ldap_server):
    """Create the secret
    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.
    Args:
        secrets_manager_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
    """
    # Exception if ldap binding fails for the current credentials
    execute_ldap_command(current_dict, None, ldap_server)

    # Now try to get the secret version, if that fails, put a new secret
    try:
        get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
        logger.info(f"createSecret: Successfully retrieved secret for {arn}.")
    except secrets_manager_client.exceptions.ResourceNotFoundException:
        # Generate a random password
        passwd = secrets_manager_client.get_random_password(
            ExcludeCharacters=EXCLUDE_CHARACTERS)
        current_dict[DICT_KEY_PASSWORD] = passwd["RandomPassword"]

        # Put the secret
        secrets_manager_client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=json.dumps(current_dict),
            VersionStages=["AWSPENDING"],
        )
        logger.info(
            f"createSecret: Successfully put secret for ARN {arn} and version {token}.")


def set_secret(current_dict, pending_dict, ldap_server):
    """
    Set the secret in Directory Services. This is the second step, where Directory Services is actually updated. 
    This method does not update the Secret Manager label. Therefore, the AWSCURRENT secret does not match the password in Directory 
    Services as the end of this step. We are technically in a broken state at the end of this step.
    It will be fixed in the finishSecret step when the Secrets Manager value is updated.
    Args:
        current_dict (dictionary): Used for ldap operations
        pending_dict (dictionary): Used to reset Directory Services password
        ldap_server (ldap3.Server or string): The Server object to be contacted. It can be a ServerPool.
        In this case the ServerPool pooling strategy is followed when opening the connection.
        You can also pass a string containing the name of the server.
        In this case the Server object is implicitly created with default values.
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not valid JSON or unable to set password in Directory Services
        KeyError: If the secret json does not contain the expected keys
        ValueError: Raise exception if ldap fails with given credentials
    """

    # Make sure current or pending credentials work
    status = execute_ldap_command(current_dict, pending_dict, ldap_server)
    # Cover the case where this step has already succeeded and
    # AWSCURRENT is no longer the current password, try to log in
    # with the AWSPENDING password and if that is successful, immediately
    # return.
    if status == LDAP_BIND_PENDING_CREDS_SUCCESSFUL:
        return

    try:
        _, password, email, bind_dn, _ = check_inputs(current_dict)
        _, new_password, _, _, _ = check_inputs(pending_dict)
        conn = Connection(ldap_server, user=email, password=password)
        conn.bind()
        if conn.result.get('result') == 0:
            extend.microsoft.modifyPassword.ad_modify_password(conn,
                                                               bind_dn,
                                                               new_password,
                                                               password,
                                                               controls=None)
        else:
            raise ValueError(
                f"ldap bind failed! Connection result: {conn.result.get('result')}, description: {conn.result.get('description')}"
            )
    except Exception as e:
        logger.error("setSecret: Unable to reset the users password in Directory "
                     f"Services user {pending_dict[DICT_KEY_USERNAME]}")
        logger.error(e)
        raise ValueError(
            "Unable to reset the users password in Directory Services") from Exception


def test_secret(pending_dict, ldap_server):
    """
    Args:
        pending_dict (dictionary): Used to test pending credentials
        ldap_server (ldap3.Server or string): The Server object to be contacted. It can be a ServerPool.
        In this case the ServerPool pooling strategy is followed when opening the connection.
        You can also pass a string containing the name of the server.
        In this case the Server object is implicitly created with default values.
    Raises:
        ValueError: Raise exception if kinit fails with given credentials
    """
    execute_ldap_command(None, pending_dict, ldap_server)


def finish_secret(secrets_manager_client, arn, token):
    """Finish the secret
    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.
    Args:
        secrets_manager_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist
    """
    # First describe the secret to get the current version
    metadata = secrets_manager_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info(
                    f"finishSecret: Version {version} already marked as AWSCURRENT for {arn}"
                )
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    secrets_manager_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version)
    logger.info(
        f"finishSecret: Successfully set AWSCURRENT stage to version {token} for secret {arn}."
    )


def get_secret_dict(secrets_manager_client, arn, stage, token=None):
    """
    Gets the secret dictionary corresponding for the secret arn, stage,
    and token
    This helper function gets credentials for the arn and stage passed in and
    returns the dictionary
    by parsing the JSON string. You can change the default dictionary keys
    using env vars above.
    Args:
        secrets_manager_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret
        version, or None if no validation is desired
        stage (string): The stage identifying the secret version
    Returns:
        SecretDictionary: Secret dictionary
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and
        stage does not exist
        ValueError: If the secret is not valid JSON
    """
    required_fields = [DICT_KEY_USERNAME, DICT_KEY_PASSWORD]
    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = secrets_manager_client.get_secret_value(SecretId=arn,
                                                         VersionId=token,
                                                         VersionStage=stage)
    else:
        secret = secrets_manager_client.get_secret_value(SecretId=arn,
                                                         VersionStage=stage)
    plaintext = secret["SecretString"]
    secret_dict = json.loads(plaintext)

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError(f"{field} key is missing from secret JSON")

    # Parse and return the secret JSON string
    return secret_dict


def execute_ldap_command(current_dict, pending_dict, ldap_server):
    """
    Executes the ldap command to verify user credentials.
    Args:
        current_dict (dictionary): Dictionary containing current credentials
        pending_dict (dictionary): Dictionary containing pending credentials
        ldap_server (ldap3.Server or string): The Server object to be contacted. It can be a ServerPool.
        In this case the ServerPool pooling strategy is followed when opening the connection.
        You can also pass a string containing the name of the server.
        In this case the Server object is implicitly created with default values.
    Returns:
        ldap_creds_successful or raises exception
    Raises:
        ValueError: Raise exception if ldap bind fails with given credentials
    """

    if pending_dict is not None:
        # First try to log in with the AWSPENDING password and if that is
        # successful, immediately return.
        username, password, email, bind_dn, obfuscated_password = check_inputs(
            pending_dict)
        try:
            conn = Connection(ldap_server, user=email, password=password)
            conn.bind()
            if conn.result.get('result') == 0:
                return LDAP_BIND_PENDING_CREDS_SUCCESSFUL
            else:
                # If Pending secret does not authenticate, we can proceed to
                # current secret.
                logger.info(
                    "execute_ldap_command: Proceed to current secret since pending secret does not authenticate"
                    f"Connection result: {conn.result.get('result')}, description: {conn.result.get('description')}"
                )
        except:
            # If Pending secret does not authenticate, we can proceed to
            # current secret.
            logger.info(
                "execute_ldap_command: Proceed to current secret since pending secret does not authenticate"
            )

    if current_dict is None:
        logger.error("execute_ldap_command: Unexpected value for current_dict")
        raise ValueError("execute_ldap_command: Unexpected value for current_dict")

    username, password, email, bind_dn, obfuscated_password = check_inputs(current_dict)
    try:
        conn = Connection(ldap_server, user=email, password=password)
        conn.bind()
        if conn.result.get('result') == 0:
            return LDAP_BIND_CURRENT_CREDS_SUCCESSFUL
        else:
            raise ValueError(
                f"ldap bind failed! Connection result: {conn.result.get('result')}, "
                f"description: {conn.result.get('description')}")
    except Exception as e:
        logger.error("execute_ldap_command: ldap bind failed")
        logger.error(e)
        raise ValueError("execute_ldap_command: ldap bind failed") from Exception


def check_inputs(dict_arg):
    """
    Check username and password for invalid characters
    Args:
        dict_arg (dictionary): Dictionary containing current credentials
    Returns:
        username(string): Username from Directory Service
        password(string): Password of username from Directory Service
    Raises:
        Value Error: If username or password has characters from exclude list.
    """
    username = dict_arg[DICT_KEY_USERNAME]
    password = dict_arg[DICT_KEY_PASSWORD]
    # Optional fields
    email = dict_arg.get(DICT_KEY_EMAIL) or None
    bind_dn = dict_arg.get(DICT_KEY_BIND_DN) or None
    obfuscated_password = dict_arg.get(DICT_KEY_OBFUSCATED_PASSWORD) or None

    username_check_list = [char in username for char in EXCLUDE_CHARACTERS]
    if True in username_check_list:
        raise ValueError("check_inputs: Invalid character in username")

    password_check_list = [char in password for char in EXCLUDE_CHARACTERS]
    if True in password_check_list:
        raise ValueError("check_inputs: Invalid character in password")

    return username, password, email, bind_dn, obfuscated_password


if __name__ == "__main__":
    event = {
        'ClientRequestToken':
            '4a3eed88-cfa6-4452-b121-9a7259ecfbcf',
        'SecretId':
            'arn:aws:secretsmanager:eu-central-1:000894882174:secret:/datalake/_global/api/sssdtest-qTpL5L',
        'Step':
            'test'
    }
    context = {}

    lambda_handler(event, context)
