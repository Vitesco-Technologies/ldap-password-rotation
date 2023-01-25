import json
import logging
import os

import boto3
from ldap3 import Connection, Server, SUBTREE, extend

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Key name in secrets manager with the username used to bind to LDAP
DICT_KEY_USERNAME = os.environ.get("DICT_KEY_USERNAME") or "username"
# Key name in secrets manager with the password used to bind to LDAP
DICT_KEY_PASSWORD = os.environ.get("DICT_KEY_PASSWORD") or "password"
# (optional) Key name in secrets manager with the user "distinguished name"
# When provided, it will update the secrets manager with the current value in LDAP
DICT_KEY_DN = os.environ.get("DICT_KEY_DN") or ""

SECRETS_MANAGER_REGION = os.environ.get("SECRETS_MANAGER_REGION") or "eu-central-1"
EXCLUDE_CHARACTERS_USER = os.environ.get("EXCLUDE_CHARACTERS_USER") or "$/'\"\\"
EXCLUDE_CHARACTERS_PW = os.environ.get("EXCLUDE_CHARACTERS_PW") or "@$/`'\"\\"
EXCLUDE_CHARACTERS_NEW_PW = os.environ.get("EXCLUDE_CHARACTERS_NEW_PW") or "@$/`'\"\\"

LDAP_SERVER_LIST = (
    os.environ.get("LDAP_SERVER_LIST")
    or '["ldaps://vt1dceuc1001.vt1.vitesco.com", "ldaps://vt1dceuc1002.vt1.vitesco.com"]'
)
LDAP_SERVER_PORT = os.environ.get("LDAP_SERVER_PORT") or "636"
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN") or "dc=vt1,dc=vitesco,dc=com"
LDAP_USER_AUTH_ATTRIBUTE = (
    os.environ.get("LDAP_USER_AUTH_ATTRIBUTE") or "userPrincipalName"
)

LDAP_USE_SSL = True
LDAP_BIND_CURRENT_CREDS_SUCCESSFUL = "LDAP_BIND_USING_CURRENT_CREDS_SUCCESSFUL"
LDAP_BIND_PENDING_CREDS_SUCCESSFUL = "LDAP_BIND_USING_PENDING_CREDS_SUCCESSFUL"


def lambda_handler(event, context):
    """Secrets Manager Rotation LDAP # noqa: E501
    Rotates a password for a LDAP user account. This is the main lambda entry point.
    This rotation lambda expects the secret in the secrets manager to include at least the user and password.
    You can also update your user "distinguished name" in secrets manager by providing it's key name.
    You can include additional fields, which will be kept unchanged after the password rotation.
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
    logger.info(f"### Current Event: {event}. ###")

    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    logger.info(f"### Current Step: {step}. ###")

    # Setup the client
    secrets_manager_client = boto3.client(
        "secretsmanager", region_name=SECRETS_MANAGER_REGION
    )

    # Make sure the version is staged correctly
    metadata = secrets_manager_client.describe_secret(SecretId=arn)
    if not metadata["RotationEnabled"]:
        logger.error(f"Secret {arn} is not enabled for rotation")
        raise ValueError(f"Secret {arn} is not enabled for rotation")
    versions = metadata["VersionIdsToStages"]
    if token not in versions:
        logger.error(
            f"Secret version {token} has no stage for rotation of secret {arn}."
        )
        raise ValueError(
            f"Secret version {token} has no stage for rotation of secret {arn}."
        )
    if "AWSCURRENT" in versions[token]:
        logger.info(
            f"Secret version {token} already set as AWSCURRENT for secret {arn}."
        )
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error(
            f"Secret version {token} not set as AWSPENDING "
            f"for rotation of secret {arn}."
        )
        raise ValueError(
            f"Secret version {token} not set as AWSPENDING "
            f"for rotation of secret {arn}."
        )

    current_dict = get_secret_dict(secrets_manager_client, arn, "AWSCURRENT")

    if step == "createSecret":
        create_secret(secrets_manager_client, arn, token, current_dict)

    elif step == "setSecret":
        # Get the pending secret and update password in Directory Services
        pending_dict = get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
        if current_dict[DICT_KEY_USERNAME] != pending_dict[DICT_KEY_USERNAME]:
            logger.error(
                f"Username {current_dict[DICT_KEY_USERNAME]} in current dict does "
                f"not match username {pending_dict[DICT_KEY_USERNAME]} in pending dict"
            )
            raise ValueError(
                f"Username {current_dict[DICT_KEY_USERNAME]} in current dict does "
                f"not match username {pending_dict[DICT_KEY_USERNAME]} in pending dict"
            )
        set_secret(current_dict, pending_dict)

    elif step == "testSecret":
        pending_dict = get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
        test_secret(pending_dict)

    elif step == "finishSecret":
        finish_secret(secrets_manager_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(secrets_manager_client, arn, token, current_dict):
    """Create the secret # noqa: E501
    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.
    Args:
        secrets_manager_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
        current_dict (dictionary): Used to validate the current credentials and generate the new AWSPENDING SecretString
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
    """
    # Exception if ldap binding fails for the current credentials
    execute_ldap_command(current_dict, None)

    # Now try to get the secret version, if that fails, put a new secret
    try:
        pending_dict = get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
        logger.info(f"createSecret: Successfully retrieved secret for {arn}.")
        _, current_secret = check_inputs(current_dict)
        _, pending_secret = check_inputs(pending_dict)
        if pending_secret == current_secret:
            logger.info(
                f"createSecret: Pending and Current secret are equal for {arn}."
            )
            raise ValueError(
                f"createSecret: Pending and Current secret are equal for {arn}."
            )
    except (
        secrets_manager_client.exceptions.ResourceNotFoundException,
        ValueError,
    ) as e:
        # Checks if we got an unexpected ValueError
        if isinstance(
            e, ValueError
        ) and "createSecret: Pending and Current secret are equal" not in str(e):
            logger.error("createSecret: Unknown Error.")
            raise e

        # Generate a random password
        passwd = secrets_manager_client.get_random_password(
            ExcludeCharacters=EXCLUDE_CHARACTERS_NEW_PW
        )
        current_dict[DICT_KEY_PASSWORD] = passwd["RandomPassword"]
        if DICT_KEY_DN:
            bind_user = get_user_dn(conn=conn, user=user, base_dn=LDAP_BASE_DN)
            current_dict[DICT_KEY_DN] = bind_user

        # Put the secret
        secrets_manager_client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=json.dumps(current_dict),
            VersionStages=["AWSPENDING"],
        )
        logger.info(
            f"createSecret: Successfully put secret for ARN {arn} and version {token}."
        )


def set_secret(current_dict, pending_dict):
    """Set the secret # noqa: E501
    This is the second step, where Directory Services is actually updated.
    This method does not update the Secret Manager label.
    Therefore, the AWSCURRENT secret does not match the password in Directory
    Services as the end of this step. We are technically in a broken state at the end of this step.
    It will be fixed in the finishSecret step when the Secrets Manager value is updated.
    Args:
        current_dict (dictionary): Used for ldap operations
        pending_dict (dictionary): Used to reset Directory Services password
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not valid JSON or unable to set password in Directory Services
        KeyError: If the secret json does not contain the expected keys
        ValueError: Raise exception if ldap fails with given credentials
    """

    # Make sure current or pending credentials work
    logger.info("setSecret: Checking if the new credentials are already active.")
    status = execute_ldap_command(current_dict, pending_dict)
    # Cover the case where this step has already succeeded and
    # AWSCURRENT is no longer the current password, try to log in
    # with the AWSPENDING password and if that is successful, immediately
    # return.
    if status == LDAP_BIND_PENDING_CREDS_SUCCESSFUL:
        logger.info(
            "setSecret: Skipping the setSecret step, "
            "since the new credentials are already valid."
        )
        return

    try:
        user, old_password = check_inputs(current_dict)
        _, new_password = check_inputs(pending_dict)
        conn = ldap_connection(current_dict)
        conn.bind()
        bind_user = get_user_dn(conn=conn, user=user, base_dn=LDAP_BASE_DN)
        if conn.result.get("result") == 0:
            ad_modify_password = extend.microsoft.modifyPassword.ad_modify_password(
                conn, bind_user, new_password=new_password, old_password=old_password
            )
            if ad_modify_password:
                logger.info(
                    f"setSecret: The password for {bind_user} was successfuly updated."
                )
            else:
                logger.error(
                    f"setSecret: Failed to update the password for {bind_user}."
                )
                raise ValueError(
                    "Unable to reset the users password in Directory Services"
                )
        else:
            raise ValueError(
                f"ldap bind failed! Connection result: {conn.result.get('result')},"
                f"description: {conn.result.get('description')}"
            )
    except Exception as e:
        logger.error(
            "setSecret: Unable to reset the users password in Directory "
            f"Services user {pending_dict[DICT_KEY_USERNAME]}"
        )
        logger.error(e)
        raise ValueError("Unable to reset the users password in Directory Services")


def test_secret(pending_dict):
    """Test the secret # noqa: E501
    Args:
        pending_dict (dictionary): Used to test pending credentials
    Raises:
        ValueError: Raise exception if kinit fails with given credentials
    """
    execute_ldap_command(None, pending_dict)


def finish_secret(secrets_manager_client, arn, token):
    """Finish the secret # noqa: E501
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
                    f"finishSecret: Version {version} "
                    f"already marked as AWSCURRENT for {arn}"
                )
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    secrets_manager_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logger.info(
        "finishSecret: Successfully set AWSCURRENT "
        f"stage to version {token} for secret {arn}."
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
        stage (string): The stage identifying the secret version
        token (string): The ClientRequestToken associated with the secret
        version, or None if no validation is desired
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
        secret = secrets_manager_client.get_secret_value(
            SecretId=arn, VersionId=token, VersionStage=stage
        )
    else:
        secret = secrets_manager_client.get_secret_value(
            SecretId=arn, VersionStage=stage
        )
    plaintext = secret["SecretString"]

    try:
        secret_dict = json.loads(plaintext)
    except ValueError as e:
        logger.error(
            "get_secret_dict: Invalid secret format. "
            "The secret can't be loaded as json."
        )
        logger.error(e)
        raise ValueError(
            "get_secret_dict: Invalid secret format. "
            "The secret can't be loaded as json."
        )

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError(f"{field} key is missing from secret JSON")

    # Parse and return the secret JSON string
    return secret_dict


def execute_ldap_command(current_dict, pending_dict):
    """
    Executes the ldap command to verify user credentials.
    Args:
        current_dict (dictionary): Dictionary containing current credentials
        pending_dict (dictionary): Dictionary containing pending credentials
    Returns:
        ldap_creds_successful or raises exception
    Raises:
        ValueError: Raise exception if ldap bind fails with given credentials
    """

    if pending_dict is not None:
        # First try to log in with the AWSPENDING password and if that is
        # successful, immediately return.
        try:
            conn = ldap_connection(pending_dict)
            conn.bind()
            if conn.result.get("result") == 0:
                return LDAP_BIND_PENDING_CREDS_SUCCESSFUL
            else:
                # If Pending secret does not authenticate, we can proceed to
                # current secret.
                logger.info(
                    "execute_ldap_command: Proceed to current secret "
                    "since pending secret does not authenticate "
                    f"Connection result: {conn.result.get('result')}, "
                    f"description: {conn.result.get('description')}"
                )
        except Exception:
            # If Pending secret does not authenticate, we can proceed to
            # current secret.
            logger.info(
                "execute_ldap_command: Proceed to current secret "
                "since pending secret does not authenticate"
            )

    if current_dict is None:
        logger.error("execute_ldap_command: Unexpected value for current_dict")
        raise ValueError("execute_ldap_command: Unexpected value for current_dict")

    try:
        conn = ldap_connection(current_dict)
        conn.bind()
        if conn.result.get("result") == 0:
            return LDAP_BIND_CURRENT_CREDS_SUCCESSFUL
        else:
            raise ValueError(
                f"ldap bind failed! Connection result: {conn.result.get('result')}, "
                f"description: {conn.result.get('description')}"
            )
    except Exception as e:
        logger.error("execute_ldap_command: ldap bind failed")
        logger.error(e)
        raise ValueError("execute_ldap_command: ldap bind failed") from Exception


def check_inputs(dict_arg):
    """# noqa: E501
    Check username and password for invalid characters
    Args:
        dict_arg(dictionary): Dictionary containing current credentials
    Returns:
        username(string): Username from Directory Service
        password(string): Password of username from Directory Service
    Raises:
        Value Error: If username or password has characters from exclude list.
    """
    username = dict_arg[DICT_KEY_USERNAME]
    password = dict_arg[DICT_KEY_PASSWORD]

    username_check_list = [char in username for char in EXCLUDE_CHARACTERS_USER]
    if True in username_check_list:
        raise ValueError("check_inputs: Invalid character in username")

    password_check_list = [char in password for char in EXCLUDE_CHARACTERS_PW]
    if True in password_check_list:
        raise ValueError("check_inputs: Invalid character in password")

    return username, password


def get_user_dn(conn, user, base_dn=LDAP_BASE_DN):
    """# noqa: E501
    Checks for the most precise bind user available
    Args:
        conn(Connection): The Connection object is used to send operation requests to the LDAP Server.
        username(string): Username from Directory Service
        base_dn(string): The base of the search request
    Returns:
        user_dn(string): User string to bind to the Directory Service
    Raises:
        Value Error: If the user DN can't be found
    """

    search_filter = "(&(" + LDAP_USER_AUTH_ATTRIBUTE + "=" + user + "))"
    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=[LDAP_USER_AUTH_ATTRIBUTE],
    )

    user_dn = None

    for entry in conn.response:
        if entry.get("dn") and user in entry.get("attributes").get(
            LDAP_USER_AUTH_ATTRIBUTE
        ):
            user_dn = entry.get("dn")

    if user_dn:
        return user_dn
    else:
        raise ValueError("get_user_dn: User DN not found")


def ldap_connection(dict_arg):
    """# noqa: E501
    Generates an LDAP Connection object and validates if it can successfully bind.
    This function uses the list of LDAP servers to generate a list of LDAP Server objects which use SSL.
    The list of LDAP Servers is then used to create the LDAP connection.
    Args:
        dict_arg (dictionary): Dictionary containing the current secret
    Returns:
        conn(Connection): The Connection object is used to send operation requests to the LDAP Server.
    Raises:
        Value Error: If the ldap connection fails.
    """
    username, password = check_inputs(dict_arg)
    ldap_servers_list = json.loads(LDAP_SERVER_LIST)

    ldap_servers = [
        Server(host, port=int(LDAP_SERVER_PORT), use_ssl=LDAP_USE_SSL, get_info="NONE")
        for host in ldap_servers_list
    ]
    try:
        conn = Connection(ldap_servers, user=username, password=password)
        conn.bind()
        if conn.result.get("result") == 0:
            return conn
        else:
            raise ValueError(
                f"ldap_connection: ldap bind failed! "
                f"Connection result: {conn.result.get('result')}, "
                f"description: {conn.result.get('description')}"
            )
    except Exception as e:
        logger.error("ldap_connection: ldap bind failed")
        logger.error(e)
        raise ValueError("ldap_connection: ldap bind failed") from Exception
