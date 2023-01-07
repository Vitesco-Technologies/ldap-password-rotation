import io
import zipfile

import boto3
from botocore.exceptions import ClientError
from moto import mock_iam

_lambda_region = "eu-central-1"


def get_role_name():
    with mock_iam():
        iam = boto3.client("iam", region_name=_lambda_region)
        while True:
            try:
                return iam.get_role(RoleName="my-role")["Role"]["Arn"]
            except ClientError:
                try:
                    return iam.create_role(
                        RoleName="my-role",
                        AssumeRolePolicyDocument="some policy",
                        Path="/my-path/",
                    )["Role"]["Arn"]
                except ClientError:
                    pass


def _zip_lambda(func_str):
    zip_output = io.BytesIO()
    zip_file = zipfile.ZipFile(zip_output, "w", zipfile.ZIP_DEFLATED)
    zip_file.writestr("lambda_function.py", func_str)
    zip_file.close()
    zip_output.seek(0)
    return zip_output.read()


def get_lambda_zip_file():
    pfunc = """
def lambda_handler(event, context):
    return event
    """
    return _zip_lambda(pfunc)


# noqa: E501
# def get_rotate_lambda_zip_file():
#     # TODO: If this issue (https://github.com/spulec/moto/issues/3779)
#     # gets implemented we could use our own code with the ldap3 lambda layer
#     pfunc = """
# # noqa: E501
# import boto3
# import json
# def lambda_handler(event, context):
#     arn = event['SecretId']
#     token = event['ClientRequestToken']
#     step = event['Step']
#     client = boto3.client("secretsmanager", region_name="eu-central-1", endpoint_url="http://motoserver:5000")
#     metadata = client.describe_secret(SecretId=arn)
#     value = client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
#     if not metadata['RotationEnabled']:
#         print("Secret %s is not enabled for rotation." % arn)
#         raise ValueError("Secret %s is not enabled for rotation." % arn)
#     versions = metadata['VersionIdsToStages']
#     if token not in versions:
#         print("Secret version %s has no stage for rotation of secret %s." % (token, arn))
#         raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
#     if "AWSCURRENT" in versions[token]:
#         print("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
#         return
#     elif "AWSPENDING" not in versions[token]:
#         print("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
#         raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
#     if step == 'createSecret':
#         try:
#             client.get_secret_value(SecretId=arn, VersionId=token, VersionStage='AWSPENDING')
#         except client.exceptions.ResourceNotFoundException:
#             client.put_secret_value(
#                 SecretId=arn,
#                 ClientRequestToken=token,
#                 SecretString=json.dumps({'create': True}),
#                 VersionStages=['AWSPENDING']
#             )
#     if step == 'setSecret':
#         client.put_secret_value(
#             SecretId=arn,
#             ClientRequestToken=token,
#             SecretString='UpdatedValue',
#             VersionStages=["AWSPENDING"]
#         )
#     elif step == 'finishSecret':
#         current_version = next(
#             version
#             for version, stages in metadata['VersionIdsToStages'].items()
#             if 'AWSCURRENT' in stages
#         )
#         print("current: %s new: %s" % (current_version, token))
#         client.update_secret_version_stage(
#             SecretId=arn,
#             VersionStage='AWSCURRENT',
#             MoveToVersionId=token,
#             RemoveFromVersionId=current_version
#         )
#         client.update_secret_version_stage(
#             SecretId=arn,
#             VersionStage='AWSPENDING',
#             RemoveFromVersionId=token
#         )
#     """
#     return _zip_lambda(pfunc)
