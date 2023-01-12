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
