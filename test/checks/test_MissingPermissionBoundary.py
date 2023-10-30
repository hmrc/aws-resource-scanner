import re

import boto3
from moto import mock_iam

from aws_resource_scanner.checks.MissingPermissionBoundary import check, MissingPermissionBoundary

@mock_iam
def test_default_roles():
    violations = check(boto3.Session(region_name="eu-west-2"))

    assert len(list(violations)) == 0

@mock_iam
def test_new_violation():
    iam = boto3.client('iam')
    iam.create_role(
        RoleName='test_new_violation',
        AssumeRolePolicyDocument='{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Principal": {"Service": "ec2.amazonaws.com"},"Action": "sts:AssumeRole"}]}',
    )

    violations = list(check(boto3.Session(region_name="eu-west-2")))

    assert len(violations) == 1
    violation = violations[0]
    assert isinstance(violation.rule, MissingPermissionBoundary)
    assert violation.resource['RoleName'] == 'test_new_violation'
    assert re.match(r"IAM Role test_new_violation (.*?) doesn't have a permission boundary.", violation.message)

@mock_iam
def test_new_non_violation():
    iam = boto3.client('iam')
    iam.create_role(
        RoleName='test_new_non_violation',
        AssumeRolePolicyDocument='{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Principal": {"Service": "ec2.amazonaws.com"},"Action": "sts:AssumeRole"}]}',
        PermissionsBoundary='arn:aws:iam::aws:policy/AdministratorAccess',
    )

    violations = list(check(boto3.Session(region_name="eu-west-2")))

    assert len(violations) == 0
