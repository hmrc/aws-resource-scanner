import boto3
from moto import mock_ec2

from aws_resource_scanner.checks.OpenSecurityGroupEgressRule import check, OpenSecurityGroupEgressRule

@mock_ec2
def test_default_violations():
    ec2_client = boto3.client("ec2", region_name="eu-west-2")
    ec2_client.create_security_group(GroupName="test", Description="test")

    violations = list(check(boto3.Session(region_name="eu-west-2")))

    assert len(violations) == 2

    for violation in violations:
        assert isinstance(violation.rule, OpenSecurityGroupEgressRule)
        assert violation.message == f"Security group {violation.resource['GroupName']} ({violation.resource['GroupId']}) egress rule allows traffic to anywhere."


@mock_ec2
def test_new_violation():
    """
    Does the check function find a new violating security group?
    """
    ec2_client = boto3.client("ec2", region_name="eu-west-2")
    ec2_client.create_security_group(GroupName="test", Description="test")

    sg = ec2_client.create_security_group(
        Description='New group for test_new_violation',
        GroupName='test_new_violation',
        VpcId='vpc-12345',
    )

    ec2_client.authorize_security_group_egress(
        GroupId=sg['GroupId'],
        CidrIp='0.0.0.0/0'
    )

    violations = list(check(boto3.Session(region_name="eu-west-2")))

    assert len(violations) == 3

    new_violation_found = False

    for violation in violations:
        assert isinstance(violation.rule, OpenSecurityGroupEgressRule)
        assert violation.message == f"Security group {violation.resource['GroupName']} ({violation.resource['GroupId']}) egress rule allows traffic to anywhere."

        if violation.resource['GroupId'] == sg['GroupId']:
            new_violation_found = True

    assert new_violation_found

@mock_ec2
def test_new_non_violation():
    """
    Does the check function find a new violating security group?
    """
    ec2_client = boto3.client("ec2", region_name="eu-west-2")
    ec2_client.create_security_group(GroupName="test", Description="test")

    sg = ec2_client.create_security_group(
        Description='New group for test_new_violation',
        GroupName='test_new_violation',
        VpcId='vpc-12345',
    )

    ec2_client.authorize_security_group_egress(
        GroupId=sg['GroupId'],
        CidrIp='1.0.0.0/0'
    )

    violations = list(check(boto3.Session(region_name="eu-west-2")))

    assert len(violations) == 2

    for violation in violations:
        assert isinstance(violation.rule, OpenSecurityGroupEgressRule)
        assert violation.message == f"Security group {violation.resource['GroupName']} ({violation.resource['GroupId']}) egress rule allows traffic to anywhere."


@mock_ec2
def test_new_empty_group_no_violation():
    ec2_client = boto3.client("ec2", region_name="eu-west-2")
    ec2_client.create_security_group(GroupName="test", Description="test")

    ec2_client.create_security_group(
        Description='New group for test_new_violation',
        GroupName='test_new_violation',
        VpcId='vpc-12345',
    )

    violations = list(check(boto3.Session(region_name="eu-west-2")))

    assert len(violations) == 2

    for violation in violations:
        assert isinstance(violation.rule, OpenSecurityGroupEgressRule)
        assert violation.message == f"Security group {violation.resource['GroupName']} ({violation.resource['GroupId']}) egress rule allows traffic to anywhere."
