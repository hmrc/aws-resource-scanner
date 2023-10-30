from typing import Iterable

import boto3

from aws_resource_scanner.types import Severity, Violation


class OpenSecurityGroupEgressRule:
    description = "Security group egress rule allows traffic to anywhere."
    severity = Severity.High
    recommendation = "Remove the egress rule that allows traffic to anywhere."


def check(boto3_session: boto3.Session) -> Iterable[Violation]:
    ec2 = boto3_session.client("ec2")

    for page in ec2.get_paginator("describe_security_groups").paginate(
        Filters=[
            {
                "Name": "egress.ip-permission.cidr",
                "Values": [
                    "0.0.0.0/0",
                ],
            },
        ],
    ):
        for security_group in page["SecurityGroups"]:
            yield Violation(
                resource=security_group,
                rule=OpenSecurityGroupEgressRule(),
                message=f"Security group {security_group['GroupName']} ({security_group['GroupId']}) egress rule allows traffic to anywhere.",
            )
