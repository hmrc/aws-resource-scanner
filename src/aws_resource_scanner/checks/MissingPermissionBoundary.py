from typing import Iterable

import boto3

from aws_resource_scanner.types import Severity, Violation


class MissingPermissionBoundary:
    description = "IAM Role is missing a permission boundary."
    severity = Severity.High
    recommendation = "Add a permission boundary to the IAM role"


def check(boto3_session: boto3.Session) -> Iterable[Violation]:
    iam = boto3_session.client("iam")

    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            if "PermissionsBoundary" in role:
                continue

            role = iam.get_role(RoleName=role["RoleName"])["Role"]

            if "PermissionsBoundary" in role:
                continue

            yield Violation(
                resource=role,
                rule=MissingPermissionBoundary,
                message=f"IAM Role {role['RoleName']} ({role['RoleId']}) doesn't have a permission boundary.",
            )
