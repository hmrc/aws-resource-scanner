from typing import Iterable

import boto3

from aws_resource_scanner.types import Severity, Violation


class NetworkLoadBalancerWithoutSecurityGroup:
    description = "Network Load Balancer is not associated with a security group"
    severity = Severity.Low
    recommendation = "Replace the Network Load Balancer with a new one that is associated with a security group"


class CrossZoneLoadBalancingEnabled:
    description = "Load Balancer has cross-zone load balancing enabled"
    severity = Severity.Medium
    recommendation = "Consider disabling cross-zone load balancing"


class LoggingDisabled:
    description = "Load Balancer has logging disabled"
    severity = Severity.High
    recommendation = "Enabling logging"


class InsufficientAvailabilityZones:
    description = "Load Balancer has less than 3 availability zones"
    severity = Severity.High
    recommendation = "Add more availability zones to the Load Balancer"


def check(boto3_session: boto3.Session) -> Iterable[Violation]:
    elbv2 = boto3_session.client("elbv2")

    for page in elbv2.get_paginator("describe_load_balancers").paginate():
        for load_balancer in page["LoadBalancers"]:
            if load_balancer["Type"] != "network":
                continue

            if "SecurityGroups" not in load_balancer:
                yield Violation(
                    resource=load_balancer,
                    rule=NetworkLoadBalancerWithoutSecurityGroup,
                    message=f"Network Load Balancer {load_balancer['LoadBalancerName']} is not associated with a security group.",
                )

            if len(load_balancer["AvailabilityZones"]) != 3:
                yield Violation(
                    resource=load_balancer,
                    rule=InsufficientAvailabilityZones,
                    message=f"Network Load Balancer {load_balancer['LoadBalancerName']} has less than 3 availability zones.",
                )

            # check attributes
            attributes = {
                att["Key"]: att["Value"]
                for att in elbv2.describe_load_balancer_attributes(LoadBalancerArn=load_balancer["LoadBalancerArn"])[
                    "Attributes"
                ]
            }

            if attributes["load_balancing.cross_zone.enabled"]:
                yield Violation(
                    resource=load_balancer,
                    rule=CrossZoneLoadBalancingEnabled,
                    message=f"Network Load Balancer {load_balancer['LoadBalancerName']} has cross-zone load balancing enabled.",
                )

            if not attributes["access_logs.s3.enabled"]:
                yield Violation(
                    resource=load_balancer,
                    rule=CrossZoneLoadBalancingEnabled,
                    message=f"Network Load Balancer {load_balancer['LoadBalancerName']} has logging disabled.",
                )
