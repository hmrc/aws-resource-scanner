import importlib
import os
import sys
from typing import Iterable

import boto3

from aws_resource_scanner.exclusions import is_violation_excluded, load_exclusions
from aws_resource_scanner.types import CheckFunction, Violation


def find_checks() -> Iterable[CheckFunction]:
    for module_path in os.listdir("src/aws_resource_scanner/checks"):
        if not module_path.endswith(".py"):
            continue

        module_name = module_path[:-3]

        try:
            check_module = importlib.import_module(f"aws_resource_scanner.checks.{module_name}")

            if hasattr(check_module, "check") and callable(check_module.check):
                yield check_module.check

        except ImportError as e:
            sys.stderr.write(f"Failed to import check module: {module_name}\n{str(e)}")


def run_checks(checks: Iterable[CheckFunction]) -> Iterable[Violation]:
    boto3_session = boto3.Session(region_name="eu-west-2")

    for check in checks:
        yield from check(boto3_session)


def main() -> None:
    exclusion_rules = load_exclusions()
    checks = find_checks()

    sys.stdout.write("Running checks...\n")

    for violation in run_checks(checks):
        if is_violation_excluded(violation, exclusion_rules.get(violation.rule.__class__.__name__, [])):
            pass
        else:
            print(violation)


if __name__ == "__main__":
    main()
