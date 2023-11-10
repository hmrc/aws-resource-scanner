import re
from typing import Any

import yaml

from aws_resource_scanner.types import Violation

RuleName = str
ExclusionRule = dict[str, Any]


def load_exclusions() -> dict[RuleName, list[ExclusionRule]]:
    with open("exclusions.yaml") as f:
        exclusions = yaml.load(f, Loader=yaml.FullLoader)
        assert isinstance(exclusions, dict)
        return exclusions


def exclusion_rule_matches(exclusion_rule: ExclusionRule, resource: dict[str, Any]) -> bool:
    """
    Does an exclusion rule match a resource?

    Every field in the exclusion must match the corresponding field in the resource.
    If the exclusion field is a string, it is a regex that must match.
    If the exclusion field is a dict, it is a nested exclusion that must match the nested field of the resource.
    """

    for key, exclusion_value in exclusion_rule.items():
        if key not in resource:
            return False

        if isinstance(exclusion_value, str):
            if not re.match(exclusion_value, resource[key]):
                return False

        elif isinstance(exclusion_value, dict):
            if not exclusion_rule_matches(exclusion_value, resource[key]):
                return False

    # Every field matched
    return True


def is_excluded(violation: Violation, exclusion_rule: ExclusionRule) -> bool:
    """
    Is a violation excluded by this exclusion rule
    """

    return exclusion_rule_matches(exclusion_rule, violation.resource)


def is_violation_excluded(violation: Violation, exclusion_rules: list[ExclusionRule]) -> bool:
    """
    Is a violation excluded by any of the exclusion rules?
    """
    for exclusion_rule in exclusion_rules:
        if is_excluded(violation, exclusion_rule):
            # This violation should be excluded
            return True

    return False
