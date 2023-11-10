from typing import Any, Callable, Iterable, Optional, Protocol

import boto3


class Severity:
    High = "HIGH"
    Medium = "MEDIUM"
    Low = "LOW"


class Rule(Protocol):
    description: str
    severity: str
    recommendation: Optional[str]


class Violation:
    # The resource that is violating the rule.
    resource: dict[str, Any]

    # The rule that is being violated.
    rule: Rule

    # A message that explains this specific violation.
    message: str

    def __init__(self, resource: dict[str, Any], rule: Rule | Any, message: str):
        self.resource = resource
        self.rule = rule() if callable(rule) else rule
        self.message = message

    def __repr__(self) -> str:
        return f"Violation(rule={self.rule.__class__.__name__}, message={self.message!r})"

    def __str__(self) -> str:
        return f"{self.rule.__class__.__name__}: {self.message}"


CheckFunction = Callable[[boto3.Session], Iterable[Violation]]
