# AWS resource scanner

This tool is used to scan AWS resources and generate a report.
When executed it will check for violations of any rules defined in the
`checks` directory.

Think of it like AWS Config checks, but better and cheaper.

## Rules

Rules are data classes that conform to the Rule protocol. They have the following attributes:
- description: A description of the rule
- severity: High, Medium or Low
- recommendation: A recommendation for resolving any violations

## Checks

Checks are defined in the `checks` directory. Each module in this directory
is loaded and if it contains a `check` function it will be executed.

The `check` function takes a `boto3` session as it's only argument. The function can
create boto3 clients and resources as needed.

The `check` function should return a list of `Violation` objects. (It may also be a generator that yields `Violation` objects)

The `Violation` object takes 3 arguments:
- resource: The resource that is in violation. This should be a `boto3` resource object.
- rule: The rule class that was violated.
- message: A message describing this violation. Be specific.

## Exclusions

Some rule violations may be expected, not actionable, or will never be fixed. In these cases
you can exclude the violation from the report. The exclusions file is a YAML file that
describe what should be excluded.

The top level of the exclusions file is a map with Rule names as keys. The values are lists
of exclusions for that Rule. Each element of that list is an exclusion rule.

The exclusion rule is tested against the resource object in the violation. If it is a match, it is excluded.

The exclusion rule value may be:
- A regex that must match that value in the resource.
- A list of regexes, one of which must match against that attribute of the resource.
- A nested map, the contents of which must match the nested field in the resource.

An example exclusions file:

```yaml
MissingPermissionBoundary:
  - RoleName: AWSServiceRole.*
```
