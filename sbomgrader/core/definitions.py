import re
from pathlib import Path
from typing import Sized

from sbomgrader.core.enums import Implementation

ROOT_DIR: Path = Path(__file__).parent.parent
RULESET_DIR = ROOT_DIR / "rulesets"
COOKBOOKS_DIR = ROOT_DIR / "cookbooks"
IMPLEMENTATION_DIR_NAME = "specification_rules"
RULESET_VALIDATION_SCHEMA_PATH = ROOT_DIR / "rulesets" / "schema" / "rule_schema.yml"
COOKBOOK_VALIDATION_SCHEMA_PATH = (
    ROOT_DIR / "cookbooks" / "schema" / "cookbook_schema.yml"
)

SBOM_FORMAT_DEFINITION_MAPPING = {
    Implementation.SPDX23: {"spdxVersion": "SPDX-2.3"},
    Implementation.CYCLONEDX15: {"bomFormat": "CycloneDX", "specVersion": "1.5"},
}
MAX_ITEM_PREVIEW_LENGTH = 50
START_PREVIEW_CHARS = 25
END_PREVIEW_CHARS = 20


class __FieldNotPresent:
    def __repr__(self):
        return "Field not present."

    def get(self, *_):
        return self


FIELD_NOT_PRESENT = __FieldNotPresent()


class FieldNotPresentError(ValueError):
    pass


operation_map = {
    "eq": lambda expected, actual: expected == actual,
    "neq": lambda expected, actual: expected != actual,
    "in": lambda expected, actual: actual in expected,
    "not_in": lambda expected, actual: actual not in expected,
    "str_startswith": lambda expected, actual: isinstance(actual, str)
    and actual.startswith(expected),
    "str_endswith": lambda expected, actual: isinstance(actual, str)
    and actual.endswith(expected),
    "str_contains": lambda expected, actual: isinstance(actual, str)
    and expected in actual,
    "str_matches_regex": lambda expected, actual: isinstance(actual, str)
    and bool(re.match(expected, actual)),
    "length_eq": lambda expected, actual: isinstance(actual, Sized)
    and len(actual) == expected,
    "length_gt": lambda expected, actual: isinstance(actual, Sized)
    and len(actual) > expected,
    "length_lt": lambda expected, actual: isinstance(actual, Sized)
    and len(actual) < expected,
    "func_name": None,
}
