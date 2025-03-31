import re
from pathlib import Path
from typing import Sized


ROOT_DIR: Path = Path(__file__).parent.parent
RULESET_DIR = ROOT_DIR / "rulesets"
COOKBOOKS_DIR = ROOT_DIR / "cookbooks"
IMPLEMENTATION_DIR_NAME = "specification_rules"
RULESET_VALIDATION_SCHEMA_PATH = ROOT_DIR / "rulesets" / "schema" / "rule_schema.yml"
COOKBOOK_VALIDATION_SCHEMA_PATH = (
    ROOT_DIR / "cookbooks" / "schema" / "cookbook_schema.yml"
)
TRANSLATION_MAP_DIR = ROOT_DIR / "translation_maps"
TRANSLATION_MAP_VALIDATION_SCHEMA_PATH = (
    TRANSLATION_MAP_DIR / "schema" / "translation_map_schema.yml"
)
FORMAT_FILE_PATH = ROOT_DIR / "formats" / "formats.yml"
FORMAT_VALIDATION_SCHEMA_PATH = ROOT_DIR / "formats" / "schema" / "formats_schema.yml"
COOKBOOK_EXTENSIONS = {".yml", ".yaml"}

TIME_ISO_FORMAT_STRING = "%Y-%m-%dT%H:%M:%SZ"

MAX_ITEM_PREVIEW_LENGTH = 50
START_PREVIEW_CHARS = 25
END_PREVIEW_CHARS = 20
VAR_REF_REGEX = r"\${(?P<var_id>[^}]+)}"


class __FieldNotPresent:
    string_repr = "FIELD_NOT_PRESENT"

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
