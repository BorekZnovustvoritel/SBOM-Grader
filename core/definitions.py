from pathlib import Path

from core.enums import Implementation

ROOT_DIR: Path = Path(__file__).parent.parent
RULESET_DIR = ROOT_DIR / "rulesets"
COOKBOOKS_DIR = ROOT_DIR / "cookbooks"
IMPLEMENTATION_DIR_NAME = "specification_rules"
RULESET_VALIDATION_SCHEMA_PATH = ROOT_DIR / "rulesets" / "schema" / "rule_schema.yml"
COOKBOOK_VALIDATION_SCHEMA_PATH = (
    ROOT_DIR / "cookbooks" / "schema" / "cookbook_schema.yml"
)

SBOM_FORMAT_DEFINITION_MAPPING = {Implementation.SPDX23: {"spdxVersion": "SPDX-2.3"}}


class __FieldNotPresent:
    def __repr__(self):
        return "Field not present."

    def get(self, *_):
        return self


FIELD_NOT_PRESENT = __FieldNotPresent()
