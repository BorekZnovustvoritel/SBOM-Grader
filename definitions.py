import json
from enum import Enum
from pathlib import Path

import yaml

ROOT_DIR: Path = Path(__file__).parent
# RULES_DIR_NAME = "rules"
RULESET_DIR = ROOT_DIR / "rulesets"
IMPLEMENTATION_DIR_NAME = "specification_rules"
# IMPLEMENTATION_DIR = ROOT_DIR / RULES_DIR_NAME / IMPLEMENTATION_DIR_NAME
RULESET_VALIDATION_SCHEMA_PATH = ROOT_DIR / "rulesets" / "schema" / "rule_schema.yml"


class Implementation(Enum):
    SPDX23 = "spdx23"


SBOM_FORMAT_DEFINITION_MAPPING = {Implementation.SPDX23: {"spdxVersion": "SPDX-2.3"}}


def get_mapping(schema: str | Path) -> dict | None:
    if isinstance(schema, str):
        schema = Path(schema)
    if isinstance(schema, Path):
        if not schema.exists():
            return None
        with open(schema) as stream:
            if schema.name.endswith(".json"):
                doc = json.load(stream)
            elif schema.name.endswith("yml") or schema.name.endswith("yaml"):
                doc = yaml.safe_load(stream)
        return doc


def get_path_to_implementations(schema_path: str | Path):
    if isinstance(schema_path, str):
        schema_path = Path(schema_path)
    return schema_path.parent / "implementations" / schema_path.name.rsplit(".", 1)[0]


class RuleForce(Enum):
    MAY = "MAY"
    SHOULD = "SHOULD"
    MUST = "MUST"
