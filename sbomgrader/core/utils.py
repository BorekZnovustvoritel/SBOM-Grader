import json
from pathlib import Path

import yaml

from sbomgrader.core.enums import Grade


def get_mapping(schema: str | Path) -> dict | None:
    if isinstance(schema, str):
        schema = Path(schema)
    if isinstance(schema, Path):
        if not schema.exists():
            return None
        with open(schema) as stream:
            if schema.name.endswith(".json"):
                doc = json.load(stream)
            elif schema.name.endswith(".yml") or schema.name.endswith(".yaml"):
                doc = yaml.safe_load(stream)
            else:
                doc = {}
            return doc


def get_path_to_implementations(schema_path: str | Path):
    if isinstance(schema_path, str):
        schema_path = Path(schema_path)
    return schema_path.parent / "implementations" / schema_path.name.rsplit(".", 1)[0]


def validation_passed(validation_grade: Grade, minimal_grade: Grade) -> bool:
    # minimal is less than or equal to validation
    return Grade.compare(validation_grade, minimal_grade) < 1
