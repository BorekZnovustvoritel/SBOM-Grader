import json
from pathlib import Path

import jinja2
import yaml
from jsonschema import validate

from sbomgrader.core.cached_python_loader import PythonLoader
from sbomgrader.core.enums import Grade


def is_mapping(file: str | Path) -> bool:
    name = file if isinstance(file, str) else file.name
    return name.endswith(".json") or name.endswith(".yml") or name.endswith(".yaml")


def get_mapping(
    schema: str | Path, validation_schema: str | Path | None = None
) -> dict | None:
    if isinstance(schema, str):
        schema = Path(schema)
    if isinstance(schema, Path):
        if not schema.exists() or not is_mapping(schema):
            return None
        with open(schema) as stream:
            if schema.name.endswith(".json"):
                doc = json.load(stream)
            elif schema.name.endswith(".yml") or schema.name.endswith(".yaml"):
                doc = yaml.safe_load(stream)
            else:
                doc = {}
    if validation_schema:
        validate(doc, get_mapping(validation_schema))
    return doc


def get_path_to_implementations(schema_path: str | Path) -> Path:
    if isinstance(schema_path, str):
        schema_path = Path(schema_path)
    return schema_path.parent / "implementations" / schema_path.name.rsplit(".", 1)[0]


def get_path_to_var_transformers(schema_path: str | Path) -> Path:
    if isinstance(schema_path, str):
        schema_path = Path(schema_path)
    return schema_path.parent / "transformers" / schema_path.name.split(".", 1)[0]


def validation_passed(validation_grade: Grade, minimal_grade: Grade) -> bool:
    # minimal is less than or equal to validation
    return Grade.compare(validation_grade, minimal_grade) < 1


def create_jinja_env(transformer_file: Path | None = None) -> jinja2.Environment:
    env = jinja2.Environment()
    env.filters["unwrap"] = lambda x: next(iter(x), None)
    if transformer_file and transformer_file.exists():
        python_loader = PythonLoader(transformer_file)
        env.filters["func"] = lambda x, name: python_loader.load_func(name)(x)
    return env
