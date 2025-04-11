import datetime
import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Literal

import jinja2
import yaml
from jsonschema import validate
from yaml import YAMLError

from sbomgrader.core.cached_python_loader import PythonLoader
from sbomgrader.core.definitions import FIELD_NOT_PRESENT, TIME_ISO_FORMAT_STRING
from sbomgrader.core.enums import Grade
from sbomgrader import __version__ as version


def is_mapping(file: str | Path) -> bool:
    name = file if isinstance(file, str) else file.name
    return name.endswith(".json") or name.endswith(".yml") or name.endswith(".yaml")


def get_mapping(
    schema: str | Path, validation_schema: str | Path | None = None
) -> dict | None:
    """
    Load a mapping from a JSON/YAML file, optionally validate it with a JSONSchema.
    This function can also load the mapping from a string.

    :argument schema: The mapping to load. Can hold the string-serialized mapping
    or a path to a JSON or YAML file.
    :argument validation_schema: The JSONSchema used for validation of the first mapping.
    """
    doc = {}
    try:
        if isinstance(schema, str):
            if schema.startswith("---"):
                doc = yaml.safe_load(schema)
            elif schema.startswith("{"):
                doc = json.loads(schema)
            else:
                schema = Path(schema)
    except (JSONDecodeError, YAMLError):
        # Some people maybe really do name
        # their files with names starting with '{'
        # or '---'
        schema = Path(schema)

    if isinstance(schema, Path):
        if not schema.exists() or not is_mapping(schema):
            return None
        with open(schema) as stream:
            if schema.name.endswith(".json"):
                doc = json.load(stream)
            elif schema.name.endswith(".yml") or schema.name.endswith(".yaml"):
                doc = yaml.safe_load(stream)

    if not doc:
        raise ValueError(f"Invalid mapping: '{schema}'.")
    if validation_schema:
        validate(doc, get_mapping(validation_schema))
    return doc


def get_path_to_implementations(schema_path: str | Path) -> Path:
    """Get a relative path to the module containing test implementation functions of this Rule Set."""
    if isinstance(schema_path, str):
        schema_path = Path(schema_path)
    return schema_path.parent / "implementations" / schema_path.name.rsplit(".", 1)[0]


def get_path_to_var_transformers(schema_path: str | Path) -> Path:
    """Get a relative path to the module containing transformer functions of this Translation Map."""
    if isinstance(schema_path, str):
        schema_path = Path(schema_path)
    return schema_path.parent / "transformers" / schema_path.name.split(".", 1)[0]


def get_path_to_preprocessing(schema_path: str | Path) -> Path:
    """Get a relative path to the module containing preprocessing functions of this Translation Map."""
    if isinstance(schema_path, str):
        schema_path = Path(schema_path)
    return schema_path.parent / "preprocessing" / schema_path.name.split(".", 1)[0]


def get_path_to_postprocessing(schema_path: str | Path) -> Path:
    """Get a relative path to the module containing postprocessing functions of this Translation Map."""
    if isinstance(schema_path, str):
        schema_path = Path(schema_path)
    return schema_path.parent / "postprocessing" / schema_path.name.split(".", 1)[0]


def get_path_to_module(
    schema_path: str | Path,
    kind: Literal["Transformer", "Preprocessing", "Postprocessing"],
    first_or_second: Literal["first", "second"],
    sbom_format: "sbomgrader.core.formats.SBOMFormat,",
):
    """
    Get a path to a module related to the translation map located
    in the file at `schema_path`.
    This loads either transformers, preprocessors or postprocessors.
    :argument schema_path: Path to Translation Map
    :argument kind: Type of module file (what type of function is searched for)
    :argument first_or_second: Do we search for the file related to `first`
    or `second` SBOM Format?
    :argument sbom_format: What is the SBOM Format this module relates to?
    """
    map_kind_to_module_function = {
        "Transformer": get_path_to_var_transformers,
        "Preprocessing": get_path_to_preprocessing,
        "Postprocessing": get_path_to_postprocessing,
    }
    mod_func = map_kind_to_module_function.get(kind)
    if not mod_func:
        raise ValueError(f"Wrong kind value: {kind}")
    mod_dir = mod_func(schema_path)
    file = None
    for filename in (
        f"{first_or_second}.py",
        f"{sbom_format.value}.py",
    ):
        file_path = mod_dir / filename
        if file_path.exists():
            file = file_path
            break
    return file


def validation_passed(validation_grade: Grade, minimal_grade: Grade) -> bool:
    """Did the SBOM get a good enough grade?"""
    # minimal is less than or equal to validation
    return Grade.compare(validation_grade, minimal_grade) < 1


def create_jinja_env(transformer_file: Path | None = None) -> jinja2.Environment:
    """Creates a Jinja2 environment with additional filters. Used in Translation Maps."""
    env = jinja2.Environment()
    env.globals["DATETIME_NOW"] = datetime.datetime.now(datetime.UTC).strftime(
        TIME_ISO_FORMAT_STRING
    )
    env.globals["SBOMGRADER_SIGNATURE"] = f"SBOMGrader {version}"

    def unwrap(input_list: list[Any]) -> Any:
        """Return the first element of a list."""
        try:
            return next(iter(input_list), "")
        except TypeError:
            return ""

    def sliced(
        input_list: list[Any] | str, start: int = 0, end: int = None
    ) -> list[Any] | str:
        """Return a slice of a list or a string."""
        if not isinstance(input_list, list) and not isinstance(input_list, str):
            return []
        return input_list[start:end]

    def fallback(first: list[Any], *other: list[Any]) -> list[Any]:
        """Return the first non-empty variable value (non-empty list)."""
        if first and first is not FIELD_NOT_PRESENT:
            return first
        for o in other:
            if o and o is not FIELD_NOT_PRESENT:
                return o
        return []

    env.filters["unwrap"] = unwrap
    env.filters["slice"] = sliced
    env.filters["fallback"] = fallback
    if transformer_file and transformer_file.exists():

        def func(item: Any, name: str, **kwargs) -> Any:
            python_loader = PythonLoader(transformer_file)
            return python_loader.load_func(name)(item, **kwargs)

        env.filters["func"] = func
    return env
