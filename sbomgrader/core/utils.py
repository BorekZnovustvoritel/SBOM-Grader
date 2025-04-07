import datetime
import json
from pathlib import Path
from typing import Any, Literal

import jinja2
import yaml
from jsonschema import validate

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


def get_path_to_preprocessing(schema_path: str | Path) -> Path:
    if isinstance(schema_path, str):
        schema_path = Path(schema_path)
    return schema_path.parent / "preprocessing" / schema_path.name.split(".", 1)[0]


def get_path_to_postprocessing(schema_path: str | Path) -> Path:
    if isinstance(schema_path, str):
        schema_path = Path(schema_path)
    return schema_path.parent / "postprocessing" / schema_path.name.split(".", 1)[0]


def get_path_to_module(
    schema_path: str | Path,
    kind: Literal["transformer", "preprocessing", "postprocessing"],
    first_or_second: Literal["first", "second"],
    sbom_format: "sbomgrader.core.formats.SBOMFormat,",
):
    map_ = {
        "transformer": get_path_to_var_transformers,
        "preprocessing": get_path_to_preprocessing,
        "postprocessing": get_path_to_postprocessing,
    }
    mod_func = map_.get(kind)
    if not mod_func:
        raise ValueError(f"Wrong kind value: {kind}")
    mod_dir = mod_func(schema_path)
    file = None
    for filename in (
        f"{first_or_second}.py",
        f"{sbom_format.value}.py",
    ):
        f = mod_dir / filename
        if f.exists():
            file = f
            break
    return file


def validation_passed(validation_grade: Grade, minimal_grade: Grade) -> bool:
    # minimal is less than or equal to validation
    return Grade.compare(validation_grade, minimal_grade) < 1


def create_jinja_env(transformer_file: Path | None = None) -> jinja2.Environment:
    env = jinja2.Environment()
    env.globals["DATETIME_NOW"] = datetime.datetime.now(datetime.UTC).strftime(
        TIME_ISO_FORMAT_STRING
    )
    env.globals["SBOMGRADER_SIGNATURE"] = f"SBOMGrader {version}"

    def unwrap(list_: list[Any]) -> Any:
        try:
            return next(iter(list_), "")
        except TypeError:
            return ""

    def sliced(
        list_: list[Any] | str, start: int = 0, end: int = None
    ) -> list[Any] | str:
        if not isinstance(list_, list) and not isinstance(list_, str):
            return []
        return list_[start:end]

    def fallback(first: list[Any], *other: list[Any]) -> list[Any]:
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
