import enum
from pathlib import Path
from typing import Any

from sbomgrader.core.definitions import FORMAT_VALIDATION_SCHEMA_PATH, FORMAT_FILE_PATH
from sbomgrader.core.utils import get_mapping


def _load_formats_file(
    path: str | Path,
) -> tuple[
    type[enum.Enum], dict[enum.Enum, dict[str, Any]], dict[enum.Enum, set[enum.Enum]]
]:
    format_dict = get_mapping(path, FORMAT_VALIDATION_SCHEMA_PATH)
    enum_dict = {}
    expected_fields_dict = {}
    fallback_dict = {}
    for format_def in format_dict["formats"]:
        name = format_def["name"]
        value = format_def["value"]
        enum_dict[name] = value

    ans_enum = enum.Enum("Formats", enum_dict)

    for format_def in format_dict["formats"]:
        name = format_def["name"]
        expected_structure = format_def["expectedStructure"]
        fallback = format_def.get("fallback", [])

        enum_instance = getattr(ans_enum, name)
        expected_fields_dict[enum_instance] = expected_structure
        fallback_dict[enum_instance] = {getattr(ans_enum, form) for form in fallback}
    return ans_enum, expected_fields_dict, fallback_dict


SBOMFormat, SBOM_FORMAT_DEFINITION_MAPPING, SBOM_FORMAT_FALLBACK = _load_formats_file(
    FORMAT_FILE_PATH
)


def get_fallbacks(format_: SBOMFormat) -> set[SBOMFormat]:
    """Get formats that are considered a fallback for the provided format."""
    return SBOM_FORMAT_FALLBACK[format_]
