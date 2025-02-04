import re
from pathlib import Path
from typing import Any, Callable

from black.trans import defaultdict
from jsonschema import validate

from sbomgrader.core.cached_python_loader import PythonLoader
from sbomgrader.core.definitions import TRANSLATION_MAP_VALIDATION_SCHEMA_PATH
from sbomgrader.core.documents import Document
from sbomgrader.core.enums import Implementation
from sbomgrader.core.field_resolve import Variable, FieldResolver
from sbomgrader.core.utils import get_mapping


class Data:
    def __init__(self, template: Any, variables: dict[str, Variable]):
        self.variables = variables
        self.template = template
        self.field_resolver = FieldResolver(variables)
        self.__fields_with_vars: dict[str, list[Any]] = defaultdict(list)

    @staticmethod
    def from_schema_dict(dictionary: dict[str, Any]) -> "Data":
        variable_list = dictionary.get("variables") or []
        variables = {}
        for var_dict in variable_list:
            var_name = var_dict["name"]
            var_field_path = var_dict["fieldPath"]
            var_map = var_dict.get("map")
            func_name = var_dict.get("funcTransform")
            variables[var_name] = Variable(var_name, var_field_path, var_map, func_name)
        template = dictionary["template"]
        return Data(template, variables)

    def _scan_for_vars(self, item: Any):
        if isinstance(item, str) and (
            occurrences := re.findall(r"\$\{(?P<varname>\S+)}", item)
        ):
            for occ in occurrences:
                self.__fields_with_vars[occ].append(item)

    @staticmethod
    def _scout_data(data, func: Callable[[Any], Any]) -> Any:
        if isinstance(data, list):
            for item in data:
                Data._scout_data(item, func)
        elif isinstance(data, dict):
            for item in data.values():
                Data._scout_data(item, func)
        else:
            func(data)

    @property
    def contained_variable_names(self) -> list[str]:
        if not self.__fields_with_vars:
            self._scout_data(self.template, self._scan_for_vars)
        return list(self.__fields_with_vars.keys())

    def render(self, doc: Document) -> Any:
        var_names = self.contained_variable_names
        for var_name in var_names:
            self.field_resolver.resolve_variables(doc.doc)


class Chunk:
    def __init__(
        self, name: str, first_format: Implementation, second_format: Implementation, first_data: Data, second_data: Data, first_field_path: str = None, second_field_path: str = None
    ):
        self.name = name
        self.first_format = first_format
        self.second_format = second_format
        self.first_data = first_data
        self.second_data = second_data
        self.first_field_path = first_field_path
        self.second_field_path = second_field_path


    def _first_or_second(self, sbom_format: Implementation) -> str:
        if sbom_format == self.first_format:
            return "first_"
        if sbom_format == self.second_format:
            return "second_"
        raise ValueError(f"This map does not support format {sbom_format}!")


    def data_for(self, sbom_format: Implementation) -> Data:
        return getattr(self, f"{self._first_or_second(sbom_format)}data")

    def field_path_for(self, sbom_format: Implementation) -> str | None:
        return getattr(self, f"{self._first_or_second(sbom_format)}field_path")

    def convert(self, doc: Document) -> Any:
        convert_to = doc.implementation
        convert_from = self.first_format if self.first_format != convert_to else self.second_format

        relevant_data = self.data_for(convert_to)
        return relevant_data.render(doc)

class TranslationMap:
    def __init__(
        self, first: Implementation, second: Implementation, chunks: list[Chunk]
    ):
        self.first = first
        self.second = second
        self.chunks = chunks

    @staticmethod
    def from_file(file: str | Path) -> "TranslationMap":
        schema_dict = get_mapping(file)
        validate(schema_dict, get_mapping(TRANSLATION_MAP_VALIDATION_SCHEMA_PATH))

        first = Implementation(schema_dict["first"])
        second = Implementation(schema_dict["second"])
        chunks = []
        for chunk_dict in schema_dict["chunks"]:
            name = chunk_dict["name"]
            first_data = Data.from_schema_dict(chunk_dict["firstData"])
            second_data = chunk_dict["secondData"]
            first_field_path = chunk_dict.get("firstFieldPath")
            second_field_path = chunk_dict.get("secondFieldPath")
            chunk = Chunk(name, first, second, first_data, second_data, first_field_path, second_field_path)
            chunks.append(chunk)
        return TranslationMap(first, second, chunks)

    def convert(self, doc: Document) -> Document:
        for chunk in self.chunks:
            chunk.convert(doc)


class TransformerMapLoader(PythonLoader):
    def __init__(self, *file_references: str | Path):
        super().__init__(*file_references)
