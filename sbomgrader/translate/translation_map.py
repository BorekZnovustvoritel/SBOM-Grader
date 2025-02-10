import re
from copy import copy
from pathlib import Path
from typing import Any

from jsonschema import validate

from sbomgrader.core.cached_python_loader import PythonLoader
from sbomgrader.core.definitions import (
    TRANSLATION_MAP_VALIDATION_SCHEMA_PATH,
    VAR_REF_REGEX,
)
from sbomgrader.core.documents import Document
from sbomgrader.core.enums import Implementation
from sbomgrader.core.field_resolve import (
    Variable,
    FieldResolver,
    VariableRef,
)
from sbomgrader.core.utils import get_mapping, get_path_to_var_transformers


class Data:
    def __init__(self, template: Any, variables: dict[str, Variable]):
        self.variables = variables
        self.template = template
        self.global_field_resolver = FieldResolver(
            {key: val for key, val in variables.items() if not val.is_relative}
        )
        self.relative_field_resolver = FieldResolver(
            {key: val for key, val in variables.items() if val.is_relative}
        )

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

    def _replace_string_with_vars(
        self, string: str, variable_values: dict[str, list[Any]]
    ) -> Any:
        occurrences = re.findall(VAR_REF_REGEX, string)
        if len(occurrences) == 1 and re.fullmatch(VAR_REF_REGEX, string):
            # Interpret this variable as the whole object, don't inject it into a string
            var_ref = VariableRef(occurrences[0])
            return var_ref.resolve(
                variable_values[var_ref.name], self.variables[var_ref.name]
            )
        new_string = f"{string}"
        for occurrence in occurrences:
            var_ref = VariableRef(occurrence)
            new_string = new_string.replace(
                "${" + occurrence + "}",
                var_ref.resolve(
                    variable_values[var_ref.name], self.variables[var_ref.name]
                ),
            )
        return new_string

    def _replace_vars(
        self, item: Any, raw_variable_values: dict[str, list[Any]]
    ) -> Any:
        if isinstance(item, dict):
            # Replace placeholders in string keys
            dic = copy(item)
            keys_to_change = {}
            for key, value in dic.items():
                if not isinstance(key, str):
                    continue
                new_key_val = str(
                    self._replace_string_with_vars(key, raw_variable_values)
                )
                if new_key_val != key:
                    keys_to_change[key] = new_key_val
            for old_key, new_key in keys_to_change.items():
                dic[new_key] = dic.pop(old_key)

            # Run recursively in dict values
            for key, val in dic.items():
                item[key] = self._replace_vars(val, raw_variable_values)
            return dic

        elif isinstance(item, list):
            return [self._replace_vars(i, raw_variable_values) for i in item]
        if isinstance(item, str):
            return self._replace_string_with_vars(item, raw_variable_values)
        return item

    def render(self, doc: Document, chunk_instance: dict[str, Any]) -> Any:
        resolved_variables = self.global_field_resolver.resolve_variables(doc.doc)
        resolved_variables.update(
            self.relative_field_resolver.resolve_variables(chunk_instance)
        )
        return self._replace_vars(self.template, resolved_variables)


class Chunk:
    def __init__(
        self,
        name: str,
        first_format: Implementation,
        second_format: Implementation,
        first_data: Data,
        second_data: Data,
        first_field_path: str,
        second_field_path: str,
        first_variables: dict[str, Variable] = None,
        second_variables: dict[str, Variable] = None,
    ):
        self.name = name
        self.first_format = first_format
        self.second_format = second_format
        self.first_data = first_data
        self.second_data = second_data
        self.first_field_path = first_field_path
        self.second_field_path = second_field_path
        self.first_variables = first_variables or {}
        self.second_variables = second_variables or {}
        self.first_resolver = FieldResolver(first_variables)
        self.second_resolver = FieldResolver(second_variables)

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

    def resolver_for(self, sbom_format: Implementation) -> FieldResolver:
        return getattr(self, f"{self._first_or_second(sbom_format)}resolver")

    def variables_for(self, sbom_format: Implementation) -> dict[str, Variable]:
        return getattr(self, f"{self._first_or_second(sbom_format)}variables")

    def occurrences(self, doc: Document) -> list[Any]:
        resolver = self.resolver_for(doc.implementation)
        return resolver.get_objects(doc.doc, self.field_path_for(doc.implementation))

    def convert_and_add(
        self,
        orig_doc: Document,
        new_doc: dict[str, Any],
    ) -> None:
        convert_from = orig_doc.implementation
        convert_to = (
            self.first_format
            if self.first_format != convert_from
            else self.second_format
        )

        appender_resolver = self.resolver_for(convert_to)
        append_path = self.field_path_for(convert_to)
        relevant_data = self.data_for(convert_to)
        for chunk_occurrence in self.occurrences(orig_doc):
            appender_resolver.insert_at_path(
                new_doc, append_path, relevant_data.render(orig_doc, chunk_occurrence)
            )


class TranslationMap:
    def __init__(
        self,
        first: Implementation,
        second: Implementation,
        chunks: list[Chunk],
        first_variables: dict[str, Variable] = None,
        second_variables: dict[str, Variable] = None,
    ):
        self.first = first
        self.second = second
        self.chunks = chunks
        self.first_variables = first_variables or {}
        self.second_variables = second_variables or {}
        self.first_resolver = FieldResolver(first_variables)
        self.second_resolver = FieldResolver(second_variables)

    @staticmethod
    def from_file(file: str | Path) -> "TranslationMap":
        schema_dict = get_mapping(file)
        print(schema_dict)
        print(get_mapping(TRANSLATION_MAP_VALIDATION_SCHEMA_PATH))
        validate(schema_dict, get_mapping(TRANSLATION_MAP_VALIDATION_SCHEMA_PATH))

        first = Implementation(schema_dict["first"])
        second = Implementation(schema_dict["second"])

        global_variable_def = schema_dict.get("variables", {})
        first_glob_var = global_variable_def.get("first")
        second_glob_var = global_variable_def.get("second")

        transformer_dir = get_path_to_var_transformers(file)
        first_transformer_file = None
        for filename in ("first.py", f"{first}.py"):
            f = transformer_dir / filename
            if f.exists():
                first_transformer_file = f
        first_glob_var_initialized = Variable.from_schema(
            first_glob_var, first_transformer_file
        )
        second_transformer_file = None
        for filename in ("second.py", f"{second}.py"):
            f = transformer_dir / filename
            if f.exists():
                second_transformer_file = f
        second_glob_var_initialized = Variable.from_schema(
            second_glob_var, second_transformer_file
        )

        chunks = []
        for chunk_dict in schema_dict["chunks"]:
            name = chunk_dict["name"]
            first_data = Data.from_schema_dict(chunk_dict["firstData"])
            second_data = Data.from_schema_dict(chunk_dict["secondData"])
            first_field_path = chunk_dict.get("firstFieldPath")
            second_field_path = chunk_dict.get("secondFieldPath")
            first_variables = Variable.from_schema(
                chunk_dict.get("firstVariables"), first_transformer_file
            )
            second_variables = Variable.from_schema(
                chunk_dict.get("secondVariables"), second_transformer_file
            )

            first_vars = {**first_glob_var_initialized}
            first_vars.update(first_variables)

            second_vars = {**second_glob_var_initialized}
            second_vars.update(second_variables)
            chunk = Chunk(
                name,
                first,
                second,
                first_data,
                second_data,
                first_field_path,
                second_field_path,
                first_vars,
                second_vars,
            )
            chunks.append(chunk)
        return TranslationMap(first, second, chunks)

    def convert(self, doc: Document) -> Document:
        new_data = {}
        convert_from = doc.implementation
        assert convert_from in {
            self.first,
            self.second,
        }, f"This map cannot convert from {doc.implementation}."
        for chunk in self.chunks:
            chunk.convert_and_add(doc, new_data)
        return Document(new_data)


class TransformerMapLoader(PythonLoader):
    def __init__(self, *file_references: str | Path):
        super().__init__(*file_references)
