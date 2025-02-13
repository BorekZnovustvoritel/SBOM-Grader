from pathlib import Path
from typing import Any

import yaml
from jsonschema import validate

from sbomgrader.core.definitions import (
    TRANSLATION_MAP_VALIDATION_SCHEMA_PATH,
)
from sbomgrader.core.documents import Document
from sbomgrader.core.enums import Implementation
from sbomgrader.core.field_resolve import (
    Variable,
    FieldResolver,
)
from sbomgrader.core.utils import (
    get_mapping,
    get_path_to_var_transformers,
    create_jinja_env,
)


class Data:
    def __init__(
        self,
        template: str,
        variables: dict[str, Variable],
        transformer_path: Path | None = None,
    ):
        self.variables = variables
        self.template = template
        self.field_resolver = FieldResolver(variables)
        self.transformer_path = transformer_path
        self.jinja_env = create_jinja_env(self.transformer_path)

    def render(self, doc: Document, path_to_instance: str | None = None) -> Any:
        resolved_variables = self.field_resolver.resolve_variables(
            doc.doc, path_to_instance
        )
        return yaml.safe_load(
            self.jinja_env.from_string(self.template).render(**resolved_variables)
        )


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
        self.first_resolver = FieldResolver(self.first_variables)
        self.second_resolver = FieldResolver(self.second_variables)

    def _first_or_second(self, sbom_format: Implementation) -> str:
        if sbom_format == self.first_format:
            return "first_"
        if sbom_format == self.second_format:
            return "second_"
        raise ValueError(f"This map does not support format {sbom_format}!")

    def _other(self, sbom_format: Implementation) -> Implementation:
        if sbom_format == self.first_format:
            return self.second_format
        if sbom_format == self.second_format:
            return self.first_format
        raise ValueError(f"This map does not support format {sbom_format}!")

    def data_for(self, sbom_format: Implementation) -> Data:
        return getattr(self, f"{self._first_or_second(sbom_format)}data")

    def field_path_for(self, sbom_format: Implementation) -> str | None:
        return getattr(self, f"{self._first_or_second(sbom_format)}field_path")

    def resolver_for(self, sbom_format: Implementation) -> FieldResolver:
        return getattr(self, f"{self._first_or_second(sbom_format)}resolver")

    def occurrences(self, doc: Document) -> list[str]:
        resolver = self.resolver_for(doc.implementation)
        return resolver.get_paths(doc.doc, self.field_path_for(doc.implementation), {})

    def convert_and_add(
        self,
        orig_doc: Document,
        new_doc: dict[str, Any],
    ) -> None:
        """Mutates the new_doc with the occurrences of this chunk."""
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
        validate(schema_dict, get_mapping(TRANSLATION_MAP_VALIDATION_SCHEMA_PATH))

        first = Implementation(schema_dict["first"])
        second = Implementation(schema_dict["second"])

        global_variable_def = schema_dict.get("variables", {})
        first_glob_var = global_variable_def.get("first")
        second_glob_var = global_variable_def.get("second")

        transformer_dir = get_path_to_var_transformers(file)
        first_transformer_file = None
        for filename in ("first.py", f"{first.value}.py"):
            f = transformer_dir / filename
            if f.exists():
                first_transformer_file = f
                break
        first_glob_var_initialized = Variable.from_schema(first_glob_var)
        second_transformer_file = None
        for filename in ("second.py", f"{second.value}.py"):
            f = transformer_dir / filename
            if f.exists():
                second_transformer_file = f
                break
        second_glob_var_initialized = Variable.from_schema(second_glob_var)

        chunks = []
        for chunk_dict in schema_dict["chunks"]:
            name = chunk_dict["name"]

            first_field_path = chunk_dict.get("firstFieldPath")
            second_field_path = chunk_dict.get("secondFieldPath")
            first_variables = Variable.from_schema(chunk_dict.get("firstVariables"))
            second_variables = Variable.from_schema(chunk_dict.get("secondVariables"))

            first_vars = {**first_glob_var_initialized}
            first_vars.update(first_variables)

            second_vars = {**second_glob_var_initialized}
            second_vars.update(second_variables)

            first_data = Data(
                chunk_dict["firstData"], second_vars, second_transformer_file
            )
            second_data = Data(
                chunk_dict["secondData"], first_vars, first_transformer_file
            )

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
