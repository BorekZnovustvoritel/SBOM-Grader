from pathlib import Path
from typing import Any

import yaml

from sbomgrader.core.definitions import (
    TRANSLATION_MAP_VALIDATION_SCHEMA_PATH,
)
from sbomgrader.core.documents import Document
from sbomgrader.core.field_resolve import (
    Variable,
    FieldResolver,
)
from sbomgrader.core.formats import (
    SBOMFormat,
    get_fallbacks,
    SBOM_FORMAT_DEFINITION_MAPPING,
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
        first_format: SBOMFormat,
        second_format: SBOMFormat,
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

    def _first_or_second(self, sbom_format: SBOMFormat) -> str:
        if sbom_format == self.first_format or self.first_format in get_fallbacks(
            sbom_format
        ):
            return "first_"
        if sbom_format == self.second_format or self.second_format in get_fallbacks(
            sbom_format
        ):
            return "second_"
        raise ValueError(f"This map does not support format {sbom_format}!")

    def _other(self, sbom_format: SBOMFormat) -> SBOMFormat:
        if sbom_format == self.first_format:
            return self.second_format
        if sbom_format == self.second_format:
            return self.first_format
        raise ValueError(f"This map does not support format {sbom_format}!")

    def data_for(self, sbom_format: SBOMFormat) -> Data:
        return getattr(self, f"{self._first_or_second(sbom_format)}data")

    def field_path_for(self, sbom_format: SBOMFormat) -> str | None:
        return getattr(self, f"{self._first_or_second(sbom_format)}field_path")

    def resolver_for(self, sbom_format: SBOMFormat) -> FieldResolver:
        return getattr(self, f"{self._first_or_second(sbom_format)}resolver")

    def occurrences(self, doc: Document) -> list[str]:
        resolver = self.resolver_for(doc.sbom_format)
        return resolver.get_paths(doc.doc, self.field_path_for(doc.sbom_format), {})

    def convert_and_add(
        self,
        orig_doc: Document,
        new_doc: dict[str, Any],
    ) -> None:
        """Mutates the new_doc with the occurrences of this chunk."""
        convert_from = orig_doc.sbom_format
        if convert_from not in {self.first_format, self.second_format}:
            fallbacks = get_fallbacks(orig_doc.sbom_format)
            if self.first_format in fallbacks:
                convert_from = self.first_format
            elif self.second_format in fallbacks:
                convert_from = self.second_format
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
        first: SBOMFormat,
        second: SBOMFormat,
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

    @property
    def first_with_fallbacks(self) -> set[SBOMFormat]:
        return {self.first, *get_fallbacks(self.first)}

    @property
    def second_with_fallbacks(self) -> set[SBOMFormat]:
        return {self.second, *get_fallbacks(self.second)}

    @staticmethod
    def from_file(file: str | Path) -> "TranslationMap":
        schema_dict = get_mapping(file, TRANSLATION_MAP_VALIDATION_SCHEMA_PATH)

        first = SBOMFormat(schema_dict["first"])
        second = SBOMFormat(schema_dict["second"])

        first_glob_var = schema_dict.get("firstVariables")
        second_glob_var = schema_dict.get("secondVariables")

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

    def convert(
        self, doc: Document, override_format: SBOMFormat | None = None
    ) -> Document:
        """Converts document to a format"""
        new_data = {}
        assert doc.sbom_format in (
            self.first,
            self.second,
        ) or any(
            fallback
            in (
                self.first,
                self.second,
            )
            for fallback in doc.sbom_format_fallback
        ), f"This map cannot convert from {doc.sbom_format}."
        for chunk in self.chunks:
            chunk.convert_and_add(doc, new_data)
        if override_format is not None:
            new_data.update(SBOM_FORMAT_DEFINITION_MAPPING[override_format])
        return Document(new_data)

    def is_exact_map(self, from_: SBOMFormat, to: SBOMFormat) -> bool:
        """Determine if this map converts between these two formats."""
        return ((from_ is self.first) and (to is self.second)) or (
            (from_ is self.second) and (to is self.first)
        )

    def is_suitable_map(self, from_: SBOMFormat, to: SBOMFormat) -> bool:
        """Determine if the map is able to convert between formats including fallbacks."""
        if self.is_exact_map(from_, to):
            return True
        from_fallbacks = get_fallbacks(from_)
        from_fallbacks.add(from_)
        to_fallbacks = get_fallbacks(to)
        to_fallbacks.add(to)
        return (self.first in from_fallbacks and self.second in to_fallbacks) or (
            self.first in to_fallbacks and self.second in from_fallbacks
        )
