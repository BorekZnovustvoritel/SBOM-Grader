from pathlib import Path
from typing import Any, Callable

import yaml

from sbomgrader.core.cached_python_loader import PythonLoader
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
    create_jinja_env,
    get_path_to_module,
)
from sbomgrader.translate.prune import prune, should_remove


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

    def render(
        self,
        doc: Document,
        path_to_instance: str | None = None,
        prune_empty: bool = True,
    ) -> Any:
        resolved_variables = self.field_resolver.resolve_variables(
            doc.doc, path_to_instance
        )
        dict_ = yaml.safe_load(
            self.jinja_env.from_string(self.template).render(**resolved_variables)
        )
        if prune_empty:
            dict_ = prune(dict_)
        return dict_


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
        """Returns a list of string fieldPaths where the element occurs."""
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
            rendered_data = relevant_data.render(orig_doc, chunk_occurrence)
            if not should_remove(rendered_data):
                appender_resolver.insert_at_path(new_doc, append_path, rendered_data)


class TranslationMap:
    def __init__(
        self,
        first: SBOMFormat,
        second: SBOMFormat,
        chunks: list[Chunk],
        postprocessing_funcs: dict[SBOMFormat, list[Callable]] = None,
    ):
        self.first = first
        self.second = second
        self.chunks = chunks
        self.postprocessing_funcs: dict[
            SBOMFormat, list[Callable[[dict, dict], Any]]
        ] = (postprocessing_funcs or {})

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

        first_transformer_file = get_path_to_module(file, "transformer", "first", first)
        first_glob_var_initialized = Variable.from_schema(first_glob_var)
        second_transformer_file = get_path_to_module(
            file, "transformer", "second", second
        )
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

        postprocessing_dict = {}
        for first_or_second, form in ("first", first), ("second", second):
            required_funcs = schema_dict.get(f"{first_or_second}Postprocessing", [])
            if not required_funcs:
                continue
            postprocessing_dict[form] = []
            py_file = get_path_to_module(file, "postprocessing", first_or_second, form)
            python_loader = PythonLoader(py_file)
            for func_name in required_funcs:
                postprocessing_dict[form].append(python_loader.load_func(func_name))

        return TranslationMap(first, second, chunks, postprocessing_dict)

    def _output_format(self, doc: Document) -> SBOMFormat:
        for form in self.first, self.second:
            if doc.sbom_format is not form and not any(
                doc.sbom_format == fallback for fallback in get_fallbacks(form)
            ):
                return form

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
        for postprocessing_func in self.postprocessing_funcs.get(
            self._output_format(doc), []
        ):
            res = postprocessing_func(doc.doc, new_data)
            if res:
                # If the function returns anything, make it the new data output.
                # Assume mutations were performed in-place otherwise.
                new_data = res
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
