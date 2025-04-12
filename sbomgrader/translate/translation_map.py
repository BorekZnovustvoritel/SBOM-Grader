from functools import cached_property
from pathlib import Path
from typing import Any, Callable

import yaml
from jinja2 import meta

from sbomgrader.core.cached_python_loader import PythonLoader
from sbomgrader.core.definitions import (
    TRANSLATION_MAP_VALIDATION_SCHEMA_PATH,
    FIELD_NOT_PRESENT,
)
from sbomgrader.core.documents import Document
from sbomgrader.core.field_resolve import (
    Variable,
    FieldResolver,
    QueryParser,
    PathParser,
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
    """The data to render in the new document."""

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
        self._variables_needed_in_template = self._get_vars_for_template()

    def render(
        self,
        whole_doc: Document,
        path_to_instance: str | None,
        instance_value: Any,
        prune_empty: bool = True,
        globally_resolved_variables: dict[str, list[Any]] = None,
    ) -> Any:
        """
        Renders a Jinja2 expression according to variables
        populated from the document.
        """
        globally_resolved_variables = globally_resolved_variables or {}
        already_resolved_vars = {**globally_resolved_variables}
        relative_resolver = FieldResolver(
            {
                var_name: var.without_relative_start
                for var_name, var in self.field_resolver.fully_relative_variables.items()
            }
        )
        already_resolved_vars.update(
            relative_resolver.resolve_variables(
                instance_value, already_resolved_variables=already_resolved_vars
            )
        )
        resolved_variables = self.field_resolver.resolve_variables(
            whole_doc.doc,
            path_to_instance,
            already_resolved_variables=already_resolved_vars,
            variables_needed=self._variables_needed_in_template,
        )
        # Remove invalid values
        for var_name, var_val in resolved_variables.items():
            resolved_variables[var_name] = [
                val for val in var_val if val is not FIELD_NOT_PRESENT
            ]
        data_value = yaml.safe_load(
            self.jinja_env.from_string(self.template).render(**resolved_variables)
        )
        if prune_empty:
            data_value = prune(data_value)
        return data_value

    def _get_vars_for_template(self) -> set[str]:
        parsed_content = self.jinja_env.parse(self.template)
        jinja_vars = meta.find_undeclared_variables(parsed_content)
        return {var for var in jinja_vars if var not in self.jinja_env.globals}


class Chunk:
    """A piece of information represented in 2 SBOM formats."""

    def __init__(
        self,
        name: str,
        first_format: SBOMFormat,
        second_format: SBOMFormat,
        first_data: Data | None,
        second_data: Data | None,
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

    def occurrences(
        self, doc: Document, fallback_variables: dict[str, Any] = None
    ) -> dict[str, Any]:
        """Returns a list of string fieldPaths where the element occurs."""
        fallback_variables = fallback_variables or {}
        resolver = self.resolver_for(doc.sbom_format)
        return resolver.get_paths_and_objects(
            doc.doc, self.field_path_for(doc.sbom_format), fallback_variables
        )

    @staticmethod
    def __mutate_obj_by_inserting(
        parent_obj: Any,
        value_to_insert: Any,
        last_step_field_path: str | QueryParser | None,
    ) -> None:
        if last_step_field_path is None:
            # This is at the root level
            parent_obj.update(value_to_insert)
        if isinstance(last_step_field_path, str):
            # We want to add to a dict
            parent_obj[last_step_field_path] = value_to_insert
        elif isinstance(last_step_field_path, QueryParser):
            # We want to add to a list
            if isinstance(value_to_insert, list):
                parent_obj.extend(value_to_insert)
            else:
                parent_obj.append(value_to_insert)

    def convert_and_add(
        self,
        orig_doc: Document,
        new_doc: dict[str, Any],
        globally_resolved_variables: dict[str, list[Any]] = None,
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
        relevant_data = self.data_for(convert_to)
        if not relevant_data:
            # This chunk does not specify anything for this direction
            return
        globally_resolved_variables = globally_resolved_variables or {}

        source_resolver = self.resolver_for(convert_from)
        chunk_based_absolute_vars = source_resolver.resolve_variables(orig_doc.doc)
        global_vars = {**globally_resolved_variables, **chunk_based_absolute_vars}

        # Resolve all info about the point where to insert data -- once
        appender_resolver = self.resolver_for(convert_to)
        append_path = appender_resolver.ensure_field_path(
            self.field_path_for(convert_to)
        )
        last_insert_step = next(iter(append_path[-1:]), None)
        mutable_parents = appender_resolver.get_mutable_parents(
            new_doc, append_path, create_nonexistent=True
        )

        for occurrence_path, occurrence_value in self.occurrences(
            orig_doc, globally_resolved_variables
        ).items():
            rendered_data = relevant_data.render(
                orig_doc,
                occurrence_path,
                occurrence_value,
                globally_resolved_variables=global_vars,
            )
            if not should_remove(rendered_data):
                for mutable_parent in mutable_parents:
                    self.__mutate_obj_by_inserting(
                        mutable_parent, rendered_data, last_insert_step
                    )


class TranslationMap:
    """This objects transforms SBOMs between formats."""

    def __init__(
        self,
        first: SBOMFormat,
        second: SBOMFormat,
        chunks: list[Chunk],
        first_variables: dict[str, Variable],
        second_variables: dict[str, Variable],
        preprocessing_funcs: dict[SBOMFormat, list[Callable]] = None,
        postprocessing_funcs: dict[SBOMFormat, list[Callable]] = None,
    ):
        self.first = first
        self.second = second
        self.chunks = chunks
        self.first_variables = first_variables or {}
        self.second_variables = second_variables or {}
        self.preprocessing_funcs: dict[SBOMFormat, list[Callable[[dict], Any]]] = (
            preprocessing_funcs or {}
        )
        self.postprocessing_funcs: dict[
            SBOMFormat, list[Callable[[dict, dict], Any]]
        ] = (postprocessing_funcs or {})

    @staticmethod
    def from_file(file: str | Path) -> "TranslationMap":
        """Load the Translation Map from a file."""
        schema_dict = get_mapping(file, TRANSLATION_MAP_VALIDATION_SCHEMA_PATH)

        first = SBOMFormat(schema_dict["first"])
        second = SBOMFormat(schema_dict["second"])

        first_glob_var = schema_dict.get("firstVariables")
        second_glob_var = schema_dict.get("secondVariables")

        first_transformer_file = get_path_to_module(file, "Transformer", "first", first)
        first_glob_var_initialized = Variable.from_schema(first_glob_var)
        second_transformer_file = get_path_to_module(
            file, "Transformer", "second", second
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

            if first_data_dict := chunk_dict.get("firstData"):
                first_data = Data(first_data_dict, second_vars, second_transformer_file)
            else:
                first_data = None
            if second_data_dict := chunk_dict.get("secondData"):
                second_data = Data(second_data_dict, first_vars, first_transformer_file)
            else:
                second_data = None
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

        preprocessing_dict = {}
        postprocessing_dict = {}
        for dict_of_functions, kind in (
            (preprocessing_dict, "Preprocessing"),
            (postprocessing_dict, "Postprocessing"),
        ):
            # Load both preprocessing and postprocessing functions
            for first_or_second, sbom_format in ("first", first), ("second", second):
                # Load both the functions for the first and the second format
                required_funcs = schema_dict.get(f"{first_or_second}{kind}", [])
                if not required_funcs:
                    # There are no functions required by the TranslationMap
                    continue
                dict_of_functions[sbom_format] = []
                py_file = get_path_to_module(file, kind, first_or_second, sbom_format)
                python_loader = PythonLoader(py_file)
                for func_name in required_funcs:
                    dict_of_functions[sbom_format].append(
                        python_loader.load_func(func_name)
                    )

        return TranslationMap(
            first,
            second,
            chunks,
            first_glob_var_initialized,
            second_glob_var_initialized,
            preprocessing_dict,
            postprocessing_dict,
        )

    def _output_format(self, doc: Document) -> SBOMFormat:
        for form in self.first, self.second:
            if doc.sbom_format is not form and not any(
                doc.sbom_format == fallback for fallback in get_fallbacks(form)
            ):
                return form

    def _input_format(self, doc: Document) -> SBOMFormat:
        for form in self.first, self.second:
            if doc.sbom_format is form:
                return form
        for form in self.first, self.second:
            if doc.sbom_format in get_fallbacks(form):
                return form
        raise ValueError(f"Cannot do anything with this format: {doc.sbom_format}")

    def convert(
        self, sbom: Document, override_format: SBOMFormat | None = None
    ) -> Document:
        """
        Converts document to the specified format.
        :argument sbom: Sbom document to convert.
        :argument override_format: Specify which is the output format.
        If omitted, the format is chosen from values self.first or
        self.second. The value not associated with input document will be used.
        """
        new_data = {}
        assert sbom.sbom_format in (
            self.first,
            self.second,
        ) or any(
            fallback
            in (
                self.first,
                self.second,
            )
            for fallback in sbom.sbom_format_fallback
        ), f"This map cannot convert from {sbom.sbom_format}."
        # Preprocess
        sbom_dict = sbom.doc
        for preprocessing_func in self.preprocessing_funcs.get(
            self._input_format(sbom), []
        ):
            res = preprocessing_func(sbom_dict)
            if res:
                sbom_dict = res
        # Finish preprocessing
        sbom = Document(sbom_dict)

        # Load global vars
        variable_definitions = (
            self.first_variables
            if self._input_format(sbom) == self.first
            else self.second_variables
        )
        globally_loaded_variables = FieldResolver(
            variable_definitions
        ).resolve_variables(sbom.doc)

        # Conversion
        for chunk in self.chunks:
            chunk.convert_and_add(sbom, new_data, globally_loaded_variables)
        # Postprocess
        for postprocessing_func in self.postprocessing_funcs.get(
            self._output_format(sbom), []
        ):
            res = postprocessing_func(sbom.doc, new_data)
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
