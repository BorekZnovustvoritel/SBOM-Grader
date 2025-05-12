import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from functools import cached_property
from typing import Union, Any, Callable, Sequence

from sbomgrader.core.definitions import (
    FIELD_NOT_PRESENT,
    FieldNotPresentError,
    MAX_ITEM_PREVIEW_LENGTH,
    START_PREVIEW_CHARS,
    END_PREVIEW_CHARS,
    VAR_REF_REGEX,
)
from sbomgrader.core.enums import QueryType

LOGGER = logging.getLogger(__name__)


class PathParser:
    """Parses the FieldPath expression into an iterable list."""

    def __init__(self, path: str):
        self._path = path
        self.__next_is_query = False
        self.ans: dict[str, list[Union[str, QueryParser]]] = defaultdict(list)

    def __create_field(
        self, field: str | int | None, next_is_query: bool, relative_path: "PathParser"
    ) -> None:
        next_expression: None | str | QueryParser = None
        if self.__next_is_query:
            if field == "@":
                try:
                    appropriate_relative_field = relative_path.parse()[
                        len(self.ans[relative_path.raw_path])
                    ]
                except IndexError:
                    raise ValueError(
                        f"Problem parsing path '{self._path}' with relative hint '{relative_path.raw_path}'. "
                        f"The relative path hint is too short!"
                    )
                if isinstance(appropriate_relative_field, QueryParser):
                    index_query = next(iter(appropriate_relative_field.parse()), None)
                    if not index_query:
                        raise ValueError(
                            f"Problem parsing path '{self._path}' with relative hint '{relative_path.raw_path}'. "
                            f"There are no queries to follow at step '{field}'."
                        )
                    if index_query.type_ is not QueryType.INDEX:
                        raise ValueError(
                            f"Problem parsing path '{self._path}' with relative hint '{relative_path.raw_path}'. "
                            f"This is not an index query type: '{index_query.type_}'"
                        )
                    field = index_query.value
            if field is not None:
                next_expression = QueryParser(field)
        else:
            if isinstance(field, str):
                next_expression = field.strip()
            else:
                next_expression = str(field)

        self.__next_is_query = next_is_query
        if next_expression:
            self.ans[relative_path.raw_path].append(next_expression)

    def parse(
        self, relative_path: str | None = None
    ) -> list[Union[str, "QueryParser"]]:
        """
        Returns a list of dictionary field names and queries for list filtering.
        Args:
            relative_path:
                Used to populate "relative" fields
                (relative path has the '@' symbol).

        Returns: Parsed path (a list of strings or QueryParsers)
        """
        relative_path = relative_path or ""
        if relative_path in self.ans:
            return self.ans[relative_path]
        parsed_relative_path = PathParser(relative_path)
        if relative_path:
            if any(
                any(query.type_ != QueryType.INDEX for query in item.parse())
                for item in parsed_relative_path.parse()
                if isinstance(item, QueryParser)
            ):
                raise ValueError(
                    "Relative path can only include field names and absolute indices. "
                    "HINT: If you wish to get a list of absolute paths, use the method "
                    "`FieldResolver.get_paths()`."
                )
        resolve_path = self._path
        if resolve_path.startswith("@"):
            if not relative_path:
                raise ValueError(
                    "Cannot resolve relative path if no relative path is passed!"
                )
            resolve_path = resolve_path.replace("@", relative_path, 1)
        in_block = 1 if self.__next_is_query else 0
        buffer = ""
        for char in resolve_path:
            if char == "[":
                if not in_block:
                    self.__create_field(buffer, True, parsed_relative_path)
                    buffer = ""
                else:
                    buffer += char
                in_block += 1
            elif char == "]":
                in_block -= 1
                if not in_block:
                    self.__create_field(buffer, False, parsed_relative_path)
                    buffer = ""
                else:
                    buffer += char
            elif char == ".":
                if not in_block:
                    # Field delimiter found
                    self.__create_field(buffer, False, parsed_relative_path)
                    buffer = ""
                else:
                    # Field delimiter is just a part of subquery, ignoring
                    buffer += char
            else:
                buffer += char
        if buffer:
            self.__create_field(buffer, False, parsed_relative_path)
        if in_block:
            raise ValueError(f"Unmatched '[' in query '{self._path}'!")
        return self.ans[relative_path]

    def __eq__(self, other):
        if not isinstance(other, PathParser):
            raise TypeError(
                f"Cannot compare PathParser to object of type {type(other)}"
            )
        return self.parse() == other.parse()

    @property
    def raw_path(self) -> str:
        """The original string containing the path."""
        return self._path

    @property
    def variable_references(self) -> set[str]:
        parsed_path = self.parse()
        ans = set()
        for step in parsed_path:
            if isinstance(step, QueryParser):
                ans.update(step.variable_references)
        return ans


@dataclass
class Query:
    """Class holding an information about list filtering."""

    type_: QueryType
    value: str | int | None
    field_path: PathParser | None

    @property
    def variable(self) -> str | None:
        if (
            self.value
            and isinstance(self.value, str)
            and (match := re.match(r"^\$\{(?P<varname>\w+)}$", self.value))
        ):
            return match.group("varname")
        return None


class QueryParser:
    """
    Parses strings into a list of Queries.
    """

    def __init__(self, path: str | int):
        self._path = path
        self.ans: dict[str | None, list[Query]] = defaultdict(list)

    def __eq__(self, other):
        if not isinstance(other, QueryParser):
            raise TypeError(
                f"Cannot compare QueryParser to object of type {type(other)}"
            )
        return self.parse() == other.parse()

    def parse(self, relative_path_index: str | None = None) -> list[Query]:
        """Parse the query list. If required, replaces the relative symbol '@' with the provided index."""
        if relative_path_index in self.ans:
            return self.ans[relative_path_index]
        if isinstance(self._path, int):
            return [Query(QueryType.INDEX, value=self._path, field_path=None)]
        queries = []
        field_buffer = ""
        operation_buffer = ""
        value_buffer = ""
        in_block = 0
        in_operation = False
        after_operation = False
        operation_symbols = {"!", "=", "%", "|", "&"}
        for char in self._path:
            if re.match(r"\s", char) and not after_operation:
                continue
            if char not in operation_symbols and in_operation:
                after_operation = True
            if char in operation_symbols and not in_block and not after_operation:
                operation_buffer += char
                in_operation = True

            elif after_operation and char != ",":
                value_buffer += char
            elif char == "," and in_operation:
                queries.append(
                    Query(
                        type_=QueryType(operation_buffer),
                        field_path=(
                            None if not field_buffer else PathParser(field_buffer)
                        ),
                        value=None if not value_buffer else value_buffer,
                    )
                )
                field_buffer = ""
                operation_buffer = ""
                value_buffer = ""
                in_operation = False
                after_operation = False
            elif char == "[":
                field_buffer += char
                in_block += 1
            elif char == "]":
                in_block -= 1
                field_buffer += char

            else:
                field_buffer += char.strip()

        if field_buffer or operation_buffer or value_buffer:
            if field_buffer == "@" and not operation_buffer and not value_buffer:
                # There is no query, just a relative symbol
                assert relative_path_index, (
                    f"Cannot parse relative path '{self._path}', "
                    f"the relative index provides no usable value: {relative_path_index}"
                )
                current_path_index = int(relative_path_index)
                query = Query(
                    type_=QueryType.INDEX,
                    field_path=None,
                    value=current_path_index,
                )
            elif (
                (m := re.fullmatch(r"\d+", field_buffer))
                and not operation_buffer
                and not value_buffer
            ):
                # There is no query, just an index
                query = Query(
                    type_=QueryType.INDEX, field_path=None, value=int(m.group())
                )
            else:
                query = Query(
                    type_=QueryType(operation_buffer.strip()),
                    field_path=PathParser(field_buffer.strip()),
                    value=self._load_val(value_buffer),
                )
            queries.append(query)
        self.ans[relative_path_index] = queries
        return queries

    @property
    def variable_references(self) -> set[str]:
        parsed_queries = self.parse()
        ans = set()
        for query in parsed_queries:
            if var_name := query.variable:
                ans.add(var_name)
            if sub_path_parser := query.field_path:
                ans.update(sub_path_parser.variable_references)
        return ans

    @staticmethod
    def _load_val(value: str) -> Any:
        stripped_val = value.strip()
        if stripped_val == FIELD_NOT_PRESENT.string_repr:
            return FIELD_NOT_PRESENT
        return stripped_val

    def __repr__(self):
        return str(self._path)


class Variable:
    def __init__(
        self,
        name: str,
        field_path: str,
    ):
        self.name = name
        self.raw_field_path = field_path
        self.path_parser = PathParser(self.raw_field_path)

    @staticmethod
    def from_schema(schema_list: list[dict[str, Any]]) -> dict[str, "Variable"]:
        """Load a variable from a dictionary."""
        variable_nammes_and_objects: dict[str, Variable] = {}
        if not schema_list:
            return variable_nammes_and_objects
        for item in schema_list:
            name = item["name"]
            field_path = item["fieldPath"]
            variable_nammes_and_objects[name] = Variable(name, field_path)
        return variable_nammes_and_objects

    @property
    def is_relative(self) -> bool:
        """Does the definition of this Variable contain a relative path?"""
        return self.is_fully_relative or self.is_partially_relative

    @property
    def is_fully_relative(self):
        return self.raw_field_path.startswith("@")

    @property
    def is_partially_relative(self):
        return "[@]" in self.raw_field_path

    @property
    def without_relative_start(self) -> "Variable":
        if not self.is_fully_relative:
            return self
        return Variable(self.name, self.path_parser.raw_path.removeprefix("@."))

    @cached_property
    def dependencies(self) -> set[str]:
        deps = {
            match.group("var_id")
            for match in re.finditer(VAR_REF_REGEX, self.raw_field_path)
        }
        assert self.name not in deps, f"Self referencing variable {self.name} found."
        return deps

    def __hash__(self):
        return self.name.__hash__()

    def __repr__(self):
        return f"<{self.__class__.__name__}, name: {self.name}, field_path: {self.raw_field_path}>"


class FieldResolver:
    """
    Resolves path expressions and dictionaries (documents).
    Can return their paths, values or executes functions on each occurrence.
    """

    def __init__(self, variables: dict[str, Variable]):
        self._uninitialized_vars = variables

    @property
    def var_definitions(self) -> dict[str, Variable]:
        return self._uninitialized_vars

    @property
    def absolute_variables(self) -> dict[str, Variable]:
        """Returns just variables without a relative path definition."""
        return {
            key: val
            for key, val in self._uninitialized_vars.items()
            if not val.is_relative
        }

    @property
    def relative_variables(self) -> dict[str, Variable]:
        """Returns just variables with a relative path definition."""
        return {
            key: val for key, val in self._uninitialized_vars.items() if val.is_relative
        }

    @property
    def fully_relative_variables(self) -> dict[str, Variable]:
        """
        Returns just variables with a fully relative path definition.
        (Their path starts with a '@', they search through
         direct descendants of the relative path).
        """
        return {
            key: val for key, val in self._uninitialized_vars.items() if val.is_relative
        }

    def __find_dependencies_for_subset(
        self,
        subset_of_variables: list[str] | set[str],
        already_resolved: set[str] | dict[str, Any],
    ) -> set[str]:
        """Returns dependencies for a subset of variables."""
        to_resolve = set(subset_of_variables)
        ans = set(already_resolved)
        while to_resolve:
            var_name = to_resolve.pop()
            variable = self.var_definitions.get(var_name)
            if not variable:
                continue
            for dep_name in variable.dependencies:
                if dep_name not in ans:
                    to_resolve.add(dep_name)
            ans.add(var_name)
        return ans

    @staticmethod
    def __mark_variable_as_resolved(
        dependency_dict: dict[str, set[str]], var_name: str
    ):
        dependency_dict.pop(var_name, None)
        for deps in dependency_dict.values():
            if var_name in deps:
                deps.remove(var_name)

    def resolve_variables(
        self,
        whole_doc: dict[str, Any],
        path_to_instance: str | None = None,
        already_resolved_variables: dict[str, list[Any]] | None = None,
        warning_on: bool = True,
        variables_needed: list[str] | set[str] | None = None,
        path_prefix: str = "",
    ) -> dict[str, list[Any]]:
        """
        Resolve dependencies.
        Without the argument `path_to_instance` this method cannot resolve relative variables
        nor absolute variables relying on relative ones.
        :argument whole_doc: The document that the FieldPath expression should be evaluated on
        :argument path_to_instance: The base for the relative paths.
        :argument already_resolved_variables: Variable values resolved previously. Helps with
        performance.
        :argument warning_on: Should this function display a warning to the STDERR?
        :argument variables_needed: Specify a subset of variables that need resolving.
        :argument path_prefix: Optionally provide a path that will be prepended to each "path tried".
        """
        already_resolved_variables = already_resolved_variables or {}
        if not variables_needed:
            # first resolve dependency tree for variables
            if path_to_instance:
                vars_to_resolve = self._uninitialized_vars
            else:
                vars_to_resolve = self.absolute_variables
            vars_to_resolve = {
                k: v
                for k, v in vars_to_resolve.items()
                if k not in already_resolved_variables
            }
        else:
            vars_to_resolve = {
                k: self.var_definitions[k]
                for k in self.__find_dependencies_for_subset(
                    variables_needed, already_resolved_variables
                )
            }
        # This will keep track of variable values that need to be
        # included for other variable resolution
        all_dependencies: dict[str, set[str]] = {
            var_name: variable_def.dependencies
            for var_name, variable_def in vars_to_resolve.items()
        }
        # This variable will be reduced so only the outstanding
        # (blocking, unresolved) dependencies are included
        dependencies: dict[str, set[str]] = {
            var_name: set(deps) for var_name, deps in all_dependencies.items()
        }
        # This variable keeps track of what is already resolved
        resolved_variables: dict[str, list] = {**already_resolved_variables}
        for var_name in resolved_variables:
            self.__mark_variable_as_resolved(dependencies, var_name)
        while not all(var_name in resolved_variables for var_name in dependencies):
            # Get a var with no dependencies
            var_name, var_deps = sorted(dependencies.items(), key=lambda x: len(x[1]))[
                0
            ]
            if not path_to_instance and any(
                self._uninitialized_vars[dep_name].is_relative for dep_name in var_deps
            ):
                # Cannot resolve absolute variable referencing a relative one
                self.__mark_variable_as_resolved(dependencies, var_name)
                continue
            assert not var_deps, (
                f"Circular variable reference found for variable {var_name}. "
                f"Needs to resolve: {dependencies[var_name]}. "
                f"Already resolved: {set(resolved_variables.keys())}"
            )

            resolved_variables[var_name] = []

            def add_to_variable(value: Any, _) -> None:
                resolved_variables[var_name].append(value)

            path = vars_to_resolve[var_name].path_parser.parse(path_to_instance)
            variable_values = self.__cast_vars_to_sets(
                {
                    dep_name: dep_value
                    for dep_name, dep_value in resolved_variables.items()
                    if dep_name in all_dependencies.get(var_name, set())
                }
            )
            try:
                self._run_on_path(
                    whole_doc,
                    path,
                    variable_values,
                    path_prefix,
                    add_to_variable,
                    False,
                )
            except Exception as e:
                problem_string = f"Could not parse variable {var_name}."
                if warning_on:
                    LOGGER.warning(problem_string)
                else:
                    LOGGER.debug(problem_string)
                LOGGER.debug("Problem information: ", exc_info=e)

            self.__mark_variable_as_resolved(dependencies, var_name)
        return resolved_variables

    @staticmethod
    def __add_at_path(
        mutable_doc: dict[Any, Any] | list[Any],
        path_remaining: Sequence[str | QueryParser | PathParser],
    ):
        if path_remaining:
            step = path_remaining[0]
        else:
            return
        if path_remaining[1:] and isinstance(path_remaining[1], str):
            # Add a dict
            mutable_doc[step] = {}  # type: ignore[call-overload]
        if path_remaining[1:] and isinstance(path_remaining[1], QueryParser):
            # Add a list
            mutable_doc[step] = []  # type: ignore[call-overload]

    @staticmethod
    def __cast_vars_to_sets(
        variables: dict[str, list[Any]],
    ) -> dict[str, list[Any] | set[Any]]:
        """
        Tries to convert lists of values to
        sets of values. Leaves the original value
        if it contains unhashable objects.
        """
        new_variables: dict[str, list[Any] | set[Any]] = {}
        for var_name in variables:
            try:
                new_value = set(variables[var_name])
                new_variables[var_name] = new_value
            except TypeError:
                new_variables[var_name] = variables[var_name]
        return new_variables

    def _run_on_path(
        self,
        doc_: Any,
        path: Sequence[str | QueryParser | PathParser],
        variable_values: dict[str, list[Any] | set[Any]],
        path_tried: str,
        func_to_run: Callable[[Any, str], Any],
        accept_not_present_field: bool,
        create_nonexistent: bool = False,
    ) -> None:
        """
        This function is the main resolver. Recursively calls itself on nested fields
        to search for all occurrences.
        Args:
            doc_:
                SBOM dictionary or its part (dictionary, list, string...)
            path:
                The parsed FieldPath that is supposed to be executed on the doc_.
            variable_values:
                Dictionary of variable names and their values (sets or lists) to
                be used in the filtering.
            path_tried:
                String representation of the already executed path passed from parent call.
            func_to_run:
                The callable to execute on this piece of code.
            accept_not_present_field:
                States if the callable is safe to execute on the FIELD_NOT_PRESENT object.
                Otherwise, this will raise a FieldNotPresentError if the field searched is absent.
            create_nonexistent:
                States if the function shall create new non-existing fields during search.
                Used for document creation.
        Returns:
            None
        """
        if not accept_not_present_field and doc_ is FIELD_NOT_PRESENT:
            raise FieldNotPresentError("Field not present: ", path_tried)
        if not path or doc_ is FIELD_NOT_PRESENT:
            # The path has ended
            try:
                resp = func_to_run(doc_, path_tried)
                assert resp is True or resp is None
            except Exception as e:
                item_str = str(doc_)
                if len(item_str) > MAX_ITEM_PREVIEW_LENGTH:
                    item_str = f"{item_str[:START_PREVIEW_CHARS]}...{item_str[-END_PREVIEW_CHARS:]}"
                if not path_tried:
                    path_tried = "."
                message_to_return = (
                    f"Check did not pass for item: {item_str} at path: {path_tried}\n"
                    + "\n".join(str(m) for m in e.args)
                )
                raise type(e)(message_to_return) from e
            return
        step = path[0]
        if isinstance(step, str):
            # Field name
            assert isinstance(
                doc_, dict
            ), f"Cannot access field '{step}' on other objects than dicts. Provided object: {doc_}"
            if step == "?":
                assert path[1:] and isinstance(
                    path[1], str
                ), "Cannot use ? before anything else than a field name."
                if path[1] not in doc_ and create_nonexistent:
                    self.__add_at_path(doc_, path[1:])
                if path[1] in doc_:
                    self._run_on_path(
                        doc_,
                        path[1:],
                        variable_values,
                        path_tried,
                        func_to_run,
                        accept_not_present_field,
                        create_nonexistent,
                    )
            else:
                if create_nonexistent and step not in doc_:
                    self.__add_at_path(doc_, path)
                self._run_on_path(
                    doc_.get(step, FIELD_NOT_PRESENT),
                    path[1:],
                    variable_values,
                    path_tried + f".{step}",
                    func_to_run,
                    accept_not_present_field,
                    create_nonexistent,
                )
        elif isinstance(step, QueryParser):
            assert isinstance(
                doc_, list
            ), f"Queries can only be performed on lists! Tested path: {path_tried}, item: {doc_}"
            queries = step.parse()

            to_use = []
            can_fail_for_some = False

            for query in queries:
                if query.type_ in {QueryType.EACH, QueryType.ANY}:
                    # Use every list index available
                    to_use.append(set(range(len(doc_))))
                    if query.type_ is QueryType.ANY:
                        can_fail_for_some = True
                    continue
                elif query.type_ is QueryType.INDEX:
                    to_use.append({query.value})  # type: ignore[arg-type]
                    continue
                # Actually filter the list
                to_use_in_query = set()
                for idx, item in enumerate(doc_):
                    varname = query.variable
                    if query.type_ is QueryType.EQ:
                        if varname:
                            func = lambda x: x in variable_values[varname]
                        else:
                            func = lambda x: x == query.value
                    elif query.type_ is QueryType.NEQ:
                        if varname:
                            func = lambda x: x not in variable_values[varname]
                        else:
                            func = lambda x: x != query.value
                    elif query.type_ is QueryType.STARTSWITH:
                        if varname:
                            func = lambda x: isinstance(x, str) and any(
                                x.startswith(val) for val in variable_values[varname]
                            )
                        else:
                            func = lambda x: isinstance(x, str) and x.startswith(
                                query.value  # type: ignore[arg-type]
                            )
                    elif query.type_ is QueryType.ENDSWITH:
                        if varname:
                            func = lambda x: isinstance(x, str) and any(
                                x.endswith(val) for val in variable_values[varname]
                            )
                        else:
                            func = lambda x: isinstance(x, str) and x.endswith(
                                query.value  # type: ignore[arg-type]
                            )
                    elif query.type_ is QueryType.CONTAINS:
                        if varname:
                            func = lambda x: isinstance(x, str) and any(
                                val in x for val in variable_values[varname]
                            )
                        else:
                            func = lambda x: isinstance(x, str) and query.value in x  # type: ignore[operator]
                    elif query.type_ is QueryType.NOT_CONTAINS:
                        if varname:
                            func = lambda x: isinstance(x, str) and all(
                                val not in x for val in variable_values[varname]
                            )
                        else:
                            func = lambda x: isinstance(x, str) and query.value not in x  # type: ignore[operator]
                    final_func = lambda x, _: (
                        to_use_in_query.add(idx) if func(x) else None
                    )
                    parsed_path = (
                        query.field_path.parse() if query.field_path is not None else []
                    )
                    self._run_on_path(
                        item,
                        parsed_path,
                        variable_values,
                        path_tried + f"[{idx}]",
                        final_func,
                        True,
                        create_nonexistent,
                    )
                    to_use.append(to_use_in_query)
            to_use_final = set.intersection(*to_use) if to_use else {}
            failed = 0
            assertions = []
            for idx, item in enumerate(doc_):
                if idx not in to_use_final:
                    continue

                if can_fail_for_some:
                    try:
                        self._run_on_path(
                            item,
                            path[1:],
                            variable_values,
                            path_tried + f"[{idx}]",
                            func_to_run,
                            accept_not_present_field,
                            create_nonexistent,
                        )
                    except (AssertionError, FieldNotPresentError) as e:
                        failed += 1
                        assertions.append(e)
                    assert failed < len(
                        to_use_final
                    ), f"Check did not pass for any fields. Assertions: {assertions}, path: {path_tried}"
                else:
                    self._run_on_path(
                        item,
                        path[1:],
                        variable_values,
                        path_tried + f"[{idx}]",
                        func_to_run,
                        accept_not_present_field,
                        create_nonexistent,
                    )

    @staticmethod
    def ensure_field_path(
        field_path: str | list[Union[str, QueryParser]],
    ) -> list[Union[str, QueryParser]]:
        """Makes sure the FieldPath is in the parsed format."""
        return (
            field_path
            if isinstance(field_path, list)
            else PathParser(field_path).parse()
        )

    @staticmethod
    def __get_vars_from_path(
        path: str | list[str | QueryParser] | PathParser,
    ) -> set[str]:
        if isinstance(path, str):
            path = PathParser(path)
        if isinstance(path, PathParser):
            path = path.parse()
        if not isinstance(path, list):
            raise TypeError(f"Invalid path type supplied: {type(path)}")
        ans = set()
        for step in path:
            if isinstance(step, QueryParser):
                ans.update(step.variable_references)
        return ans

    def __populate_variables(
        self,
        doc: dict[str, Any],
        fallback_values: dict[str, Any] | None,
        field_path: list[str | QueryParser] | str | PathParser,
        allow_fail: bool = False,
        prefer_fallback: bool = False,
    ) -> dict[str, Any]:
        variables_needed = self.__get_vars_from_path(field_path)
        args = {
            "whole_doc": doc,
            "warning_on": not allow_fail,
            "variables_needed": variables_needed,
        }
        if prefer_fallback:
            args["already_resolved_variables"] = fallback_values
        variables = {} if not fallback_values else {**fallback_values}
        variables.update(self.resolve_variables(**args))  # type: ignore[arg-type]
        return variables

    def run_func(
        self,
        doc: dict[str, Any],
        func: Callable[[Any], Any],
        field_path: str | list[Union[str, QueryParser]],
        minimal_runs: int = 1,
        fallback_variables: dict[str, Any] | None = None,
        create_nonexistent: bool = False,
        path_prefix: str = "",
    ) -> None:
        """
        Execute a function on each field matching the FieldPath expression.
        :argument doc: The dictionary that the expression is evaluated on.
        :argument func: The function to run on each occurrence.
        :argument field_path: The FieldPath expression to locate all fields.
        :argument minimal_runs: If the number of executions of the function
        is not met, this method raises an Assertion Error.
        :argument fallback_variables: Variable values resolved previously in
        the format {"var_name": [var_value1, var_value2,...]}
        :argument create_nonexistent: If the path does not exist yet, should
        this function create it? Useful for document creation.
        :argument path_prefix: Optionally provide a path that will be prepended to each "path tried".
        """
        ran_on = set()

        def adjusted_func(value: Any, path: str) -> None:
            ran_on.add(path)
            func(value)

        parsed_path = self.ensure_field_path(field_path)
        resolved_variables = self.__cast_vars_to_sets(
            self.__populate_variables(
                doc, fallback_variables, parsed_path, create_nonexistent
            )
        )
        self._run_on_path(
            doc,
            parsed_path,
            resolved_variables,
            path_prefix,
            adjusted_func,
            create_nonexistent,
            create_nonexistent,
        )
        assert (
            len(ran_on) >= minimal_runs
        ), "Test was not performed on any fields because no fields match given filters."

    def get_objects(
        self,
        doc: dict[str, Any],
        field_path: str | list[Union[str, QueryParser]],
        fallback_variables: dict[str, Any] | None = None,
        create_nonexistent: bool = False,
        path_prefix: str = "",
    ) -> list[Any]:
        """
        Gets all fields matching the FieldPath expression.
        :argument doc: The document the expression is evaluated on.
        :argument field_path: The FieldPath expression.
        :argument fallback_variables: Already resolved variable values in
        the format {"var_name": [var_value1, var_value2,...]}.
        :argument create_nonexistent: If the fields do not exist already,
        should they be created? Useful for document creation.
        :argument path_prefix: Optionally provide a path that will be prepended to each "path tried".
        :return: A list of field values.
        """
        ans = []

        def add_to_ans(item: Any) -> None:
            ans.append(item)

        try:
            self.run_func(
                doc,
                add_to_ans,
                field_path,
                minimal_runs=0,
                fallback_variables=fallback_variables,
                create_nonexistent=create_nonexistent,
                path_prefix=path_prefix,
            )
            return ans
        except FieldNotPresentError:
            return []

    def get_paths_and_objects(
        self,
        doc: dict[str, Any],
        field_path: str | list[Union[str, QueryParser]],
        fallback_variables: dict[str, list[Any]],
        path_prefix: str = "",
    ) -> dict[str, Any]:
        """
        Retrieves a dictionary of absolute paths and values
        on these paths according to field_path query.
        Args:
            doc: SBOM document or its part.
            field_path: FieldPath Query.
            fallback_variables: Pre-populated variables.
            path_prefix: If this is not the document root, specify current path for proper debug.

        Returns:
            Dictionary of absolute paths (strings) and objects located there.
        """
        parsed_path = self.ensure_field_path(field_path)
        resolved_variables = self.__cast_vars_to_sets(
            self.__populate_variables(
                doc,
                fallback_variables,
                parsed_path,
                allow_fail=True,
                prefer_fallback=True,
            )
        )
        ans = {}

        def extend_ans(value: Any, path: str):
            ans[path] = value

        self._run_on_path(
            doc,
            parsed_path,
            resolved_variables,
            path_prefix,
            extend_ans,
            False,
            False,
        )
        return ans

    def get_mutable_parents(
        self,
        doc: dict[str, Any],
        field_path: str | list[Union[str, QueryParser]],
        fallback_variables: dict[str, Any] | None = None,
        create_nonexistent: bool = False,
    ) -> list[Any]:
        """
        Fetches the parent of the last expression. Useful for document mutations.
        Does not resolve variables on its own.
        """
        path = self.ensure_field_path(field_path)
        if create_nonexistent:
            # create parents
            self.get_objects(doc, path, fallback_variables, create_nonexistent)
        # fetch parents
        return self.get_objects(doc, path[:-1], fallback_variables, create_nonexistent)
