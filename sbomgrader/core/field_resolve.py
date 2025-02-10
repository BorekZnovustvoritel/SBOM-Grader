import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Union, Any, Callable

from sbomgrader.core.cached_python_loader import PythonLoader
from sbomgrader.core.definitions import (
    FIELD_NOT_PRESENT,
    FieldNotPresentError,
    MAX_ITEM_PREVIEW_LENGTH,
    START_PREVIEW_CHARS,
    END_PREVIEW_CHARS,
    VAR_REF_REGEX,
)
from sbomgrader.core.enums import QueryType


class PathParser:
    def __init__(self, path: str):
        self._path = path
        self.__next_is_query = False
        self.ans: list[Union[str, QueryParser]] | None = None

    def __create_field(
        self, field: str, next_is_query: bool
    ) -> None:
        if self.__next_is_query:
            next_ = QueryParser(field)
        else:
            next_ = field.strip()
        self.__next_is_query = next_is_query

        if next_:
            self.ans.append(next_)

    def parse(self) -> list[Union[str, "QueryParser"]]:
        if self.ans is not None:
            return self.ans
        self.ans = []
        in_block = 1 if self.__next_is_query else 0
        buffer = ""
        for char in self._path:
            if char == "[":
                if not in_block:
                    self.__create_field(buffer, True)
                    buffer = ""
                else:
                    buffer += char
                in_block += 1
            elif char == "]":
                in_block -= 1
                if not in_block:
                    self.__create_field(buffer, False)
                    buffer = ""
                else:
                    buffer += char
            elif char == ".":
                if not in_block:
                    self.__create_field(buffer, False)
                    buffer = ""
                else:
                    buffer += char
            else:
                buffer += char
        if buffer:
            self.__create_field(buffer, False)
        return self.ans


@dataclass
class Query:
    type_: QueryType
    value: str | None
    field_path: PathParser | None

    @property
    def variable(self) -> str | None:
        if self.value and (match := re.match(r"^\$\{(?P<varname>\w+)}$", self.value)):
            return match.group("varname")


class QueryParser:
    def __init__(self, path: str):
        self._path = path

    def parse(self) -> list[Query]:
        queries = []
        field_buffer = ""
        operation_buffer = ""
        value_buffer = ""
        in_block = 0
        after_operation = False
        for char in self._path:
            if re.match(r"\s", char) and not after_operation:
                continue
            if char in {"!", "=", "%", "|", "&"} and not in_block:
                operation_buffer += char
                after_operation = True
            elif after_operation and char != ",":
                value_buffer += char
            elif char == "," and after_operation:
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
            queries.append(
                Query(
                    type_=QueryType(operation_buffer.strip()),
                    field_path=PathParser(field_buffer.strip()),
                    value=value_buffer.strip(),
                )
            )
        return queries


class Variable:
    def __init__(
        self,
        name: str,
        field_path: str,
        value_map: dict[Any, Any] = None,
        transformer: Callable[[Any], Any] = None,
    ):
        self.name = name
        self.raw_field_path = field_path
        self.value_map = value_map
        self.transformer = transformer
        full_parsed_path = PathParser(self.raw_field_path).parse()
        self.is_relative: bool = full_parsed_path[0] == "@"
        self.parsed_path: list[Union[str, QueryParser]] = (
            full_parsed_path if not self.is_relative else full_parsed_path[1:]
        )

    @staticmethod
    def from_schema(
        schema_list: list[dict[str, Any]], transformer_file: Path = None
    ) -> dict[str, "Variable"]:
        ans = {}
        if not schema_list:
            return ans
        python_loader = None
        if transformer_file:
            python_loader = PythonLoader(transformer_file)
        for item in schema_list:
            name = item["name"]
            field_path = item["fieldPath"]
            transform_map = item.get("map", {})
            func_transform_name = item.get("funcTransform")
            if (not python_loader) and func_transform_name:
                raise ValueError(
                    "Cannot load a transformer when its file is unspecified!"
                )
            func_transform = None
            if func_transform_name:
                func_transform = python_loader.functions[func_transform_name]
            ans[name] = Variable(name, field_path, transform_map, func_transform)
        return ans

    def __hash__(self):
        return self.name.__hash__()


class VariableRef:
    def __init__(self, identifier: str):
        self.original_identifier = identifier
        identifier_parts = identifier.split(".")
        self.name: str = identifier_parts[0]
        self.specifiers: set[str] = set(identifier_parts[1:])

    def __hash__(self):
        return self.original_identifier.__hash__()

    def resolve(self, base_value: list[Any], variable_def: Variable) -> Any:
        """
        Variable values are always returned in a list.
        However, we might want to include different data formats into the templates.
        To solve this, specifiers are introduced.
        """
        if "raw" in self.specifiers:
            ans = base_value
        elif variable_def.transformer:
            ans = variable_def.transformer(base_value)
        elif variable_def.value_map:
            ans = [variable_def.value_map.get(b, b) for b in base_value]
        else:
            ans = base_value
        if "unwrap" in self.specifiers or all(
            not isinstance(stmt, QueryParser) for stmt in variable_def.parsed_path
        ):
            return next(iter(ans), None)
        return ans


class FieldResolver:

    def __init__(self, variables: dict[str, Variable]):
        self._uninitialized_vars = variables

    def has_var(self, var_name: str) -> bool:
        return var_name in self._uninitialized_vars

    @property
    def var_definitions(self) -> dict[str, Variable]:
        return self._uninitialized_vars

    def resolve_variables(self, doc: dict[str, Any]) -> dict[str, list[Any]]:
        # first resolve dependency tree for variables
        dependencies = {}
        for variable in self._uninitialized_vars.values():
            dependencies[variable.name] = set()
            dependencies[variable.name].update(
                VariableRef(match.group("var_id")).name
                for match in re.finditer(VAR_REF_REGEX, variable.raw_field_path)
            )
            assert (
                variable.name not in dependencies[variable.name]
            ), f"Self referencing variable {variable.name} found."
        resolved_variables: dict[str, list] = {}
        while not all(var_name in resolved_variables for var_name in dependencies):
            # Get a var with no dependencies
            var_name, var_deps = sorted(dependencies.items(), key=lambda x: len(x[1]))[
                0
            ]
            assert (
                not var_deps
            ), f"Circular variable reference found for variable {var_name}"

            resolved_variables[var_name] = []

            def add_to_variable(value: Any) -> None:
                resolved_variables[var_name].append(value)

            path = PathParser(self._uninitialized_vars[var_name].raw_field_path).parse()
            try:
                self._run_on_path(
                    doc,
                    path,
                    resolved_variables,
                    "",
                    add_to_variable,
                    False,
                    set(),
                )
            except Exception as e:
                print(
                    f"Could not parse variable {var_name}, problem: {str(e)}",
                    file=sys.stderr,
                )

            dependencies.pop(var_name)
            for dep in dependencies.values():
                if var_name in dep:
                    dep.remove(var_name)
        return resolved_variables

    def _run_on_path(
        self,
        doc_: Union[dict, list[Any], FIELD_NOT_PRESENT],
        path: list[str | QueryParser | PathParser],
        variable_values: dict[str, Any],
        path_tried: str,
        func_to_run: Callable[[Any], Any],
        accept_not_present_field: bool,
        ran_on: set[str],
        create_nonexistent: bool = False,
    ):

        if not accept_not_present_field and doc_ is FIELD_NOT_PRESENT:
            raise FieldNotPresentError("Field not present: ", path_tried)
        if not path:
            # The path has ended
            try:
                resp = func_to_run(doc_)
                ran_on.add(path_tried)
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
                raise type(e)(message_to_return)
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
                if path[1] in doc_:
                    self._run_on_path(
                        doc_,
                        path[1:],
                        variable_values,
                        path_tried,
                        func_to_run,
                        accept_not_present_field,
                        ran_on,
                        create_nonexistent,
                    )
            else:
                if create_nonexistent and step not in doc_:
                    if path[1:] and isinstance(path[1], str):
                        # Add a dict
                        doc_[step] = {}
                    if path[1:] and isinstance(path[1], QueryParser):
                        # Add a list
                        doc_[step] = []
                self._run_on_path(
                    doc_.get(step, FIELD_NOT_PRESENT),
                    path[1:],
                    variable_values,
                    path_tried + f".{step}",
                    func_to_run,
                    accept_not_present_field,
                    ran_on,
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
                # Actually filter the list
                to_use_in_query = set()
                for idx, item in enumerate(doc_):
                    varname = query.variable
                    if query.type_ is QueryType.EQ:
                        if varname:
                            func = lambda x: x in variable_values[varname]
                        else:
                            func = lambda x: str(x) == query.value
                    elif query.type_ is QueryType.NEQ:
                        if varname:
                            func = lambda x: x not in variable_values[varname]
                        else:
                            func = lambda x: str(x) != query.value
                    elif query.type_ is QueryType.STARTSWITH:
                        if varname:
                            func = lambda x: isinstance(x, str) and any(
                                x.startswith(val) for val in variable_values[varname]
                            )
                        else:
                            func = lambda x: isinstance(x, str) and x.startswith(
                                query.value
                            )
                    elif query.type_ is QueryType.ENDSWITH:
                        if varname:
                            func = lambda x: isinstance(x, str) and any(
                                x.endswith(val) for val in variable_values[varname]
                            )
                        else:
                            func = lambda x: isinstance(x, str) and x.endswith(
                                query.value
                            )
                    final_func = lambda x: (
                        to_use_in_query.add(idx) if func(x) else None
                    )
                    self._run_on_path(
                        item,
                        query.field_path.parse(),
                        variable_values,
                        path_tried + f"[{idx}]",
                        final_func,
                        True,
                        set(),
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
                            ran_on,
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
                        ran_on,
                        create_nonexistent,
                    )

    def run_func(
        self,
        doc: dict[str, Any],
        func: Callable[[Any], Any],
        field_path: str | list[Union[str, QueryParser]],
        minimal_runs: int = 1,
        fallback_variables: dict[str, Any] | None = None,
        create_nonexistent: bool = False,
    ) -> Any:
        variables = {} if not fallback_variables else {**fallback_variables}
        variables.update(self.resolve_variables(doc))

        ran_on = set()
        path = (
            field_path
            if isinstance(field_path, list)
            else PathParser(field_path).parse()
        )
        self._run_on_path(
            doc,
            path,
            variables,
            "",
            func,
            False,
            ran_on,
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
    ) -> list[Any]:
        ans = []

        def add_to_ans(item: Any) -> None:
            ans.append(item)

        self.run_func(
            doc,
            add_to_ans,
            field_path,
            minimal_runs=0,
            fallback_variables=fallback_variables,
            create_nonexistent=create_nonexistent,
        )
        return ans

    def get_mutable_parent(
        self,
        doc: dict[str, Any],
        field_path: str | list[Union[str, QueryParser]],
        fallback_variables: dict[str, Any] | None = None,
        create_nonexistent: bool = False,
    ) -> list[Any]:
        if isinstance(field_path, list):
            parent_path = field_path[:-1]
        else:
            parent_path = PathParser(field_path).parse()[:-1]
        return self.get_objects(
            doc, parent_path, fallback_variables, create_nonexistent
        )

    def insert_at_path(
        self,
        doc: dict[str, Any],
        field_path: str | list[Union[str, QueryParser]],
        to_insert: Any,
        fallback_variables: dict[str, Any] | None = None,
    ) -> None:
        objects_to_mutate = self.get_mutable_parent(
            doc, field_path, fallback_variables, True
        )
        if isinstance(field_path, list):
            last_step_list = field_path[-1:]
        else:
            last_step_list = PathParser(field_path).parse()[-1:]
        last_step = next(iter(last_step_list), None)
        for obj in objects_to_mutate:
            if last_step is None:
                obj.update(to_insert)
            if isinstance(last_step, str):
                obj[last_step] = to_insert
            elif isinstance(last_step, QueryParser):
                obj.append(to_insert)
