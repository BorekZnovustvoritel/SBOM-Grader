import re
import sys
from dataclasses import dataclass
from typing import Union, Any, Callable

from sbomgrader.core.definitions import (
    FIELD_NOT_PRESENT,
    FieldNotPresentError,
    MAX_ITEM_PREVIEW_LENGTH,
    START_PREVIEW_CHARS,
    END_PREVIEW_CHARS,
)
from sbomgrader.core.enums import QueryType


class PathParser:
    def __init__(self, path: str):
        self._path = path
        self.char_no = 0
        self.next_is_query = False

    def __create_field(
        self, field: str, next_is_query: bool
    ) -> Union[str, "QueryParser"]:
        if self.next_is_query:
            next_ = QueryParser(field)
        else:
            next_ = field.strip()
        self.next_is_query = next_is_query
        return next_

    def next(self) -> Union[str, list["QueryParser"], None]:
        in_block = 1 if self.next_is_query else 0
        buffer = ""
        for char in self._path[self.char_no :]:
            self.char_no += 1
            if char == "[":
                if not in_block:
                    return self.__create_field(buffer, True)
                buffer += char
                in_block += 1
            elif char == "]":
                in_block -= 1
                if not in_block:
                    return self.__create_field(buffer, False)
                buffer += char
            elif char == ".":
                if not in_block:
                    return self.__create_field(buffer, False)
                buffer += char
            else:
                buffer += char
        if buffer:
            return self.__create_field(buffer, False)
        return None

    @property
    def all(self) -> list[Union[str, "QueryParser"]]:
        backup = self.char_no
        self.char_no = 0
        ans = []
        step = self.next()
        while step is not None:
            ans.append(step)
            step = self.next()
        self.char_no = backup
        return ans


@dataclass
class Query:
    type_: QueryType
    value: str | None
    field_path: PathParser | None

    @property
    def variable(self) -> str | None:
        if self.value and (match := re.match(r"^\$\{(?P<varname>\w+)\}$", self.value)):
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


class FieldResolver:

    def __init__(self, variables: dict[str, str]):
        self._uninitialized_vars = variables

    def has_var(self, var_name: str) -> bool:
        return var_name in self._uninitialized_vars

    @property
    def var_definitions(self) -> dict[str, str]:
        return self._uninitialized_vars

    def resolve_variables(self, doc: dict[str, Any]) -> dict[str, set]:
        # first resolve dependency tree for variables
        dependencies = {}
        for variable_name, variable_path in self._uninitialized_vars.items():
            dependencies[variable_name] = set()
            dependencies[variable_name].update(
                match.group("varname")
                for match in re.finditer(r"\${(?P<varname>\w+)}", variable_path)
            )
            assert (
                variable_name not in dependencies[variable_name]
            ), f"Self referencing variable {variable_name} found."
        resolved_variables: dict[str, set] = {}
        while not all(var_name in resolved_variables for var_name in dependencies):
            # Get a var with no dependencies
            var_name, var_deps = sorted(dependencies.items(), key=lambda x: len(x[1]))[
                0
            ]
            assert (
                not var_deps
            ), f"Circular variable reference found for variable {var_name}"

            resolved_variables[var_name] = set()

            def add_to_variable(value: Any) -> None:
                resolved_variables[var_name].add(value)

            path = PathParser(self._uninitialized_vars[var_name]).all
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
        variables: dict[str, Any],
        path_tried: str,
        func_to_run: Callable[[Any], Any],
        accept_not_present_field: bool,
        ran_on: set[str],
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
                        variables,
                        path_tried,
                        func_to_run,
                        accept_not_present_field,
                        ran_on,
                    )
            else:
                self._run_on_path(
                    doc_.get(step, FIELD_NOT_PRESENT),
                    path[1:],
                    variables,
                    path_tried + f".{step}",
                    func_to_run,
                    accept_not_present_field,
                    ran_on,
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
                            func = lambda x: x in variables[varname]
                        else:
                            func = lambda x: str(x) == query.value
                    elif query.type_ is QueryType.NEQ:
                        if varname:
                            func = lambda x: x not in variables[varname]
                        else:
                            func = lambda x: str(x) != query.value
                    elif query.type_ is QueryType.STARTSWITH:
                        if varname:
                            func = lambda x: isinstance(x, str) and any(
                                x.startswith(val) for val in variables[varname]
                            )
                        else:
                            func = lambda x: isinstance(x, str) and x.startswith(
                                query.value
                            )
                    elif query.type_ is QueryType.ENDSWITH:
                        if varname:
                            func = lambda x: isinstance(x, str) and any(
                                x.endswith(val) for val in variables[varname]
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
                        query.field_path.all,
                        variables,
                        path_tried + f"[{idx}]",
                        final_func,
                        True,
                        set(),
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
                            variables,
                            path_tried + f"[{idx}]",
                            func_to_run,
                            accept_not_present_field,
                            ran_on,
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
                        variables,
                        path_tried + f"[{idx}]",
                        func_to_run,
                        accept_not_present_field,
                        ran_on,
                    )

    def run_func(
        self,
        doc: dict[str, Any],
        func: Callable[[Any], Any],
        field_path: str,
        minimal_runs: int = 1,
        fallback_variables: dict[str, Any] | None = None,
    ) -> Any:
        variables = {} if not fallback_variables else {**fallback_variables}
        variables.update(self.resolve_variables(doc))

        ran_on = set()
        self._run_on_path(
            doc, PathParser(field_path).all, variables, "", func, False, ran_on
        )
        assert (
            len(ran_on) >= minimal_runs
        ), "Test was not performed on any fields because no fields match given filters."
