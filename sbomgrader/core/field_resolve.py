import re
import sys
from dataclasses import dataclass
from typing import Union, Any, Callable

from black.trans import defaultdict

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
        self.ans: dict[str, list[Union[str, QueryParser]]] = defaultdict(list)

    def __create_field(
        self, field: str, next_is_query: bool, relative_path: str
    ) -> None:
        if self.__next_is_query:
            raw_field_path = field
            if field.startswith("@"):
                raw_field_path = field.replace("@", relative_path, 1)
            next_ = QueryParser(raw_field_path)
        else:
            next_ = field.strip()
        self.__next_is_query = next_is_query

        if next_:
            self.ans[relative_path].append(next_)

    def parse(
        self, relative_path: str | None = None
    ) -> list[Union[str, "QueryParser"]]:
        relative_path = relative_path or ""
        if relative_path in self.ans:
            return self.ans[relative_path]
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
                    self.__create_field(buffer, True, relative_path)
                    buffer = ""
                else:
                    buffer += char
                in_block += 1
            elif char == "]":
                in_block -= 1
                if not in_block:
                    self.__create_field(buffer, False, relative_path)
                    buffer = ""
                else:
                    buffer += char
            elif char == ".":
                if not in_block:
                    self.__create_field(buffer, False, relative_path)
                    buffer = ""
                else:
                    buffer += char
            else:
                buffer += char
        if buffer:
            self.__create_field(buffer, False, relative_path)
        return self.ans[relative_path]


@dataclass
class Query:
    type_: QueryType
    value: str | int | None
    field_path: PathParser | None

    @property
    def variable(self) -> str | None:
        if self.value and (match := re.match(r"^\$\{(?P<varname>\w+)}$", self.value)):
            return match.group("varname")


class QueryParser:
    def __init__(self, path: str):
        self._path = path

    def __eq__(self, other):
        if not isinstance(other, QueryParser):
            raise TypeError(
                f"Cannot compare QueryParser to object of type {type(other)}"
            )
        return self._path == other._path

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
            if (
                (m := re.fullmatch(r"\d+", field_buffer))
                and not operation_buffer
                and not value_buffer
            ):
                query = Query(
                    type_=QueryType.INDEX, field_path=None, value=int(m.group())
                )
            else:
                query = Query(
                    type_=QueryType(operation_buffer.strip()),
                    field_path=PathParser(field_buffer.strip()),
                    value=value_buffer.strip(),
                )
            queries.append(query)
        return queries


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
        ans = {}
        if not schema_list:
            return ans
        for item in schema_list:
            name = item["name"]
            field_path = item["fieldPath"]
            ans[name] = Variable(name, field_path)
        return ans

    @property
    def is_relative(self) -> bool:
        return self.raw_field_path.startswith("@.")

    def __hash__(self):
        return self.name.__hash__()

    def __repr__(self):
        return f"<{self.__class__.__name__}, name: {self.name}, field_path: {self.raw_field_path}>"


class VariableRef:
    def __init__(self, identifier: str):
        self.original_identifier = identifier
        self.name: str = identifier

    def __hash__(self):
        return self.original_identifier.__hash__()


class FieldResolver:

    def __init__(self, variables: dict[str, Variable]):
        self._uninitialized_vars = variables

    def has_var(self, var_name: str) -> bool:
        return var_name in self._uninitialized_vars

    @property
    def var_definitions(self) -> dict[str, Variable]:
        return self._uninitialized_vars

    @property
    def absolute_variables(self) -> dict[str, Variable]:
        return {
            key: val
            for key, val in self._uninitialized_vars.items()
            if not val.is_relative
        }

    @property
    def relative_variables(self) -> dict[str, Variable]:
        return {
            key: val for key, val in self._uninitialized_vars.items() if val.is_relative
        }

    def resolve_variables(
        self,
        whole_doc: dict[str, Any],
        path_to_instance: str | None = None,
        warning_on: bool = True,
    ) -> dict[str, list[Any]]:
        """
        Resolve dependencies.
        Without the argument `path_to_instance` this method cannot resolve relative variables
        nor absolute variables relying on relative ones.
        """
        # first resolve dependency tree for variables
        dependencies = {}
        if path_to_instance:
            vars_to_resolve = self._uninitialized_vars
        else:
            vars_to_resolve = self.absolute_variables
        for variable in vars_to_resolve.values():
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
            if not path_to_instance and any(
                self._uninitialized_vars[dep_name].is_relative for dep_name in var_deps
            ):
                # Cannot resolve absolute variable referencing a relative one
                dependencies.pop(var_name)
                continue
            assert (
                not var_deps
            ), f"Circular variable reference found for variable {var_name}"

            resolved_variables[var_name] = []

            def add_to_variable(value: Any) -> None:
                resolved_variables[var_name].append(value)

            path = vars_to_resolve[var_name].path_parser.parse(path_to_instance)
            try:
                self._run_on_path(
                    whole_doc,
                    path,
                    resolved_variables,
                    "",
                    add_to_variable,
                    False,
                    set(),
                )
            except Exception as e:
                if warning_on:
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
                elif query.type_ is QueryType.INDEX:
                    to_use.append({query.value})
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

    @staticmethod
    def __parse_field_path(
        field_path: str | list[Union[str, QueryParser]]
    ) -> list[Union[str, QueryParser]]:
        return (
            field_path
            if isinstance(field_path, list)
            else PathParser(field_path).parse()
        )

    def __populate_variables(
        self,
        doc: dict[str, Any],
        fallback_values: dict[str, Any],
        allow_fail: bool = False,
    ) -> dict[str, Any]:
        variables = {} if not fallback_values else {**fallback_values}
        resolved_vars = self.resolve_variables(doc, warning_on=not allow_fail)
        resolved_vars = {
            k: [i for i in v if i and i is not FIELD_NOT_PRESENT]
            for k, v in resolved_vars.items()
            if v
        }
        variables.update(resolved_vars)
        return variables

    def run_func(
        self,
        doc: dict[str, Any],
        func: Callable[[Any], Any],
        field_path: str | list[Union[str, QueryParser]],
        minimal_runs: int = 1,
        fallback_variables: dict[str, Any] | None = None,
        create_nonexistent: bool = False,
    ) -> Any:
        ran_on = set()

        self._run_on_path(
            doc,
            self.__parse_field_path(field_path),
            self.__populate_variables(doc, fallback_variables, create_nonexistent),
            "",
            func,
            create_nonexistent,
            ran_on,
            create_nonexistent,
        )
        assert (
            len(ran_on) >= minimal_runs
        ), "Test was not performed on any fields because no fields match given filters."

    def get_paths(
        self,
        doc: dict[str, Any],
        field_path: str | list[Union[str, QueryParser]],
        fallback_variables: dict[str, Any],
    ) -> list[str]:
        paths = set()
        self._run_on_path(
            doc,
            self.__parse_field_path(field_path),
            self.__populate_variables(doc, fallback_variables),
            "",
            lambda _: None,
            False,
            paths,
            False,
        )
        return list(paths)

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
        path = self.__parse_field_path(field_path)
        if create_nonexistent:
            # create parents
            self.get_objects(doc, path, fallback_variables, create_nonexistent)
        # fetch parents
        return self.get_objects(doc, path[:-1], fallback_variables, create_nonexistent)

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
