import re
from collections import defaultdict
from typing import Union, Any, Callable

from core.definitions import FIELD_NOT_PRESENT, FieldNotPresentError


class FieldResolver:

    def __init__(self, variables: dict[str, str]):
        self._uninitialized_vars = variables

    def has_var(self, var_name: str) -> bool:
        return var_name in self._uninitialized_vars

    @property
    def var_definitions(self) -> dict[str, str]:
        return self._uninitialized_vars

    def resolve_variables(self, doc: dict[str, Any]) -> dict[str, Any]:
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
        resolved_variables = defaultdict(set)
        while not all(var_name in resolved_variables for var_name in dependencies):
            # Get a var with no dependencies
            var_name, var_deps = sorted(dependencies.items(), key=lambda x: len(x[1]))[
                0
            ]
            assert (
                not var_deps
            ), f"Circular variable reference found for variable {var_name}"

            def add_to_variable(value: Any) -> None:
                resolved_variables[var_name].add(value)

            self._run_on_path(
                doc,
                re.split(r"[\[\.\]]", self._uninitialized_vars[var_name]),
                resolved_variables,
                "",
                add_to_variable,
                True,
                set(),
            )

            dependencies.pop(var_name)
            for dep in dependencies.values():
                if var_name in dep:
                    dep.remove(var_name)
        return dict(resolved_variables)

    def _run_on_path(
        self,
        doc_: Union[dict, list[Any], FIELD_NOT_PRESENT],
        path: list[str],
        variables: dict[str, Any],
        path_tried: str,
        func_to_run: Callable[[Any], Any],
        accept_not_present_field: bool,
        ran_on: set[str],
    ):
        if not accept_not_present_field and doc_ is FIELD_NOT_PRESENT:
            raise FieldNotPresentError("Field not present: ", path_tried)
        if path:
            step = path[0]
            if "=" in step:
                # Query
                assert isinstance(
                    doc_, list
                ), f"Incorrect path to field: {path_tried}[{step}]"
                sub_queries = step.split(",")
                fields_to_skip = set()
                for sub_query in sub_queries:
                    if match := re.match(
                        r"^(?P<field>\w+)(?P<operation>[=!]+)\${(?P<varname>\w+)}$",
                        sub_query,
                    ):
                        field_ = match.group("field")
                        operation = match.group("operation")
                        varname = match.group("varname")
                        assert (
                            varname in variables
                        ), f"Unknown query variable: {varname}."
                        val_to_check = variables[varname]
                        is_variable = True
                    else:
                        match = re.match(
                            r"^(?P<field>\w+)(?P<operation>[=!]+)(?P<val>[\w\-\.]+)$",
                            sub_query,
                        )
                        field_ = match.group("field")
                        operation = match.group("operation")
                        val_to_check = match.group("val")
                        is_variable = False
                    for idx, item in enumerate(doc_):
                        field_val = item.get(field_, FIELD_NOT_PRESENT)

                        if operation == "!=" and (
                            # Vals from variables are always a set
                            (not is_variable and field_val == val_to_check)
                            or (is_variable and field_val in val_to_check)
                        ):
                            fields_to_skip.add(idx)
                        elif operation == "=" and (
                            # Vals from variables are always a set
                            (not is_variable and field_val != val_to_check)
                            or (is_variable and field_val not in val_to_check)
                        ):
                            fields_to_skip.add(idx)
                for idx, item in enumerate(doc_):
                    if idx in fields_to_skip:
                        continue
                    self._run_on_path(
                        item,
                        path[1:],
                        variables,
                        path_tried + f"[{idx}]",
                        func_to_run,
                        accept_not_present_field,
                        ran_on,
                    )

            elif step == "|":
                # Any
                assert isinstance(
                    doc_, list
                ), f"Incorrect path to field: {path_tried}[|]."
                failed = 0
                assertions = []
                for idx, item in enumerate(doc_):
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
                    doc_
                ), f"Check did not pass for any fields. Assertions: {assertions}, path: {path_tried}"

            elif step == "&":
                # Each
                assert isinstance(
                    doc_, list
                ), f"Incorrect path to field: {path_tried}[&]."
                for idx, item in enumerate(doc_):
                    self._run_on_path(
                        item,
                        path[1:],
                        variables,
                        path_tried + f"[{idx}]",
                        func_to_run,
                        accept_not_present_field,
                        ran_on,
                    )

            elif step == "?":
                # Skippable if not present
                assert isinstance(
                    doc_, dict
                ), "Skippable fields only apply on dictionaries"
                if path[1:] and path[1] in doc_:
                    self._run_on_path(
                        doc_.get(path[1]),
                        path[2:],
                        variables,
                        path_tried,
                        func_to_run,
                        accept_not_present_field,
                        ran_on,
                    )

            elif step.isdigit():
                # Element on an index
                assert isinstance(
                    doc_, list
                ), f"Incorrect path to field: {path_tried}[{step}]"
                self._run_on_path(
                    doc_[int(step)],
                    path[1:],
                    variables,
                    path_tried + f"[{step}]",
                    func_to_run,
                    accept_not_present_field,
                    ran_on,
                )

            else:
                # Name of the field
                self._run_on_path(
                    doc_.get(step, FIELD_NOT_PRESENT),
                    path[1:],
                    variables,
                    path_tried + f".{step}",
                    func_to_run,
                    accept_not_present_field,
                    ran_on,
                )
        else:
            # The path has ended
            try:
                resp = func_to_run(doc_)
                ran_on.add(path_tried)
                assert resp is True or resp is None
            except Exception as e:
                message_to_return = (
                    f"Check did not pass for item: {doc_} at path: {path_tried}"
                    + "\n".join(str(m) for m in e.args)
                )
                raise type(e)(message_to_return)

    def run_func(
        self,
        doc: dict[str, Any],
        func: Callable[[Any], Any],
        field_path: str,
        minimal_runs: int = 1,
        fallback_variables: dict[str, Any] | None = None,
    ) -> Any:
        path_list = re.split(r"[\[\.\]]", field_path)
        path_list = [item for item in path_list if item]
        variables = {} if not fallback_variables else {**fallback_variables}
        variables.update(self.resolve_variables(doc))

        ran_on = set()
        self._run_on_path(doc, path_list, variables, "", func, False, ran_on)
        assert (
            len(ran_on) >= minimal_runs
        ), "Test was not performed on any fields because no fields match given filters."
