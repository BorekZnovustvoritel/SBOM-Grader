import re
from typing import Union, Any, Callable

from core.definitions import FIELD_NOT_PRESENT, FieldNotPresentError


class FieldResolver:

    def __init__(self, variables: dict[str, str]):
        self._uninitialized_vars = variables

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
        resolved_variables = {}
        while not all(var_name in resolved_variables for var_name in dependencies):
            # Get a var with no dependencies
            var_name, var_deps = sorted(dependencies.items(), key=lambda x: len(x[1]))[
                0
            ]
            assert (
                not var_deps
            ), f"Circular variable reference found for variable {var_name}"

            self._run_on_path(
                doc,
                re.split(r"[\[\.\]]", self._uninitialized_vars[var_name]),
                resolved_variables,
                "",
                lambda x: resolved_variables.update({var_name: x}),
                True,
            )

            dependencies.pop(var_name)
            for dep in dependencies.values():
                if var_name in dep:
                    dep.remove(var_name)
        return resolved_variables

    def _run_on_path(
        self,
        doc_: Union[dict, list[Any], FIELD_NOT_PRESENT],
        path: list[str],
        variables: dict[str, Any],
        path_tried: str,
        func_to_run: Callable[[Any], Any],
        accept_not_present_field: bool,
    ):
        if not accept_not_present_field and doc_ is FIELD_NOT_PRESENT:
            raise FieldNotPresentError("Field not present: ", path_tried)
        if path:
            step = path[0]
            if match := re.match(
                r"^(?P<field>\w+)(?P<operation>[=!~]+)\${(?P<varname>\w+)}$", step
            ):
                # Variable query
                assert isinstance(
                    doc_, list
                ), f"Incorrect path to field: {path_tried}[{step}]"
                field_ = match.group("field")
                operation = match.group("operation")
                varname = match.group("varname")
                assert varname in variables, f"Unknown query variable: {varname}."
                for idx, item in enumerate(doc_):
                    field_val = item.get(field_, FIELD_NOT_PRESENT)
                    if operation == "!=" and field_val == variables[varname]:
                        continue
                    elif operation == "=" and field_val != variables[varname]:
                        continue
                    elif (
                        "~" in operation
                        and "!" not in operation
                        and field_val not in variables[varname]
                    ):
                        continue
                    elif (
                        "~" in operation
                        and "!" in operation
                        and field_val in variables[varname]
                    ):
                        continue
                    self._run_on_path(
                        item,
                        path[1:],
                        variables,
                        path_tried + f"[{idx}]",
                        func_to_run,
                        accept_not_present_field,
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
                    )

            elif "!=" in step:
                # Filter which fields to use
                assert isinstance(doc_, list), "Incorrect path to field."
                attr, check = step.split("!=")
                for idx, item in enumerate(doc_):
                    if check == "FIELD_NOT_PRESENT":
                        check = FIELD_NOT_PRESENT
                    if item.get(attr, FIELD_NOT_PRESENT) == check:
                        continue
                    self._run_on_path(
                        item,
                        path[1:],
                        variables,
                        path_tried + f"[{idx}]",
                        func_to_run,
                        accept_not_present_field,
                    )

            elif "=" in step:
                # Filter which fields to use
                assert isinstance(doc_, list), "Incorrect path to field."
                attr, check = step.split("=")
                for idx, item in enumerate(doc_):
                    if check == "FIELD_NOT_PRESENT":
                        check = FIELD_NOT_PRESENT
                    if item.get(attr, FIELD_NOT_PRESENT) != check:
                        continue
                    self._run_on_path(
                        item,
                        path[1:],
                        variables,
                        path_tried + f"[{idx}]",
                        func_to_run,
                        accept_not_present_field,
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
                )
        else:
            # The path has ended
            try:
                resp = func_to_run(doc_)
                assert resp is True or resp is None
            except Exception as e:
                message_to_return = (
                    f"Check did not pass for item: {doc_} at path: {path_tried}"
                    + "\n".join(str(m) for m in e.args)
                )
                raise type(e)(message_to_return)

    def run_func(
        self, doc: dict[str, Any], func: Callable[[Any], Any], field_path: str
    ) -> Any:
        path_list = re.split(r"[\[\.\]]", field_path)
        path_list = [item for item in path_list if item]
        variables = self.resolve_variables(doc)

        self._run_on_path(doc, path_list, variables, "", func, False)
