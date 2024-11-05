import re
from collections import defaultdict
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Callable, Iterable, Sized, Generator, Union

from jsonschema.validators import validate

from .rule_loader import RuleLoader
from definitions import (
    RULESET_VALIDATION_SCHEMA_PATH,
    get_mapping,
    get_path_to_implementations,
    Implementation,
    Selector,
    SBOM_FORMAT_DEFINITION_MAPPING,
    RuleForce,
)


class __FieldNotPresent:
    def __repr__(self):
        return "Field not present."

    def get(self, *_):
        return self


FIELD_NOT_PRESENT = __FieldNotPresent()

operation_map = {
    "eq": lambda expected, actual: expected == actual,
    "neq": lambda expected, actual: expected != actual,
    "in": lambda expected, actual: actual in expected,
    "not_in": lambda expected, actual: actual not in expected,
    "str_startswith": lambda expected, actual: isinstance(actual, str)
    and actual.startswith(expected),
    "str_endswith": lambda expected, actual: isinstance(actual, str)
    and actual.endswith(expected),
    "str_contains": lambda expected, actual: isinstance(actual, str)
    and actual in expected,
    "str_matches_regex": lambda expected, actual: isinstance(actual, str)
    and bool(re.match(expected, actual)),
    "length_eq": lambda expected, actual: isinstance(actual, Sized)
    and len(actual) == expected,
    "length_gt": lambda expected, actual: isinstance(actual, Sized)
    and len(actual) > expected,
    "length_lt": lambda expected, actual: isinstance(actual, Sized)
    and len(actual) < expected,
    "func_name": None,
}


class Document:
    def __init__(self, document_dict: dict[str, Any]):
        self._doc = document_dict

    @property
    def implementation(self) -> Implementation:
        for item in Implementation:
            field_to_check = SBOM_FORMAT_DEFINITION_MAPPING[item]

            if self._doc.get(next(iter(field_to_check.keys()))) == next(
                iter(field_to_check.values())
            ):
                return item
        raise ValueError("Document is in an unknown standard.")


@dataclass
class Result:
    ran: set[str] = field(default_factory=set)
    failed: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    skipped: set[str] = field(default_factory=set)
    not_implemented: set[str] = field(default_factory=set)

    def __add__(self, other: "Result"):
        if not isinstance(other, Result):
            raise TypeError(f"Cannot add Result and {type(other)}")
        return Result(
            failed=self.failed | other.failed,
            ran=self.ran | other.ran,
            errors=self.errors | other.errors,
            skipped=self.skipped | other.skipped,
        )


class FieldNotPresentError(ValueError):
    pass


@dataclass
class Rule:
    name: str
    func: Callable
    error_message: str
    field_path: str
    skippable: bool

    def __call__(self, doc: list[dict] | dict | Document) -> Result:
        if isinstance(doc, dict):
            doc = Document(doc)

        def run_on_path(
            doc_: Union[dict, list[Any], FIELD_NOT_PRESENT],
            path: list[str],
            path_tried: str,
        ):
            if doc_ is FIELD_NOT_PRESENT:
                raise FieldNotPresentError("Field not present: ", path_tried)
            if path:
                step = path[0]
                if step == "|":
                    # Any
                    assert isinstance(doc_, list), "Incorrect path to field."
                    failed = 0
                    assertions = []
                    for idx, item in enumerate(doc_):
                        try:
                            run_on_path(item, path[1:], path_tried + f"[{idx}]")
                        except (AssertionError, FieldNotPresentError) as e:
                            failed += 1
                            assertions.append(e)
                    assert failed < len(
                        doc_
                    ), f"Check did not pass for any fields. Assertions: {assertions}, path: {path_tried}"

                elif step == "&":
                    # Each
                    assert isinstance(doc_, list), "Incorrect path to field."
                    for idx, item in enumerate(doc_):
                        run_on_path(item, path[1:], path_tried + f"[{idx}]")

                elif step.isdigit():
                    assert isinstance(doc_, list), "Incorrect path to field."
                    # Element on an index
                    run_on_path(doc_[int(step)], path[1:], path_tried + f"[{step}]")

                else:
                    # Name of the field
                    run_on_path(
                        doc_.get(step, FIELD_NOT_PRESENT),
                        path[1:],
                        path_tried + f".{step}",
                    )
            else:
                # The path has ended
                resp = self.func(doc_)
                assert (
                    resp is True or resp is None
                ), f"Check did not pass for item: {doc_} at path: {path_tried}"

        result = Result(ran={self.name})
        field_path = self.field_path or ""
        path_list = re.split(r"[\[\.\]]", field_path)
        path_list = [item for item in path_list if item]
        try:
            run_on_path(doc._doc, path_list, "")

        except AssertionError as e:
            message_to_return = self.error_message
            if e.args:
                message_to_return += "\nDetail from runtime: " + "\n".join(
                    str(m) for m in e.args
                )
            result.failed[self.name] = message_to_return
        except FieldNotPresentError as e:
            if self.skippable:
                result.skipped.add(self.name)
            else:
                result.failed[self.name] = (
                    self.error_message + " Field not present: " + e.args[1]
                )
        except Exception as e:
            result.errors[self.name] = str(e)
        return result


class RuleSet:
    @staticmethod
    def from_schema(schema: str | Path):
        schema_dict = get_mapping(schema)

        validate(schema_dict, get_mapping(RULESET_VALIDATION_SCHEMA_PATH))

        implementation_loaders: dict[str, RuleLoader] = {}

        for implementation_file in get_path_to_implementations(schema).iterdir():
            implementation_name = implementation_file.name.rsplit(".", 1)[0]
            implementation_loaders[implementation_name] = RuleLoader(
                implementation_name, implementation_file
            )

        all_rules = defaultdict(dict)
        for rule in schema_dict["rules"]:
            name = rule["name"]
            implementations = rule["implementations"]
            failure_message = rule["failureMessage"]
            for spec in implementations:
                implementation_name = spec["name"]
                field_path = spec.get("fieldPath")
                selector = spec.get("selector")
                checker = spec["checker"]
                # TODO rework for more than one operation
                operation = next(iter(checker.keys()))

                check_against = checker[operation]
                if check_against == "FIELD_NOT_PRESENT":
                    check_against = FIELD_NOT_PRESENT
                elif isinstance(check_against, list):
                    contains_field_not_present = "FIELD_NOT_PRESENT" in check_against
                    check_against = [
                        item for item in check_against if item != "FIELD_NOT_PRESENT"
                    ]
                    if contains_field_not_present:
                        check_against.append(FIELD_NOT_PRESENT)
                func = operation_map[operation]

                if not callable(func):
                    # load func according to name
                    func = implementation_loaders[implementation_name].load_rule(
                        check_against
                    )
                else:
                    func = partial(func, check_against)
                all_rules[implementation_name][name] = Rule(
                    name=name,
                    func=func,
                    error_message=failure_message,
                    field_path=field_path,
                    # selector=selector,
                    skippable=spec.get("skippable", False),
                )
        all_rule_names = {rule["name"] for rule in schema_dict["rules"]}
        return RuleSet(
            implementation_loaders=implementation_loaders,
            rules=all_rules,
            all_rule_names=all_rule_names,
        )

    def __init__(
        self,
        rules: dict[str, dict[str, Callable]] | None = None,
        implementation_loaders: dict[str, RuleLoader] | None = None,
        all_rule_names: set[str] | None = None,
        selection: set[str] | None = None,
        weights_override: dict[str, RuleForce] | None = None,
    ):
        self.implementation_loaders = implementation_loaders or {}
        self.rules = rules or {}
        self.all_rule_names = all_rule_names or set()
        self.selection = selection or self.all_rule_names
        self.weights_override = weights_override or {}

    def __add__(self, other: "RuleSet"):
        if not isinstance(other, RuleSet):
            raise TypeError(f"Cannot combine RuleSet with instance of {type(other)}!")
        return RuleSet(
            rules=(self.rules | other.rules),
            all_rule_names=self.all_rule_names | other.all_rule_names,
            selection=self.selection | other.selection,
        )

    def __call__(self, document: dict | Document) -> Result:
        res = Result()
        if isinstance(document, dict):
            document = Document(document)
        implementation = document.implementation.value
        for rule in self.all_rule_names:
            if rule not in self.selection:
                res.skipped.add(rule)
                continue
            if rule_obj := self.rules.get(implementation, {}).get(rule):
                rule_obj: Rule | None
                if not callable(rule_obj.func):
                    res.not_implemented.add(rule)
                else:
                    res += rule_obj(document)
            else:
                res.not_implemented.add(rule)
        return res

    def apply_weights(self, weights: dict[str, RuleForce]):
        self.weights_override = weights
