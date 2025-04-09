from collections import defaultdict
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Callable

from sbomgrader.core.documents import Document
from sbomgrader.core.enums import ResultType
from sbomgrader.core.field_resolve import FieldResolver, Variable
from sbomgrader.core.formats import SBOMFormat
from sbomgrader.grade.rule_loader import RuleLoader
from sbomgrader.core.definitions import (
    RULESET_VALIDATION_SCHEMA_PATH,
    FIELD_NOT_PRESENT,
    FieldNotPresentError,
    operation_map,
)
from sbomgrader.core.utils import get_mapping, get_path_to_implementations


@dataclass
class ResultDetail:
    rule_name: str
    result_type: ResultType
    result_detail: str | None


@dataclass
class Result:
    ran: set[str] = field(default_factory=set)
    failed: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    skipped: set[str] = field(default_factory=set)
    not_implemented: set[str] = field(default_factory=set)

    def __add__(self, other: "Result") -> "Result":
        if not isinstance(other, Result):
            raise TypeError(f"Cannot add Result and {type(other)}")
        return Result(
            failed=self.failed | other.failed,
            ran=self.ran | other.ran,
            errors=self.errors | other.errors,
            skipped=self.skipped | other.skipped,
            not_implemented=self.not_implemented | other.not_implemented,
        )

    def get(self, rule_name: str) -> ResultDetail:
        if rule_name in self.failed:
            return ResultDetail(
                rule_name=rule_name,
                result_type=ResultType.FAILED,
                result_detail=self.failed[rule_name],
            )
        if rule_name in self.errors:
            return ResultDetail(
                rule_name=rule_name,
                result_type=ResultType.ERROR,
                result_detail=self.errors[rule_name],
            )
        if rule_name in self.skipped:
            return ResultDetail(
                rule_name=rule_name,
                result_type=ResultType.SKIPPED,
                result_detail="Rule was not present in the cookbook.",
            )
        if rule_name in self.not_implemented:
            return ResultDetail(
                rule_name=rule_name,
                result_type=ResultType.NOT_IMPLEMENTED,
                result_detail="No implementation found for the document type.",
            )
        if rule_name in self.ran:
            return ResultDetail(
                rule_name=rule_name,
                result_type=ResultType.SUCCESS,
                result_detail="Success.",
            )
        return ResultDetail(
            rule_name=rule_name,
            result_type=ResultType.NOT_PRESENT,
            result_detail="Rule is not present in any RuleSet.",
        )


@dataclass
class Rule:
    name: str
    func: Callable
    error_message: str
    field_path: str
    minimum_tested_elements: int
    field_resolver: FieldResolver

    def __call__(
        self,
        doc: list[dict] | dict | Document,
        fallback_vars: dict[str, Any] | None = None,
    ) -> Result:
        if isinstance(doc, dict):
            doc = Document(doc)

        result = Result(ran={self.name})
        field_path = self.field_path or ""
        fallback_vars = {} if not fallback_vars else fallback_vars
        try:
            self.field_resolver.run_func(
                doc.doc,
                self.func,
                field_path,
                self.minimum_tested_elements,
                fallback_variables=fallback_vars,
            )

        except AssertionError as e:
            message_to_return = self.error_message
            if e.args:
                message_to_return += "\nDetail from runtime: " + "\n".join(
                    str(m) for m in e.args
                )
            result.failed[self.name] = message_to_return
        except FieldNotPresentError as e:
            result.failed[self.name] = (
                self.error_message + " Field not present: " + e.args[1]
            )
        except Exception as e:
            result.errors[self.name] = str(type(e)) + " " + str(e)
        return result


class RuleSet:
    @staticmethod
    def from_file(file: str | Path):
        schema_dict = get_mapping(file, RULESET_VALIDATION_SCHEMA_PATH)

        implementation_loaders: dict[str, RuleLoader] = {}

        for implementation_file in get_path_to_implementations(file).iterdir():
            implementation_name = implementation_file.name.rsplit(".", 1)[0]
            implementation_loaders[implementation_name] = RuleLoader(
                implementation_name, implementation_file
            )

        global_variable_definitions = {}
        for implementation_obj in schema_dict.get("variables", {}).get(
            "implementations", []
        ):

            implementation = implementation_obj["name"]
            global_variable_definitions[implementation] = {}
            for var_obj in implementation_obj["variables"]:
                global_variable_definitions[implementation][var_obj["name"]] = Variable(
                    var_obj["name"], var_obj["fieldPath"]
                )

        all_rules = defaultdict(dict)
        for rule in schema_dict["rules"]:
            name = rule["name"]
            implementations = rule["implementations"]
            failure_message = rule["failureMessage"]
            for spec in implementations:
                implementation_name = spec["name"]
                field_path = spec.get("fieldPath")
                checker = spec["checker"]
                # TODO rework for more than one operation
                operation = next(iter(checker.keys()))

                check_against = checker[operation]
                if check_against == FIELD_NOT_PRESENT.string_repr:
                    check_against = FIELD_NOT_PRESENT
                elif isinstance(check_against, list):
                    contains_field_not_present = (
                        FIELD_NOT_PRESENT.string_repr in check_against
                    )
                    check_against = [
                        item
                        for item in check_against
                        if item != FIELD_NOT_PRESENT.string_repr
                    ]
                    if contains_field_not_present:
                        check_against.append(FIELD_NOT_PRESENT)
                func = operation_map[operation]

                if not callable(func):
                    # load func according to name
                    func = implementation_loaders[implementation_name].load_func(
                        check_against
                    )
                else:
                    func = partial(func, check_against)

                var_dict = {}
                spec_variables = spec.get("variables", [])
                for var_obj in spec_variables:
                    var_dict[var_obj["name"]] = Variable(
                        var_obj["name"], var_obj["fieldPath"]
                    )

                minimum_tested_elements = spec.get("minimumTestedElements", 1)
                failure_message = spec.get("failureMessage") or failure_message

                all_rules[implementation_name][name] = Rule(
                    name=name,
                    func=func,
                    error_message=failure_message,
                    field_path=field_path,
                    field_resolver=FieldResolver(var_dict),
                    minimum_tested_elements=minimum_tested_elements,
                )
        all_rule_names = {rule["name"] for rule in schema_dict["rules"]}
        return RuleSet(
            implementation_loaders=implementation_loaders,
            rules=all_rules,
            all_rule_names=all_rule_names,
            variables=global_variable_definitions,
        )

    def __init__(
        self,
        rules: dict[str, dict[str, Callable]] | None = None,
        implementation_loaders: dict[str, RuleLoader] | None = None,
        all_rule_names: set[str] | None = None,
        selection: set[str] | None = None,
        variables: dict[str, dict[str, Variable]] | None = None,
    ):
        self.implementation_loaders = implementation_loaders or {}
        self.rules = rules or {}
        self.all_rule_names = all_rule_names or set()
        self.selection = selection if selection is not None else self.all_rule_names
        self.field_resolvers = {}
        if not variables:
            variables = {}
        for implementation, var_dict in variables.items():
            self.field_resolvers[implementation] = FieldResolver(var_dict)

    @property
    def formats(self) -> set[SBOMFormat]:
        return {SBOMFormat(k) for k in self.rules}

    def format_for_doc(self, doc: Document) -> SBOMFormat | None:
        if doc.sbom_format in self.formats:
            return doc.sbom_format
        fallbacks = doc.sbom_format_fallback
        for format_ in self.formats:
            if format_ in fallbacks:
                return format_
        return None

    def __add__(self, other: "RuleSet"):
        if not isinstance(other, RuleSet):
            raise TypeError(f"Cannot combine RuleSet with instance of {type(other)}!")
        implementation_loaders = {}
        for implementation in [
            *self.implementation_loaders.keys(),
            *other.implementation_loaders.keys(),
        ]:
            new_loader = RuleLoader(implementation)
            self_loader = self.implementation_loaders.get(implementation, None)
            other_loader = other.implementation_loaders.get(implementation, None)
            if self_loader:
                new_loader.add_file_references(*self_loader.file_references)
            if other_loader:
                new_loader.add_file_references(*other_loader.file_references)
            implementation_loaders[implementation] = new_loader

        new_rules = {}
        for implementation in [*self.rules.keys(), *other.rules.keys()]:
            new_rules[implementation] = {
                **self.rules.get(implementation, {}),
                **other.rules.get(implementation, {}),
            }
        variable_definitions = {}
        for implementation in [*self.field_resolvers.keys(), *other.rules.keys()]:
            variable_definitions[implementation] = {}
            self_resolver = self.field_resolvers.get(implementation)
            if self_resolver:
                variable_definitions[implementation].update(
                    self_resolver.var_definitions
                )
            other_resolver = other.field_resolvers.get(implementation)
            if other_resolver:
                variable_definitions[implementation].update(
                    other_resolver.var_definitions
                )
        return RuleSet(
            rules=new_rules,
            all_rule_names=self.all_rule_names | other.all_rule_names,
            selection=self.selection | other.selection,
            implementation_loaders=implementation_loaders,
            variables=variable_definitions,
        )

    def __call__(self, document: dict | Document) -> Result:
        res = Result()
        if isinstance(document, dict):
            document = Document(document)
        format_ = self.format_for_doc(document).value
        global_variables_resolver = self.field_resolvers.get(format_)
        global_variables = {}
        if global_variables_resolver:
            global_variables = global_variables_resolver.resolve_variables(document.doc)

        for rule in self.all_rule_names:
            if rule not in self.selection:
                res.skipped.add(rule)
                continue
            if rule_obj := self.rules.get(format_, {}).get(rule):
                rule_obj: Rule | None
                if not callable(rule_obj):
                    res.not_implemented.add(rule)
                else:
                    res += rule_obj(document, fallback_vars=global_variables)
            else:
                res.not_implemented.add(rule)
        return res
