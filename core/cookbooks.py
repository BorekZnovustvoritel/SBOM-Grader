import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Any

import yaml
from jsonschema.validators import validate
from sympy import euler

from core.enums import Grade, RuleForce, OutputType, ResultType
from core.utils import get_mapping
from core.definitions import (
    COOKBOOK_VALIDATION_SCHEMA_PATH,
    RULESET_DIR,
    ROOT_DIR,
)
from core.rules import RuleSet, Document, Result, ResultDetail


@dataclass
class CookbookResult:
    result: Result
    cookbook: "Cookbook"

    def __get_by_force(self, force: RuleForce) -> Iterable[ResultDetail]:
        return [
            self.result.get(name)
            for name in getattr(self.cookbook, force.value.lower())
        ]

    @property
    def must(self) -> Iterable[ResultDetail]:
        return self.__get_by_force(RuleForce.MUST)

    @property
    def should(self) -> Iterable[ResultDetail]:
        return self.__get_by_force(RuleForce.SHOULD)

    @property
    def may(self) -> Iterable[ResultDetail]:
        return self.__get_by_force(RuleForce.MAY)

    @property
    def grade(self) -> Grade:
        unsuccessful = self.get_unsuccessful()
        if unsuccessful.must:
            return Grade.F
        grade = Grade.A
        for _ in unsuccessful.should:
            grade = Grade.lower(grade)
        return grade

    def get(self, rule_name: str):
        return self.result.get(rule_name)

    def get_unsuccessful(self) -> "CookbookResult":

        failed = self.result.failed
        error = self.result.errors
        unsuccessful = set(failed.keys())
        unsuccessful.update(error.keys())
        new_must = set(filter(lambda x: x in unsuccessful, self.cookbook.must))
        new_should = set(filter(lambda x: x in unsuccessful, self.cookbook.should))
        new_may = set(filter(lambda x: x in unsuccessful, self.cookbook.may))
        return CookbookResult(
            Result(unsuccessful, failed, error),
            Cookbook(
                self.cookbook.name,
                self.cookbook.ruleset_names,
                new_must,
                new_should,
                new_may,
            ),
        )

    def output(self, o_type: OutputType) -> str:
        if o_type is OutputType.VISUAL:
            ans = f"# Cookbook: {self.cookbook.name}\n"
            ans += "\n## Summary\n"
            ans += f"\nAchieved grade: {self.grade.value}\n"
            for force in RuleForce:
                ans += f"\n### {force.value}:\n\n"
                for result_detail in self.__get_by_force(force):
                    detail = self.get(result_detail.rule_name)
                    ans += f"- {result_detail.rule_name} {ResultType.get_visual(detail.result_type)}\n"
            unsuccessful = self.get_unsuccessful()
            if unsuccessful.cookbook.all_used_rule_names:
                ans += "\n## Failure details\n\n"
                for rule in unsuccessful.result.failed:
                    ans += f"\n### {rule}\n\n"
                    detail = self.get(rule)
                    ans += f"{detail.result_detail}\n"

            return ans
        if o_type is OutputType.JSON:
            return json.dumps(self.to_dict(), indent=4)
        return yaml.dump(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        ans = {"cookbook_name": self.cookbook.name, "grade": self.grade.value}
        for force in RuleForce:
            ans[force.value] = {}
            for result_detail in self.__get_by_force(force):
                ans[force.value][result_detail.rule_name] = {}
                ans[force.value][result_detail.rule_name][
                    result_detail.result_type.value
                ] = result_detail.result_detail
        return ans


class Cookbook:
    def __init__(
        self,
        name: str,
        ruleset_names: Iterable[str],
        must: Iterable[str],
        should: Iterable[str],
        may: Iterable[str],
    ):
        self.name = name
        self.ruleset_names = ruleset_names
        self._initialized_ruleset: RuleSet | None = None
        self.__is_initialized: bool = False
        self.must = set(must)
        self.should = set(should)
        self.may = set(may)

    @property
    def ruleset(self) -> RuleSet:
        self.initialize()
        return self._initialized_ruleset

    def __contains__(self, item):
        return item in self.must or item in self.should or item in self.may

    def __hash__(self):
        return (*self.ruleset_names, *self.must, *self.should, *self.may).__hash__()

    @property
    def all_used_rule_names(self) -> set[str]:
        selected_rules = set()
        for type_ in [self.must, self.should, self.may]:
            selected_rules.update(type_)
        return selected_rules

    def initialize(self):
        if self.__is_initialized:
            return
        self._initialized_ruleset = RuleSet()
        for ruleset in self.ruleset_names:
            if "\\" not in ruleset and "/" not in ruleset:
                # Is a native ruleset
                self._initialized_ruleset += RuleSet.from_file(
                    RULESET_DIR / (ruleset + ".yml")
                )
            else:
                # Load it from a file
                path = Path(ruleset)
                if path.is_absolute():
                    self._initialized_ruleset += RuleSet.from_file(ruleset)
                else:
                    self._initialized_ruleset += RuleSet.from_file(ROOT_DIR / ruleset)
        selected_rules = self.all_used_rule_names
        self._initialized_ruleset.selection = selected_rules
        self.__is_initialized = True

    @staticmethod
    def from_file(file_path: str | Path) -> "Cookbook":
        file_path = Path(file_path)
        schema_dict = get_mapping(file_path)
        validate(schema_dict, get_mapping(COOKBOOK_VALIDATION_SCHEMA_PATH))

        return Cookbook(
            file_path.name.rsplit(".", 1)[0],
            schema_dict["rulesets"],
            schema_dict.get(RuleForce.MUST.value, []),
            schema_dict.get(RuleForce.SHOULD.value, []),
            schema_dict.get(RuleForce.MAY.value, []),
        )

    def __call__(self, document: dict | Document) -> CookbookResult:
        self.initialize()
        res = self._initialized_ruleset(document)
        cook_res = CookbookResult(res, self)
        return cook_res
