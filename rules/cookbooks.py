from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from jsonschema.validators import validate

from definitions import (
    get_mapping,
    COOKBOOK_VALIDATION_SCHEMA_PATH,
    RULESET_DIR,
    ROOT_DIR,
)
from rules.rule import RuleSet, Document, Result


@dataclass
class CookbookResult:
    result: Result
    cookbook: "Cookbook"

    @property
    def must(self):
        return [self.result.get(name) for name in self.cookbook.must]

    @property
    def should(self):
        return [self.result.get(name) for name in self.cookbook.should]

    @property
    def may(self):
        return [self.result.get(name) for name in self.cookbook.may]

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
            Cookbook(self.cookbook.rulesets, new_must, new_should, new_may),
        )


class Cookbook:
    def __init__(
        self,
        rulesets: Iterable[str],
        must: Iterable[str],
        should: Iterable[str],
        may: Iterable[str],
    ):
        self.rulesets = rulesets
        self._initialized_ruleset: RuleSet | None = None
        self.__is_initialized: bool = False
        self.must = set(must)
        self.should = set(should)
        self.may = set(may)

    def initialize(self):
        self._initialized_ruleset = RuleSet()
        for ruleset in self.rulesets:
            if "\\" not in ruleset and "/" not in ruleset:
                # Is a native ruleset
                self._initialized_ruleset += RuleSet.from_schema(
                    RULESET_DIR / (ruleset + ".yml")
                )
            else:
                # Load it from a file
                path = Path(ruleset)
                if path.is_absolute():
                    self._initialized_ruleset += RuleSet.from_schema(ruleset)
                else:
                    self._initialized_ruleset += RuleSet.from_schema(ROOT_DIR / ruleset)
        selected_rules = set()
        for type_ in [self.must, self.should, self.may]:
            selected_rules.update(type_)
        self._initialized_ruleset.selection = selected_rules
        self.__is_initialized = True

    @staticmethod
    def from_schema(schema: str | Path) -> "Cookbook":
        schema_dict = get_mapping(schema)
        validate(schema_dict, get_mapping(COOKBOOK_VALIDATION_SCHEMA_PATH))

        return Cookbook(
            schema_dict["rulesets"],
            schema_dict.get("MUST", []),
            schema_dict.get("SHOULD", []),
            schema_dict.get("MAY", []),
        )

    def __call__(self, document: dict | Document) -> CookbookResult:
        if not self.__is_initialized:
            self.initialize()
        res = self._initialized_ruleset(document)
        cook_res = CookbookResult(res, self)
        return cook_res
