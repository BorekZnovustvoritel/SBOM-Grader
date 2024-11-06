from pathlib import Path

from jsonschema.validators import validate

from definitions import (
    get_mapping,
    COOKBOOK_VALIDATION_SCHEMA_PATH,
    RULESET_DIR,
    ROOT_DIR,
)
from rules.rule import RuleSet, Document


class Cookbook:
    def __init__(
        self, rulesets: list[str], must: list[str], should: list[str], may: list[str]
    ):
        self.rulesets = rulesets
        self._initialized_ruleset: RuleSet | None = None
        self.__is_initialized: bool = False
        self.must = must
        self.should = should
        self.may = may

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

    def __call__(self, document: dict | Document):
        if not self.__is_initialized:
            self.initialize()
        res = self._initialized_ruleset(document)
        result_dict = {}
        for type_, rules in [
            ("MUST", self.must),
            ("SHOULD", self.should),
            ("MAY", self.may),
        ]:
            result_dict[type_] = [res.get(rule) for rule in rules]
        return result_dict
