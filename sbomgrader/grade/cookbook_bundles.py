import json
import logging
import sys
from copy import copy
from dataclasses import fields, dataclass, field
from pathlib import Path
from typing import Iterable, Any, Generator

import jsonschema.exceptions
import yaml

from sbomgrader.grade.cookbooks import Cookbook, CookbookResult
from sbomgrader.core.definitions import COOKBOOKS_DIR
from sbomgrader.core.documents import Document
from sbomgrader.core.enums import SBOMType, SBOMTime, OutputType, Grade
from sbomgrader.grade.rules import RuleSet, Result


LOGGER = logging.getLogger(__name__)


@dataclass
class CookbookBundleResult:
    cookbook_bundle: "CookbookBundle"
    cookbook_results: list[CookbookResult] = field(default_factory=list)

    def output(self, o_type: OutputType) -> str:
        if o_type in {OutputType.MARKDOWN, OutputType.VISUAL}:
            ans = "# Cookbook bundle result\n\n"
            ans += f"**Grade: {self.grade.value}**\n\n"
            ans += "## Used cookbooks\n\n"
            for cookbook_result in self.cookbook_results:
                ans += f"- {cookbook_result.cookbook.name}\n"
            ans += "\n---\n\n"
            ans += "\n---\n\n".join(
                cookbook_result.output(o_type)
                for cookbook_result in self.cookbook_results
            )
            return ans
        if o_type is OutputType.JSON:
            return json.dumps(self.to_dict(), indent=4)
        return yaml.dump(self.to_dict())

    @property
    def grade(self) -> Grade:
        if decisive_cookbook := self.cookbook_bundle.decisive_cookbook:
            cookbook_result: CookbookResult = next(
                filter(
                    lambda x: x.cookbook.name == decisive_cookbook,
                    self.cookbook_results,
                ),
                None,  # type: ignore[arg-type]
            )
            if cookbook_result is not None:
                return cookbook_result.grade
        grades = [x.grade for x in self.cookbook_results]
        return sorted(grades, key=lambda x: ord(x.value))[-1]

    def to_dict(self) -> dict[str, Any]:
        """
        Dumps the result into a dictionary.
        :return: The dictionary representation of self.
        """
        result_dict: dict[str, Any] = {
            "cookbook_results": [],
            "grade": self.grade.value,
        }
        for cookbook_result in self.cookbook_results:
            result_dict["cookbook_results"].append(cookbook_result.to_dict())
        return result_dict

    def __iter__(self):
        yield from self.cookbook_results


class CookbookBundle:
    def __init__(
        self, cookbooks: Iterable[Cookbook], decisive_cookbook: str | None = None
    ):
        self.cookbooks = set(cookbooks)
        self.decisive_cookbook: str | None = decisive_cookbook

    @staticmethod
    def from_directory(dir_path: Path) -> "CookbookBundle":
        cookbooks = Cookbook.from_directory(dir_path)
        return CookbookBundle(cookbooks)

    @property
    def all_rules(self) -> set[str]:
        all_rules: set[str] = set()
        for cookbook in self.cookbooks:
            all_rules.update(cookbook.must)
            all_rules.update(cookbook.should)
            all_rules.update(cookbook.may)
        return all_rules

    @property
    def ruleset(self) -> RuleSet:
        ruleset = RuleSet()
        for cookbook in self.cookbooks:
            ruleset += cookbook.ruleset
        return ruleset

    def __call__(self, doc: Document) -> CookbookBundleResult:
        """
        Execute the CookbookBundle on an SBOM object instance.
        :param doc: SBOM Document.
        :return: Result of running the Cookbook.
        """
        result = self.ruleset(doc)
        ans = []
        for cookbook in self.cookbooks:
            kwargs: dict[str, dict[Any, Any] | set[Any]] = {}
            for attr_obj in fields(Result):
                attr = attr_obj.name
                attr_value = getattr(result, attr)
                if isinstance(attr_value, dict):
                    kwargs[attr] = {
                        k: v for k, v in attr_value.items() if k in cookbook
                    }
                else:
                    kwargs[attr] = {v for v in attr_value if v in cookbook}
            new_result = Result(**kwargs)  # type: ignore[arg-type]
            ans.append(CookbookResult(new_result, cookbook))
        return CookbookBundleResult(self, ans)

    @staticmethod
    def for_document_type(
        sbom_type: SBOMType, requested_stage: SBOMTime = SBOMTime.UNSPECIFIED
    ) -> "CookbookBundle":
        cookbook_identifiers = []
        if sbom_type is SBOMType.PRODUCT:
            cookbook_identifiers.append(COOKBOOKS_DIR / (sbom_type.value + ".yml"))
            decisive_cookbook = sbom_type.value

        elif requested_stage is SBOMTime.UNSPECIFIED:
            for sbom_time in SBOMTime.RELEASE, SBOMTime.BUILD:
                cookbook_identifiers.append(
                    COOKBOOKS_DIR / f"{sbom_type.value}_{sbom_time.value}.yml"
                )
            decisive_cookbook = f"{sbom_type.value}_{SBOMTime.RELEASE}"
        else:
            cookbook_identifiers.append(
                COOKBOOKS_DIR / f"{sbom_type.value}_{requested_stage.value}.yml"
            )
            decisive_cookbook = f"{sbom_type.value}_{requested_stage.value}"
        return CookbookBundle(
            [Cookbook.from_file(identifier) for identifier in cookbook_identifiers],
            decisive_cookbook,
        )

    def __add__(self, other):
        if isinstance(other, Cookbook):
            new_bundle = CookbookBundle(copy(self.cookbooks))
            new_bundle.cookbooks.add(other)
            return new_bundle
        if isinstance(other, CookbookBundle):
            new_bundle = CookbookBundle(copy(self.cookbooks))
            new_bundle.cookbooks.update(other.cookbooks)
            return new_bundle
        raise TypeError(f"Cannot add types Cookbook and {type(other)}.")

    def __iter__(self) -> Generator[Cookbook, None, None]:
        yield from self.cookbooks
