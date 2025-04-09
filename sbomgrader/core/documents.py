import json
from functools import cached_property
from pathlib import Path
from typing import Any

from sbomgrader.core.enums import SBOMType
from sbomgrader.core.formats import (
    SBOM_FORMAT_DEFINITION_MAPPING,
    SBOMFormat,
    get_fallbacks,
)
from sbomgrader.core.utils import get_mapping


class Document:
    def __init__(self, document_dict: dict[str, Any]):
        self._doc = document_dict

    @cached_property
    def sbom_format(self) -> SBOMFormat:
        for item in SBOMFormat:
            field_to_check = SBOM_FORMAT_DEFINITION_MAPPING[item]

            if all(
                self._doc.get(key) == value for key, value in field_to_check.items()
            ):
                return item
        raise NotImplementedError("Document is in an unsupported standard.")

    @property
    def sbom_format_fallback(self) -> set[SBOMFormat]:
        return get_fallbacks(self.sbom_format)

    @property
    def sbom_type(self) -> "SBOMType":
        if self.sbom_format is SBOMFormat.SPDX23 or self.sbom_format in get_fallbacks(
            SBOMFormat.SPDX23
        ):
            relationships = self._doc.get("relationships", [])
            main_relationships = [
                relationship
                for relationship in relationships
                if relationship["spdxElementId"] == "SPDXRef-DOCUMENT"
                and relationship["relationshipType"] == "DESCRIBES"
            ]
            if len(main_relationships) > 1:
                raise ValueError(
                    "Cannot determine single SBOMType from multi-sbom. Try separating docs first."
                )
            main_relationship = main_relationships[0]
            main_spdxid = main_relationship["relatedSpdxElement"]
            first_degree_relationships = [
                relationship
                for relationship in relationships
                if (
                    relationship["spdxElementId"] == main_spdxid
                    or relationship["relatedSpdxElement"] == main_spdxid
                )
                and relationship != main_relationship
            ]
            if all(
                relationship["relationshipType"] == "VARIANT_OF"
                for relationship in first_degree_relationships
            ):
                return SBOMType.IMAGE_INDEX
            if all(
                relationship["relationshipType"]
                in {"DESCENDANT_OF", "CONTAINS", "BUILD_TOOL_OF"}
                for relationship in first_degree_relationships
            ):
                return SBOMType.IMAGE
            if all(
                relationship["relationshipType"] in {"GENERATED_FROM", "CONTAINS"}
                for relationship in first_degree_relationships
            ):
                return SBOMType.RPM

            def sort_relationship_key(relationship: dict):
                return "".join(sorted(relationship.values()))

            if sorted(
                first_degree_relationships + main_relationships,
                key=sort_relationship_key,
            ) == sorted(relationships, key=sort_relationship_key):
                return SBOMType.PRODUCT
            return SBOMType.UNKNOWN
        elif (
            self.sbom_format is SBOMFormat.CYCLONEDX16
            or self.sbom_format in get_fallbacks(SBOMFormat.CYCLONEDX16)
        ):
            if self._doc.get("metadata", {}).get("component", {}).get("type") in {
                "operating-system"
            }:
                return SBOMType.PRODUCT
            return SBOMType.UNKNOWN
        else:
            raise NotImplementedError()

    @property
    def doc(self):
        return self._doc

    @property
    def json_dump(self) -> str:
        return json.dumps(self._doc, indent=4)

    @staticmethod
    def from_file(path_to_file: str | Path) -> "Document":
        path_to_file = Path(path_to_file)
        mapping = get_mapping(path_to_file)
        if not mapping:
            raise ValueError(
                f"It seems that file {path_to_file.absolute()} does not contain a valid mapping."
                f"Please make sure a valid json or yaml file is provided."
            )
        return Document(get_mapping(path_to_file))
