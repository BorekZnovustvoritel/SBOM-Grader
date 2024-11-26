from copy import copy
from functools import cached_property
from typing import Any, Iterable

from sbomgrader.core.definitions import SBOM_FORMAT_DEFINITION_MAPPING
from sbomgrader.core.enums import SBOMType, Implementation


class Document:
    def __init__(self, document_dict: dict[str, Any]):
        self._doc = document_dict

    @cached_property
    def implementation(self) -> Implementation:
        for item in Implementation:
            field_to_check = SBOM_FORMAT_DEFINITION_MAPPING[item]

            if all(
                self._doc.get(key) == value for key, value in field_to_check.items()
            ):
                return item
        raise NotImplementedError("Document is in an unsupported standard.")

    @property
    def sbom_type(self) -> "SBOMType":
        if self.implementation is Implementation.SPDX23:
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
        elif self.implementation is Implementation.CYCLONEDX15:
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
