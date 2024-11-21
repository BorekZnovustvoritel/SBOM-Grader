from copy import copy
from functools import cached_property
from typing import Any, Iterable

from core.definitions import SBOM_FORMAT_DEFINITION_MAPPING
from core.enums import SBOMType, Implementation


class Document:
    def __init__(self, document_dict: dict[str, Any]):
        self._doc = document_dict

    @cached_property
    def implementation(self) -> Implementation:
        for item in Implementation:
            field_to_check = SBOM_FORMAT_DEFINITION_MAPPING[item]

            if self._doc.get(next(iter(field_to_check.keys()))) == next(
                iter(field_to_check.values())
            ):
                return item
        raise NotImplementedError("Document is in an unsupported standard.")

    def separate_trees(self) -> Iterable["Document"]:
        """If SBOMs contain separable data, separate them so every SBOM contains only a single main element."""
        if self.implementation is Implementation.SPDX23:

            main_spdxids = [
                relationship["relatedSpdxElement"]
                for relationship in self._doc.get("relationships", [])
                if relationship["spdxElementId"] == "SPDXRef-DOCUMENT"
                and relationship["relationshipType"] == "DESCRIBES"
            ]
            if len(main_spdxids) < 1:
                raise ValueError(
                    "Invalid SPDX 2.3 document, no element is DESCRIBED_BY SPDXRef-DOCUMENT"
                )
            if len(main_spdxids) == 1:
                return [self]
            new_docs = []
            for main_spdxid in main_spdxids:
                # Gather all SPDXIDs related to this root
                visited = set()
                visited.add(main_spdxid)
                visited_length = 1
                starting_size = 0
                while starting_size != visited_length:
                    starting_size = len(visited)
                    for relationship in self._doc.get("relationships", []):
                        if relationship["spdxElementId"] in visited:
                            visited.add(relationship["relatedSpdxElement"])
                        elif relationship["relatedSpdxElement"] in visited:
                            visited.add(relationship["spdxElementId"])
                    visited_length = len(visited)

                # Create sub-docs
                doc = copy(self._doc)
                for field_name in "packages", "files", "snippets":
                    if field_name not in doc:
                        continue
                    doc[field_name] = []
                    for element in self._doc.get(field_name, []):
                        if element["SPDXID"] in visited:
                            doc[field_name].append(element)
                new_docs.append(Document(doc))
            return new_docs

        else:
            raise NotImplementedError()

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
        #   elif self.implementation.is Implementation. ...
        else:
            raise NotImplementedError()

    @property
    def doc(self):
        return self._doc
