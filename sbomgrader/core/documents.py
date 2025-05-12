import json
from enum import Enum
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
    def sbom_format(self) -> Enum:
        for item in SBOMFormat:
            field_to_check = SBOM_FORMAT_DEFINITION_MAPPING[item]

            if all(
                self._doc.get(key) == value for key, value in field_to_check.items()
            ):
                return item
        raise NotImplementedError("Document standard and/or version is not supported.")

    @property
    def sbom_format_fallback(self) -> set[Enum]:
        return get_fallbacks(self.sbom_format)

    @staticmethod
    def __determine_type_from_purls(purls: list[str]) -> SBOMType:
        if any(purl.startswith("pkg:rpm/") for purl in purls):
            return SBOMType.RPM
        neutral_arches = {"noarch", "src"}
        for purl in purls:
            if purl.startswith("pkg:oci/"):
                if "arch=" in purl:
                    if any(f"arch={arch}" in purl for arch in neutral_arches):
                        return SBOMType.IMAGE_INDEX
                    else:
                        return SBOMType.IMAGE
                return SBOMType.IMAGE_INDEX

        return SBOMType.UNKNOWN

    @staticmethod
    def __determine_type_from_cpes_and_purls(
        cpes: list[str], purls: list[str]
    ) -> SBOMType:
        if cpes:
            return SBOMType.PRODUCT
        return Document.__determine_type_from_purls(purls)

    @property
    def sbom_type(self) -> "SBOMType":
        ### SPDX 2.3
        if (
            self.sbom_format is SBOMFormat.SPDX23  # type: ignore[attr-defined]
            or self.sbom_format
            in get_fallbacks(SBOMFormat.SPDX23)  # type: ignore[attr-defined]
        ):  # type: ignore[attr-defined]
            # First get main component
            relationships = self._doc.get("relationships", [])
            main_relationships = [
                relationship
                for relationship in relationships
                if relationship["spdxElementId"] == "SPDXRef-DOCUMENT"
                and relationship["relationshipType"] == "DESCRIBES"
            ]
            if len(main_relationships) > 1:
                # Many main components. Don't know what to do here
                return SBOMType.UNKNOWN
            main_relationship = main_relationships[0]
            main_spdxid = main_relationship["relatedSpdxElement"]
            packages = self._doc.get("packages", [])
            main_package: dict[str, Any] = next(
                filter(lambda x: x.get("SPDXID") == main_spdxid, packages), {}
            )
            main_pkg_references = main_package.get("externalRefs", [])
            cpes = list(
                filter(
                    lambda x: x.get("referenceCategory") == "SECURITY",
                    main_pkg_references,
                )
            )
            purls = [
                ref.get("referenceLocator")
                for ref in main_pkg_references
                if ref.get("referenceType") == "purl"
            ]
            return self.__determine_type_from_cpes_and_purls(cpes, purls)
        ### CDX 1.6
        elif (
            self.sbom_format is SBOMFormat.CYCLONEDX16  # type: ignore[attr-defined]
            or self.sbom_format in get_fallbacks(SBOMFormat.CYCLONEDX16)  # type: ignore[attr-defined]
        ):
            main_component = self._doc.get("metadata", {}).get("component", {})
            cpes = main_component.get("cpe", [])
            cpes.extend(
                [
                    ref.get("concludedValue")
                    for ref in main_component.get("evidence", {}).get("identity", [])
                    if ref.get("field") == "cpe"
                ]
            )
            purls = main_component.get("purl", [])
            purls.extend(
                [
                    ref.get("concludedValue")
                    for ref in main_component.get("evidence", {}).get("identity", [])
                    if ref.get("field") == "purl"
                ]
            )
            return self.__determine_type_from_cpes_and_purls(cpes, purls)
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
        return Document(get_mapping(path_to_file))  # type: ignore[arg-type]
