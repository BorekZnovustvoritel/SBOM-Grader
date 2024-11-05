from typing import Any
from datetime import datetime

from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document


def validate_schema(doc: dict[str, Any]):
    document = JsonLikeDictParser().parse(doc)
    validations = validate_full_spdx_document(document, "SPDX-2.3")
    if validations:
        raise AssertionError(validations)


def check_datetime(doc: str):
    try:
        datetime.fromisoformat(doc)
    except:
        raise AssertionError("Cannot parse ISO datetime.")


def package_relationships(doc: dict[str, Any]):
    package_spdxids = {package["SPDXID"] for package in doc.get("packages", [])}
    for relationship in doc.get("relationships", []):
        references = relationship.get("spdxElementId"), relationship.get(
            "relatedSpdxElement"
        )
        for r in references:
            if r in package_spdxids:
                package_spdxids.remove(r)
        if not package_spdxids:
            break
    assert (
        not package_spdxids
    ), f"Not all packages are referenced in relationships: {package_spdxids}"
