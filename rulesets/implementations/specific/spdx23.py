import re

from packageurl import PackageURL


def _get_relationships(doc: dict) -> list:
    relationships = doc.get("relationships")
    assert relationships, "Missing field 'relationships'"
    return relationships


def _get_main_packages(doc: dict) -> list:
    relationships = _get_relationships(doc)
    main_element_relationship = list(
        filter(
            lambda x: x.get("spdxElementId") == "SPDXRef-DOCUMENT"
            and x.get("relationshipType") == "DESCRIBES",
            relationships,
        )
    )
    main_packages = []
    for main_element in main_element_relationship:
        expected_spdxid = main_element.get("relatedSpdxElement")
        referenced_package = next(
            filter(
                lambda x: x.get("SPDXID") == expected_spdxid, doc.get("packages", [])
            )
        )
        main_packages.append(referenced_package)
    return main_packages


def main_element_is_package(doc: dict):
    for item in _get_main_packages(doc):
        assert (
            item
        ), f"The item referenced to be described by SPDXRef-DOCUMENT is not a package. (SPDXID: {item["SPDXID"]})"


def image_packages_variants(doc: dict):
    main_package_SPDXIDs = {p.get("SPDXID") for p in _get_main_packages(doc)}
    for package in doc.get("packages", []):
        if package["SPDXID"] in main_package_SPDXIDs:
            continue
        assert next(
            filter(
                lambda x: x.get("relationshipType") == "VARIANT_OF"
                and x.get("spdxElementId") == package["SPDXID"]
                and x.get("relatedSpdxElement") in main_package_SPDXIDs,
                doc.get("relationships", []),
            )
        ), f"Package {package["SPDXID"]} is not variant of main element."


def purl_arch(doc: dict):
    main_package_SPDXIDs = {p.get("SPDXID") for p in _get_main_packages(doc)}
    for package in doc.get("packages", []):
        if package["SPDXID"] in main_package_SPDXIDs:
            continue

        purl_dicts = filter(
            lambda x: x.get("referenceType") == "purl", package.get("externalRefs")
        )
        purls = [purl_dict.get("referenceLocator") for purl_dict in purl_dicts]
        assert any(
            PackageURL.from_string(purl).qualifiers.get("arch") for purl in purls
        ), "All child images in image index should have at least one arch qualifier in purls."


def spdxid_check(doc: dict):
    main_package_SPDXIDs = {p.get("SPDXID") for p in _get_main_packages(doc)}
    for package in doc.get("packages", []):
        if package["SPDXID"] in main_package_SPDXIDs:
            continue
        assert re.match(r"SPDXRef-[a-z]+-[\w]+-[a-z0-9]+", package["SPDXID"])


def main_element_arch_purl(doc: dict):
    for main_element in _get_main_packages(doc):
        purl_dicts = filter(
            lambda x: x.get("referenceType") == "purl", main_element.get("externalRefs")
        )
        purls = [purl_dict.get("referenceLocator") for purl_dict in purl_dicts]
        assert any(
            PackageURL.from_string(purl).qualifiers.get("arch") for purl in purls
        ), f"Image {main_element['SPDXID']} does not have any arch qualifier."


def non_main_packageFileName(doc: dict):
    main_package_SPDXIDs = {p.get("SPDXID") for p in _get_main_packages(doc)}
    for package in doc.get("packages", []):
        if package["SPDXID"] in main_package_SPDXIDs:
            continue
        assert "packageFileName" in package, f"Check failed for package {package["SPDXID"]}"

