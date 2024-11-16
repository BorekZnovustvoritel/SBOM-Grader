import re

from packageurl import PackageURL


def _get_relationships(doc: dict) -> list:
    relationships = doc.get("relationships")
    assert relationships, "Missing field 'relationships'"
    return relationships


def _get_dependencies_spdxids(doc: dict) -> list[str]:
    return [
        r["relatedSpdxElement"]
        for r in filter(
            lambda x: x["relationshipType"] == "CONTAINS", _get_relationships(doc)
        )
    ]


def _get_rpms_spdxids(doc: dict) -> list[str]:
    relationships = _get_relationships(doc)
    main_packages = _get_main_packages(doc)
    main_spdxids = {p["SPDXID"] for p in main_packages}
    return [
        r["relatedSpdxElement"]
        for r in filter(
            lambda x: x["relationshipType"] == "GENERATED_FROM"
            and x["relatedSpdxElement"] in main_spdxids,
            relationships,
        )
    ]


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


def dependencies_packageFileName(doc: dict):
    dependencies_spdxids = list(_get_dependencies_spdxids(doc))
    for spdxid in dependencies_spdxids:
        packages = list(
            filter(lambda x: x["SPDXID"] == spdxid, doc.get("packages", []))
        )
        assert packages, f"No package found for dependency with SPDXID {spdxid}"
        assert len(packages) == 1, f"{spdxid} is not unique."
        assert "packageFileName" in packages[0]


def purl_has_repo_and_tag_qualifiers(purl: str):
    purl = PackageURL.from_string(purl)
    assert "repository_url" in purl.qualifiers
    assert "tag" in purl.qualifiers


def rpms_have_md5sig(doc: dict):
    rpm_spdxids = list(_get_rpms_spdxids(doc))
    for spdxid in rpm_spdxids:
        packages = list(
            filter(lambda x: x["SPDXID"] == spdxid, doc.get("packages", []))
        )
        assert packages, f"No package found for dependency with SPDXID {spdxid}"
        assert len(packages) == 1, f"{spdxid} is not unique."
        package = packages[0]
        assert (
            "annotations" in package
        ), f"Package {spdxid} does not have any annotations."
        correct_annotations = 0
        for annotation in package["annotations"]:
            if annotation.get("comment", "").startswith("sigmd5: "):
                correct_annotations += 1
        assert (
            correct_annotations
        ), f"No annotations with RPM signature sigmd5 found for {spdxid}"


def main_element_cpe22(doc: dict):
    for main_package in _get_main_packages(doc):
        assert any(
            ref.get("referenceType") == "cpe22Type"
            for ref in main_package.get("externalRefs")
        ), f"Package does not have cpe22Type: {main_package['SPDXID']}"


def non_main_repo_arch_qualifiers(doc: dict):
    main_package_SPDXIDs = {p.get("SPDXID") for p in _get_main_packages(doc)}
    for package in doc.get("packages", []):
        if package["SPDXID"] in main_package_SPDXIDs:
            continue
        purl_dicts = filter(
            lambda x: x.get("referenceType") == "purl", package.get("externalRefs")
        )
        purls = [purl_dict.get("referenceLocator") for purl_dict in purl_dicts]

        found_correct = False
        for purl in purls:
            purl_obj = PackageURL.from_string(purl)
            found_correct = (
                "repository_id" in purl_obj.qualifiers and "arch" in purl_obj.qualifiers
            )
            if found_correct:
                break
        assert (
            found_correct
        ), f"Package {package['SPDXID']} does not have a purl with 'arch' and 'repository_id' qualifiers."
