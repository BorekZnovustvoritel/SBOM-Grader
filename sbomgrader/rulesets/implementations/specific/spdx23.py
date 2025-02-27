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
            ),
            None,
        ), f"Package {package["SPDXID"]} is not variant of main element."


def purl_has_repo_and_tag_qualifiers(purl: str):
    purl = PackageURL.from_string(purl)
    assert "repository_url" in purl.qualifiers
    assert "tag" in purl.qualifiers
