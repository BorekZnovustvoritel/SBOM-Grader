from typing import Any

import yaml


def generate_huge_spdx(num_of_packages: int) -> dict[str, Any]:
    skeleton = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Foobar"],
            "licenseListVersion": "3.25",
        },
        "name": "foo",
        "documentNamespace": "https://example.com/foo",
    }
    main_component = {
        "SPDXID": "SPDXRef-main",
        "name": "main_foo",
        "versionInfo": "0.0.1",
        "supplier": "Crafted at home",
        "downloadLocation": "NOASSERTION",
        "licenseDeclared": "MIT",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:oci/main_foo@ac16399720ebe2b5690a4fe98b925ff7027e825bbf527b6dfbd949965e391d18?arch=the_best&repository_url=example.com/bar/main_foo&tag=0.0.1",
            }
        ],
        "checksums": [
            {
                "algorithm": "SHA256",
                "checksumValue": "ac16399720ebe2b5690a4fe98b925ff7027e825bbf527b6dfbd949965e391d18",
            }
        ],
    }
    main_package_relationship = {
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-main",
    }
    dep = {
        "SPDXID": "SPDXRef-dep-{num}",
        "name": "dep_{num}",
        "versionInfo": "0.0.1",
        "supplier": "Crafted at home",
        "downloadLocation": "NOASSERTION",
        "licenseDeclared": "MIT",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:rpm/dep_{num}@a8a3ea3ddbea6b521e4c0e8f2cca8405e75c042b2a7ed848baaa03e867355bc2?arch=the_best&repository_url=example.com/bar/dep_{num}&tag=0.0.1",
            }
        ],
        "checksums": [
            {
                "algorithm": "SHA256",
                "checksumValue": "a8a3ea3ddbea6b521e4c0e8f2cca8405e75c042b2a7ed848baaa03e867355bc2",
            }
        ],
    }
    dep_relationship = {
        "spdxElementId": "SPDXRef-main",
        "relationshipType": "CONTAINS",
        "relatedSpdxElement": "SPDXRef-dep-{num}",
    }
    skeleton["packages"] = [main_component]
    skeleton["relationships"] = [main_package_relationship]

    for index in range(num_of_packages):
        skeleton["packages"].append(
            yaml.safe_load(yaml.safe_dump(dep).format(num=index)))
        skeleton["relationships"].append(
            yaml.safe_load(yaml.safe_dump(dep).format(num=index))
        )
    return skeleton
