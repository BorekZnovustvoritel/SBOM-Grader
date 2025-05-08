from typing import Any

import pytest
import yaml


@pytest.fixture()
def maximal_time_per_translation() -> float:
    return 1.5


@pytest.fixture()
def maximal_time_per_grade() -> float:
    return 0.5


@pytest.fixture()
def repetitions() -> int:
    return 2


@pytest.fixture()
def component_number_to_generate() -> int:
    return 100


@pytest.fixture()
def huge_spdx(component_number_to_generate: int) -> dict[str, Any]:
    skeleton = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: Foobar"],
            "licenseListVersion": "3.25",
        },
        "name": "foo",
        "documentNamespace": "https://example.com/foo",
    }
    main_component = {
        "SPDXID": "SPDXRef-main",
        "name": "main_foo",
        "versionInfo": "0.0.1",
        "supplier": "Organization: Crafted at home",
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
        "supplier": "Organization: Crafted at home",
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

    for index in range(component_number_to_generate):
        skeleton["packages"].append(
            yaml.safe_load(yaml.safe_dump(dep).format(num=index))
        )
        skeleton["relationships"].append(
            yaml.safe_load(yaml.safe_dump(dep_relationship).format(num=index))
        )
    return skeleton


@pytest.fixture()
def huge_cdx(component_number_to_generate: int) -> dict[str, Any]:
    skeleton = {
        "bomFormat": "CycloneDX",
        "serialNumber": "urn:uuid:11111111-1111-1111-1111-1111111111",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "name": "main_foo",
                "purl": "pkg:oci/main_foo@ac16399720ebe2b5690a4fe98b925ff7027e825bbf527b6dfbd949965e391d18?arch=the_best&repository_url=example.com/bar/main_foo&tag=0.0.1",
                "supplier": {
                    "name": "Crafted at home",
                },
                "type": "container",
            },
            "timestamp": "1970-01-01T00:00:00Z",
        },
    }
    main_component = {
        "bom-ref": "main",
        "name": "main_foo",
        "purl": "pkg:oci/main_foo@ac16399720ebe2b5690a4fe98b925ff7027e825bbf527b6dfbd949965e391d18?arch=the_best&repository_url=example.com/bar/main_foo&tag=0.0.1",
        "supplier": {
            "name": "Crafted at home",
        },
        "type": "container",
    }
    dep = {
        "bom-ref": "dep-{num}",
        "name": "quarkus/mandrel-for-jdk-21-rhel8",
        "purl": "pkg:oci/mandrel-for-jdk-21-rhel8@sha256%3A65c139d16564a14b6832d1a393d18146e2fd921b8d263bf214df5720c1c79b19?arch=amd64&tag=23.1-16",
        "type": "container",
        "version": "sha256:65c139d16564a14b6832d1a393d18146e2fd921b8d263bf214df5720c1c79b19",
        "supplier": {"name": "Red Hat", "url": ["https://www.redhat.com"]},
    }
    skeleton["components"] = [main_component]
    for index in range(component_number_to_generate):
        skeleton["components"].append(
            yaml.safe_load(yaml.safe_dump(dep).format(num=index))
        )
    skeleton["dependencies"] = [
        {
            "ref": "main",
            "dependsOn": [f"dep-{num}" for num in range(component_number_to_generate)],
        }
    ]
    return skeleton
