import json

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonValidator

from sbomgrader.core.definitions import FIELD_NOT_PRESENT


def validate_schema(doc: dict):
    validator = JsonValidator(SchemaVersion.V1_5)
    error = validator.validate_str(json.dumps(doc))
    if error:
        raise AssertionError(error.data)


def package_relationships(doc: dict):
    all_bom_refs_from_deps = set()
    for dep in doc.get("dependencies", []):
        all_bom_refs_from_deps.update(dep.get("dependsOn", []))
        all_bom_refs_from_deps.add(dep["ref"])
    for idx, component in enumerate(doc.get("components", [])):
        assert (
            component.get("bom-ref", FIELD_NOT_PRESENT) in all_bom_refs_from_deps
        ), f"Test failed item components[{idx}]: Component does not have any relationships to other components: {component}"
