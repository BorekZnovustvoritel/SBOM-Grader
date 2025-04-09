from typing import Any

from sbomgrader.core.field_resolve import FieldResolver


def clone_main_element(doc: dict[str, Any]):
    main_component = doc.get("metadata", {}).get("component", {})
    if not main_component:
        raise ValueError(
            "Please provide an SBOM with a valid metadata.component field."
        )
    if main_component.get("bom-ref"):
        return
    applicable_identifiers = [
        x for x in ("purl", "cpe", "identity", "name") if x in main_component
    ]
    assert (
        applicable_identifiers
    ), "Cannot convert SBOM that does not have any identifiers of the metadata.component field."
    for identifier in applicable_identifiers:
        id_value = main_component.get(identifier)
        for comp in doc.get("components", []):
            if comp.get(identifier) == id_value:
                # This is the main component
                main_component.update(comp)


def ensure_tools_format(doc: dict[str, Any]):
    tools = doc.get("metadata", {}).get("tools")
    if isinstance(tools, list):
        doc["metadata"]["tools"] = {
            "components": [{"name": t, "type": "application"} for t in tools]
        }


def __insert(doc: dict[str, Any], value: Any, path: list[str]) -> None:
    for step in path[:-1]:
        if step not in doc:
            doc[step] = {}
        doc = doc[step]
    doc[path[-1]] = value


def ensure_supplier_format(doc: dict[str, Any]):
    """Makes sure all suppliers are in expected format."""
    if (
        supplier := doc.get("metadata", {}).get("component", {}).get("supplier")
    ) and not doc.get("metadata", {}).get("supplier", {}).get("name"):
        __insert(doc, supplier, ["metadata", "supplier"])
    elif supplier := doc.get("metadata", {}).get("supplier") and not doc.get(
        "metadata", {}
    ).get("component", {}).get("supplier", {}).get("name"):
        __insert(doc, supplier, ["metadata", "component", "supplier"])

    paths = ["metadata", "components[|]"]
    resolver = FieldResolver({})
    for path in paths:
        for element in resolver.get_objects(doc, path):
            if "supplier" not in element:
                continue
            supplier = element["supplier"]
            if isinstance(supplier, str):
                element["supplier"] = {"name": supplier}
