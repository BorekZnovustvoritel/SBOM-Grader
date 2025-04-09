from typing import Any


def set_relationships_last(_, new_doc: dict[str, Any]):
    rels = new_doc.pop("relationships", None)
    new_doc["relationships"] = rels
