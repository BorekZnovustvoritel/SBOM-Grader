import datetime
from typing import Any

from sbomgrader.core.definitions import FIELD_NOT_PRESENT, TIME_ISO_FORMAT_STRING


def should_remove(item: Any) -> bool:
    """Is the field considered invalid?"""
    # All kinds of empty values are considered invalid
    # But `False` is valid
    return (
        (not item and item is not False)
        or item is FIELD_NOT_PRESENT
        or item == "Field not present."
    )


def __is_prunable(item: Any) -> bool:
    return (
        isinstance(item, dict)
        or isinstance(item, list)
        or isinstance(item, datetime.datetime)
    )


def prune(struc: Any) -> Any:
    """This function cuts off invalid values from returned structures."""
    if isinstance(struc, datetime.datetime):
        # YAML automatically transforms ISO time to python datetime.
        # Datetime is not JSON-serializable
        return struc.strftime(TIME_ISO_FORMAT_STRING)
    if not __is_prunable(struc):
        return struc
    if isinstance(struc, list):
        to_prune = []
        replace_dict = {}
        for idx, item in enumerate(struc):
            if should_remove(item):
                to_prune.append(idx)

            if __is_prunable(item):
                pruned = prune(item)
                if should_remove(pruned):
                    to_prune.append(idx)
                else:
                    replace_dict[idx] = pruned

        for idx, item in replace_dict.items():
            struc[idx] = item
        for idx in reversed(to_prune):
            struc.pop(idx)

    elif isinstance(struc, dict):
        to_prune = set()
        update_dict = {}
        for key, val in struc.items():
            if should_remove(val):
                to_prune.add(key)
            if __is_prunable(val):
                pruned = prune(val)
                if should_remove(pruned):
                    to_prune.add(key)
                else:
                    update_dict[key] = pruned
        struc.update(update_dict)
        for item in to_prune:
            struc.pop(item)
    return struc
