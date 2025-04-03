import re
import uuid
from typing import Any

import yaml
from packageurl import PackageURL
from spdx_tools.spdx.model.spdx_no_assertion import SPDX_NO_ASSERTION_STRING

from sbomgrader.core.definitions import FIELD_NOT_PRESENT
from sbomgrader.translation_maps.transformers.red_hat_spdx23_cdx16.utils import (
    SPDX_CDX_HASHES,
)

_CACHE = {}


def get_serial_number(_: Any) -> str:
    return str(uuid.uuid4())


def spdxid_to_bom_ref(spdxid: str, purls: list[str]) -> str:
    if spdxid in _CACHE:
        return _CACHE[spdxid]
    purl = next(iter(purls), FIELD_NOT_PRESENT)
    if purl is FIELD_NOT_PRESENT:
        purl = spdxid.replace("SPDXRef-", "", 1)
    _CACHE[spdxid] = purl
    return _CACHE[spdxid]


def hash_alg_from_spdx_to_cdx(algorithm: str) -> str:
    dic = {first: second for first, second in SPDX_CDX_HASHES}
    return dic.get(algorithm, algorithm)


def purl_to_component_type(purl: str) -> str | None | FIELD_NOT_PRESENT.__class__:
    if not isinstance(purl, str):
        return FIELD_NOT_PRESENT
    if purl.startswith("pkg:oci/"):
        return "container"
    if (
        purl.startswith("pkg:rpm/")
        or purl.startswith("pkg:maven/")
        or purl.startswith("pkg:generic/")
    ):
        return "library"
    return FIELD_NOT_PRESENT


def namespaces_to_url(namespaces: list[str]) -> list[str]:
    ans = []
    for namespace in namespaces:
        match = re.match(r"https?://[\w.-]+", namespace)
        if match:
            ans.append(match.group())

    return ans


def sanitise_supplier(supplier: str) -> str:
    if not isinstance(supplier, str):
        return FIELD_NOT_PRESENT
    return re.sub(r"^\w+:\s", "", supplier, count=1)


def tool_to_dict(tool_string: str) -> dict[str, str]:
    if not isinstance(tool_string, str):
        return FIELD_NOT_PRESENT
    tool_string = tool_string.strip()
    tool_string = re.sub(r"Tool: ", "", tool_string, flags=re.IGNORECASE, count=1)

    splits = tool_string.rsplit(" ", 1)
    if len(splits) == 2 and re.search(r"\d", splits[1]):
        # Let's assume that the version is the last bit and contains numbers
        return {"name": splits[0], "version": splits[1]}
    else:
        return {"name": tool_string}


def annotations_to_properties(annotations: list[str]) -> list[dict[str, str]]:
    ans = []
    for annotation in annotations:
        try:
            dic = yaml.safe_load(annotation)
            tmp = {}
            for key, value in dic.items():
                tmp.update({"name": key, "value": value})
            ans.append(tmp)
        except Exception:
            ans.append({"name": "COMMENT", "value": annotation})
    return ans


def purl_with_download_location(purl: str, download_location_var: list[str]) -> str:
    if not purl or not isinstance(purl, str):
        return FIELD_NOT_PRESENT
    purl_obj = PackageURL.from_string(purl)
    if "download_url" in purl_obj.qualifiers:
        return purl
    download_location = next(iter(download_location_var), SPDX_NO_ASSERTION_STRING)
    if download_location == SPDX_NO_ASSERTION_STRING:
        return purl
    purl_obj.qualifiers["download_url"] = download_location
    return purl_obj.to_string()
