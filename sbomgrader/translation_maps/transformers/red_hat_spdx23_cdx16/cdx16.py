import base64
import re
import urllib.parse
import uuid

from packageurl import PackageURL
from spdx_tools.spdx.model.spdx_no_assertion import SPDX_NO_ASSERTION_STRING

from sbomgrader.core.definitions import FIELD_NOT_PRESENT
from sbomgrader.translation_maps.transformers.red_hat_spdx23_cdx16.utils import (
    SPDX_CDX_HASHES,
)

_CACHE = {}


def bom_ref_to_spdxid(bom_ref: str, component_name_var: list[str]) -> str:

    if bom_ref in _CACHE:
        return _CACHE[bom_ref]
    if not bom_ref or bom_ref is FIELD_NOT_PRESENT:
        name = next(iter(component_name_var), None)
        if name and name is not FIELD_NOT_PRESENT:
            bom_ref = name
        else:
            bom_ref = base64.b64encode(uuid.uuid4().bytes)

    _CACHE[bom_ref] = f"SPDXRef-{re.sub(r"[^A-Za-z\d.-]", "-", bom_ref)}"
    return _CACHE[bom_ref]


def hash_alg_from_cdx_to_spdx(algorithm: str) -> str:
    dic = {second: first for first, second in SPDX_CDX_HASHES}
    return dic.get(algorithm, algorithm)


def url_to_namespace(
    url: str,
    component_name_var: list[str],
    serial_no_var: list[str],
) -> str:
    if not url or not isinstance(url, str):
        url = "https://github.com/BorekZnovustvoritel/SBOM-Grader"
    end_string = urllib.parse.quote_plus(
        next(iter(component_name_var), FIELD_NOT_PRESENT)
        + "/"
        + next(iter(serial_no_var), FIELD_NOT_PRESENT)
    )

    return url + "/" + end_string


def cpe_to_cpe_type(cpe: str) -> str:
    if cpe.startswith("cpe:2.3:"):
        return "cpe23Type"
    return "cpe22Type"


def purl_to_download_location(purl: str) -> str:
    if not purl or not isinstance(purl, str):
        return SPDX_NO_ASSERTION_STRING
    purl_obj = PackageURL.from_string(purl)
    loc = purl_obj.qualifiers.get("download_url") or SPDX_NO_ASSERTION_STRING
    return loc
