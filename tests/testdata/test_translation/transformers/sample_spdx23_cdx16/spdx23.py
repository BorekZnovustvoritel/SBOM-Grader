import re


def spdxid_to_name(spdxid: str) -> str:
    spdxid = re.sub(r"^SPDXRef-", "", spdxid, count=1)
    return spdxid.replace("-", " ")
