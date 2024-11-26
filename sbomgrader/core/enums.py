from enum import Enum


class Implementation(Enum):
    SPDX23 = "spdx23"
    CYCLONEDX15 = "cdx15"


class ResultType(Enum):
    SUCCESS = "success"
    NOT_PRESENT = "not present"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_IMPLEMENTED = "not implemented"

    @staticmethod
    def get_visual(res_type: "ResultType") -> str:
        mapping = {
            ResultType.SUCCESS: "\N{check mark}",
            ResultType.FAILED: "\N{cross mark}",
            ResultType.ERROR: "!",
            ResultType.SKIPPED: "\N{RIGHT-SIDE ARC CLOCKWISE ARROW}",
            ResultType.NOT_PRESENT: "??",
            ResultType.NOT_IMPLEMENTED: "?",
        }
        return mapping[res_type]


class RuleForce(Enum):
    MUST = "MUST"
    SHOULD = "SHOULD"
    MAY = "MAY"


class SBOMTime(Enum):
    RELEASE = "release"
    BUILD = "build"
    UNSPECIFIED = None


class Grade(Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"

    @staticmethod
    def lower(grade: "Grade"):
        if grade is Grade.F:
            return grade.F
        return Grade(chr(ord(grade.value) + 1))

    @staticmethod
    def compare(left: "Grade", right: "Grade") -> int:
        diff = ord(left.value) - ord(right.value)
        if not diff:
            return diff
        return diff // abs(diff)


class SBOMType(Enum):
    IMAGE = "image"
    IMAGE_INDEX = "image_index"
    RPM = "rpm"
    PRODUCT = "product"
    UNKNOWN = "generic"
    UNSPECIFIED = None


class OutputType(Enum):
    YAML = "yaml"
    JSON = "json"
    VISUAL = "visual"


class QueryType(Enum):
    EACH = "&"
    ANY = "|"
    EQ = "="
    NEQ = "!="
    STARTSWITH = "%="
    ENDSWITH = "=%"