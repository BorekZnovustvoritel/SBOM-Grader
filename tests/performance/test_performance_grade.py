import timeit
from typing import Any

from sbomgrader.grade.choose_cookbooks import select_cookbook_bundle
from sbomgrader.core.documents import Document


def test_grade_performance_spdx(
    huge_spdx: dict[str, Any], repetitions: int, maximal_time_per_grade: int
):
    cookbook = select_cookbook_bundle(["generic_build"])
    doc = Document(huge_spdx)

    def func_to_run():
        return cookbook(doc)

    res = timeit.timeit(func_to_run, number=repetitions)
    assert res / repetitions < maximal_time_per_grade


def test_grade_performance_cdx(
    huge_cdx: dict[str, Any], repetitions: int, maximal_time_per_grade: int
):
    cookbook = select_cookbook_bundle(["generic_build"])
    doc = Document(huge_cdx)

    def func_to_run():
        return cookbook(doc)

    res = timeit.timeit(func_to_run, number=repetitions)
    assert res / repetitions < maximal_time_per_grade
