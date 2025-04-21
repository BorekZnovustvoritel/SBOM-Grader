import timeit
from typing import Any

from sbomgrader.translate.choose_map import get_default_maps
from sbomgrader.core.formats import SBOMFormat
from sbomgrader.core.documents import Document


def test_performance_spdx(
    huge_spdx: dict[str, Any], repetitions: int, maximal_time_per_translation: int
):
    default_map = next(
        filter(
            lambda x: x.is_exact_map(SBOMFormat.SPDX23, SBOMFormat.CYCLONEDX16),
            get_default_maps(),
        )
    )
    doc = Document(huge_spdx)

    def func_to_run():
        return default_map.convert(doc)

    res = timeit.timeit(func_to_run, number=repetitions)
    assert res / repetitions < maximal_time_per_translation


def test_performance_cdx(
    huge_cdx: dict[str, Any], repetitions: int, maximal_time_per_translation: int
):
    default_map = next(
        filter(
            lambda x: x.is_exact_map(SBOMFormat.SPDX23, SBOMFormat.CYCLONEDX16),
            get_default_maps(),
        )
    )
    doc = Document(huge_cdx)

    def func_to_run():
        return default_map.convert(doc)

    res = timeit.timeit(func_to_run, number=repetitions)
    assert res / repetitions < maximal_time_per_translation
