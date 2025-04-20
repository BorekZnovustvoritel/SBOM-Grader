from time import perf_counter

from tests.performance.generate_test_data import generate_huge_spdx
from sbomgrader.translate.choose_map import get_default_maps
from sbomgrader.core.formats import SBOMFormat
from sbomgrader.core.documents import Document


def test_performance():
    default_map = next(
        filter(
            lambda x: x.is_exact_map(SBOMFormat.SPDX23, SBOMFormat.CYCLONEDX16),
            get_default_maps(),
        )
    )
    doc = Document(generate_huge_spdx(500))
    ref = perf_counter()
    print(default_map.convert(doc))
    assert perf_counter() - ref < 10
