import pytest

from sbomgrader.core.documents import Document
from sbomgrader.core.formats import SBOMFormat
from sbomgrader.translate.translation_map import TranslationMap
from sbomgrader.core.utils import get_mapping


class ComparableDoc:
    def __init__(self, doc: Document):
        self.document = doc

    def __eq__(self, other):
        if not isinstance(other, ComparableDoc) or not isinstance(other, Document):
            raise TypeError(
                f"Cannot compare object of type {self.__class__.__name__} to an object  of type {other.__class__.__name__}."
            )


@pytest.mark.parametrize(["spdx"], [("spdx23",), ("spdx22",)])
@pytest.mark.parametrize(["cyclonedx"], [("cdx16",), ("cdx15",)])
def test_translation(cyclonedx, spdx):
    tm = TranslationMap.from_file(
        "tests/testdata/test_translation/sample_spdx23_cdx16.yml"
    )
    first_doc = Document(
        get_mapping(f"tests/testdata/test_translation/sample_{spdx}.json")
    )
    second_doc = Document(
        get_mapping(f"tests/testdata/test_translation/sample_{cyclonedx}.json")
    )
    assert tm.convert(first_doc, SBOMFormat(cyclonedx)).doc == second_doc.doc
    assert tm.convert(second_doc, SBOMFormat(spdx)).doc == first_doc.doc
