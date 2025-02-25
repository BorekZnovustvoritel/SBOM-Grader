import pytest

from sbomgrader.core.documents import Document
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


def test_translation():
    tm = TranslationMap.from_file(
        "tests/testdata/test_translation/sample_spdx23_cdx16.yml"
    )
    first_doc = Document(
        get_mapping("tests/testdata/test_translation/sample_spdx23.json")
    )
    second_doc = Document(
        get_mapping("tests/testdata/test_translation/sample_cdx16.json")
    )
    # raise ValueError(tm.convert(second_doc).doc)
    assert tm.convert(first_doc).doc == second_doc.doc
    assert tm.convert(second_doc).doc == first_doc.doc
