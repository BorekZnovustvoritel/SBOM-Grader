import pytest

from sbomgrader.grade.cookbooks import Cookbook
from sbomgrader.core.documents import Document


@pytest.mark.parametrize(
    ["sbom_fixture_name", "cookbook_fixture_name"],
    [
        ("image_build_sbom", "image_build_cookbook"),
        ("image_release_sbom", "image_release_cookbook"),
        ("image_index_build_sbom", "image_index_build_cookbook"),
        ("image_index_release_sbom", "image_index_release_cookbook"),
        ("product_sbom", "product_cookbook"),
        ("rpm_build_sbom", "rpm_build_cookbook"),
        ("rpm_release_sbom", "rpm_release_cookbook"),
    ],
)
def test_success_cookbook_build(sbom_fixture_name, cookbook_fixture_name, request):
    cookbook: Cookbook = request.getfixturevalue(cookbook_fixture_name)
    sbom_doc: Document = request.getfixturevalue(sbom_fixture_name)
    res = cookbook(sbom_doc)
    assert res.result.ran
    assert not res.result.not_implemented
    unsuccessful = res.get_unsuccessful()
    assert not unsuccessful.may
    assert not unsuccessful.should
    assert not unsuccessful.must
    assert not res.result.not_implemented
