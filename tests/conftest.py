from pathlib import Path

import pytest

from sbomgrader.core.definitions import COOKBOOKS_DIR
from sbomgrader.core.utils import get_mapping
from sbomgrader.grade.cookbooks import Cookbook
from sbomgrader.grade.rules import Document
from sbomgrader.translate.translation_map import TranslationMap


@pytest.fixture()
def testdata_dir() -> Path:
    return Path(__file__).parent / "testdata"


@pytest.fixture()
def grading_dir(testdata_dir: Path) -> Path:
    return testdata_dir / "test_grading"


@pytest.fixture()
def image_index_build_sbom(grading_dir) -> Document:
    return Document(get_mapping(grading_dir / "image_index_build_sbom.spdx.json"))


@pytest.fixture()
def image_index_release_sbom(grading_dir) -> Document:
    return Document(get_mapping(grading_dir / "image_index_release_sbom.spdx.json"))


@pytest.fixture()
def image_build_sbom(grading_dir) -> Document:
    return Document(get_mapping(grading_dir / "image_build_sbom.spdx.json"))


@pytest.fixture()
def image_release_sbom(grading_dir) -> Document:
    return Document(get_mapping(grading_dir / "image_release_sbom.spdx.json"))


@pytest.fixture()
def product_sbom(grading_dir) -> Document:
    return Document(get_mapping(grading_dir / "product_sbom.spdx.json"))


@pytest.fixture()
def rpm_build_sbom(grading_dir) -> Document:
    return Document(get_mapping(grading_dir / "rpm_build_sbom.spdx.json"))


@pytest.fixture()
def rpm_release_sbom(grading_dir) -> Document:
    return Document(get_mapping(grading_dir / "rpm_release_sbom.spdx.json"))


@pytest.fixture()
def cookbooks_dir() -> Path:
    return COOKBOOKS_DIR


@pytest.fixture()
def image_build_cookbook(cookbooks_dir) -> Cookbook:
    return Cookbook.from_file(cookbooks_dir / "image_build.yml")


@pytest.fixture()
def image_index_build_cookbook(cookbooks_dir) -> Cookbook:
    return Cookbook.from_file(cookbooks_dir / "image_index_build.yml")


@pytest.fixture()
def image_index_release_cookbook(cookbooks_dir) -> Cookbook:
    return Cookbook.from_file(cookbooks_dir / "image_index_release.yml")


@pytest.fixture()
def image_release_cookbook(cookbooks_dir) -> Cookbook:
    return Cookbook.from_file(cookbooks_dir / "image_release.yml")


@pytest.fixture()
def product_cookbook(cookbooks_dir) -> Cookbook:
    return Cookbook.from_file(cookbooks_dir / "product.yml")


@pytest.fixture()
def rpm_build_cookbook(cookbooks_dir) -> Cookbook:
    return Cookbook.from_file(cookbooks_dir / "rpm_build.yml")


@pytest.fixture()
def rpm_release_cookbook(cookbooks_dir) -> Cookbook:
    return Cookbook.from_file(cookbooks_dir / "rpm_release.yml")


@pytest.fixture(scope="session")
def built_in_translation_map() -> TranslationMap:
    return TranslationMap.from_file(
        "sbomgrader/translation_maps/red_hat_spdx23_cdx16.yml"
    )
