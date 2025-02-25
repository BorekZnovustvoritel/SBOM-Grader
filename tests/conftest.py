from pathlib import Path

import pytest

from sbomgrader.core.definitions import COOKBOOKS_DIR
from sbomgrader.core.utils import get_mapping
from sbomgrader.grade.cookbooks import Cookbook
from sbomgrader.grade.rules import Document


@pytest.fixture()
def testdata_dir() -> Path:
    return Path(__file__).parent / "testdata"


@pytest.fixture()
def image_index_build_sbom(testdata_dir) -> Document:
    return Document(get_mapping(testdata_dir / "image_index_build_sbom.json"))


@pytest.fixture()
def image_index_release_sbom(testdata_dir) -> Document:
    return Document(get_mapping(testdata_dir / "image_index_release_sbom.json"))


@pytest.fixture()
def image_build_sbom(testdata_dir) -> Document:
    return Document(get_mapping(testdata_dir / "image_build_sbom.json"))


@pytest.fixture()
def image_release_sbom(testdata_dir) -> Document:
    return Document(get_mapping(testdata_dir / "image_release_sbom.json"))


@pytest.fixture()
def product_sbom(testdata_dir) -> Document:
    return Document(get_mapping(testdata_dir / "product_sbom.json"))


@pytest.fixture()
def rpm_build_sbom(testdata_dir) -> Document:
    return Document(get_mapping(testdata_dir / "rpm_build_sbom.json"))


@pytest.fixture()
def rpm_release_sbom(testdata_dir) -> Document:
    return Document(get_mapping(testdata_dir / "rpm_release_sbom.json"))


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
