from typing import Union

import pytest

from sbomgrader.core.field_resolve import PathParser, QueryParser


@pytest.mark.parametrize(
    ["path", "relative_path", "output"],
    [
        ("foo", "", ["foo"]),
        ("foo.bar", "", ["foo", "bar"]),
        ("foo[1]bar", "", ["foo", QueryParser("1"), "bar"]),
        ("@.foo[1]bar", "spam.ham", ["spam", "ham", "foo", QueryParser("1"), "bar"]),
    ],
)
def test_path_parser(path: str, relative_path: str, output: list[Union]):
    assert PathParser(path).parse(relative_path) == output
