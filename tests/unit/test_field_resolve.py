from copy import deepcopy
from typing import Union

import pytest

from sbomgrader.core.enums import QueryType
from sbomgrader.core.field_resolve import (
    PathParser,
    QueryParser,
    FieldResolver,
    Query,
    Variable,
)


@pytest.mark.parametrize(
    ["path", "relative_path", "output"],
    [
        ("foo", "", ["foo"]),
        ("foo.bar", "", ["foo", "bar"]),
        ("foo[1]bar", "", ["foo", QueryParser("1"), "bar"]),
        ("@.foo[1]bar", "spam.ham", ["spam", "ham", "foo", QueryParser("1"), "bar"]),
        (
            "foo[@]bar[@]spam",
            "foo[4]bar[2]ham[7]",
            ["foo", QueryParser(4), "bar", QueryParser("2"), "spam"],
        ),
    ],
)
def test_path_parser(path: str, relative_path: str, output: list[Union]):
    assert PathParser(path).parse(relative_path) == output


@pytest.mark.parametrize(
    ["path"],
    [
        ("hello.foo[bar=1,spam!=2]ham",),
        ("hello . foo [bar =1, spam != 2 ] ham",),
        (".hello.foo.[.bar.=1,.spam.!= 2 ].ham",),
        (" . hello . foo . [ . bar . =1, . spam . != 2] . ham",),
        ("..hello..foo..[..bar..=1,..spam..!=2 ]..ham",),
    ],
)
def test_path_parser_unambiguity(path: str):
    assert PathParser(path).parse() == [
        "hello",
        "foo",
        QueryParser("bar=1,spam!=2"),
        "ham",
    ]


@pytest.mark.parametrize(
    ["query_str"],
    [
        ("bar=1,spam!=2",),
        ("bar =1, spam !=2",),
        (".bar.=1,.spam.!=2",),
        (" . bar . =1, . spam . !=2",),
        ("..bar..=1,..spam..!=2",),
    ],
)
def test_query_parser_unambiguity(query_str: str):
    assert QueryParser(query_str).parse() == [
        Query(QueryType.EQ, value="1", field_path=PathParser("bar")),
        Query(QueryType.NEQ, value="2", field_path=PathParser("spam")),
    ]


@pytest.mark.parametrize(
    ["path", "document", "output"],
    [
        (
            "dependencies[provides[&]%=]",
            {
                "dependencies": [
                    {
                        "ref": "foo",
                        "provides": ["bar"],
                        "dependsOn": [],
                    },
                    {
                        "ref": "spam",
                        "provides": [],
                        "dependsOn": ["ham"],
                    },
                ]
            },
            [  # Output is always a list
                {
                    "ref": "foo",
                    "provides": ["bar"],
                    "dependsOn": [],
                }
            ],
        ),
        (
            "foo[bar=FIELD_NOT_PRESENT]",
            {"foo": [{"bar": 1}, {"spam": 2}]},
            [{"spam": 2}],
        ),
    ],
)
def test_fetch_fields(path, document, output):
    resolver = FieldResolver({})
    assert output == resolver.get_objects(document, path)


@pytest.mark.parametrize(
    ["path", "expected"],
    [
        (".=.", [Query(QueryType.EQ, ".", PathParser("."))]),
        (
            "?.purl%=pkg:rpm/,?.purl%arch=src",
            [
                Query(QueryType.STARTSWITH, "pkg:rpm/", PathParser("?.purl")),
                Query(QueryType.CONTAINS, "arch=src", PathParser("?.purl")),
            ],
        ),
        (
            "externalRefs[referenceType=purl]referenceLocator%=pkg:generic/",
            [
                Query(
                    QueryType.STARTSWITH,
                    "pkg:generic/",
                    PathParser("externalRefs[referenceType=purl]referenceLocator"),
                )
            ],
        ),
    ],
)
def test_query_parser(path: str, expected: list[Query]):
    assert QueryParser(path).parse() == expected


@pytest.mark.parametrize(
    ["path", "variables", "original_doc", "expected_doc"],
    [
        (".foo.bar", {}, {}, {"foo": {}}),
        ("foo[|]", {}, {}, {"foo": []}),
        ("?.foo.?.bar", {}, {}, {"foo": {}}),
        (
            "foo[|]?.bar.spam",
            {},
            {"foo": [{"ham": 1}]},
            {"foo": [{"ham": 1, "bar": {}}]},
        ),
        (
            "foo[|]?.bar[|].?.spam.?.ham",
            {},
            {"foo": [{"bar": [{"hi": 1}]}]},
            {"foo": [{"bar": [{"hi": 1, "spam": {}}]}]},
        ),
    ],
)
def test_create_nonexistent(
    path: str, variables: dict[str, Variable], original_doc, expected_doc
):
    """Tests if non-present fields are correctly created"""
    resolver = FieldResolver(variables)
    testing_doc = deepcopy(original_doc)
    resolver.get_objects(testing_doc, path, {}, True)
    assert expected_doc == testing_doc
