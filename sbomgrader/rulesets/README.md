# Rulesets

Rulesets define rules to be chosen from when crafting Cookbooks.
To create a Ruleset, make sure to follow the schema inside the `schema/` dir.

More details will be provided here.

## *FieldPath* Query Language

This project has a unique query language for dynamic SBOM field querying. The options are:

- querying attributes (`foo.bar.spam` queries attribute named `foo`, then its attribute `bar` and then its attribute `spam`)
- declaring skippable part of the path (`?.foo` queries attribute named `foo` only if it exists in the object)
- querying items of a list (`[foo!=${variable1}]` queries only items in the list whose attribute `foo` is not in a set stored in `variable1`)

### All list filtering options

- `foo[&]bar` queries all attributes `bar` in a list called `foo`
- `foo[|]bar` queries all attributes `bar` in a list called `foo` but permits failures for 
  less items than is the length of list `foo`
- `foo[id=1,name!=hi]bar` queries all attributes `bar` for items in `foo` which have attribute
  `id` equal to `1` and attribute `name` not equal to `hi`
- `foo[bar%=hello]` Queries all elements in the list `foo` which contain an attribute `bar`
  with a value that STARTS with a string `hello`
- `foo[bar%=See you.]` Queries all elements in the list `foo` which contain an attribute `bar`
  with a value that ENDS with a string `See you.`
- `foo[bar%sbom]` Queries all elements in the list `foo` which contain an attribute `bar`
  with a value that CONTAINS a string `sbom`
- `foo[bar!%vex]` Queries all elements in the list `foo` which contain an attribute `bar`
  with a value that DOES NOT CONTAIN the string `vex`
- `foo[id=${my_var},name!=${your_var}]` queries all attributes `bar` for items in `foo` which
  have attribute `id` equal to some value in variable `my_var` and attribute `name` not equal
  to any value in variable `your_var`. Note that the variable has to be on the right side of
  the operator (`=` or `!=`).

## Syntax

The file contains only 2 fields: `variables` and `rules`.

### `variables`


These *ruleset-global* variables store values that can be used for querying fields to use.
Variable values are ALWAYS sets. Make sure to only reference hashable types in them.

Example value:

```yaml
---
variables:
  implementations:
    - name: spdx23
      variables:
        - name: generated_spdxids
          fieldPath: relationships[relationshipType=GENERATED_FROM]spdxElementId
```

This configuration creates a variable with all SPDXIDs that reference objects created from some other objects.
The variable value will be available as a set for all rules with implementation `spdx23` in this RuleSet.

Variables can also contain other variables in their fieldPath queries, the dependency graph for variables
simply has to be solvable (no cyclic variable references).

### `rules`

Each rule can have multiple implementations, for different SBOM standards. It has to have a unique name and
a message to display upon test failure. This message will be accompanied by details from the test runtime.

Example value:

```yaml
---
rules:
  - name: Main element is a package
    failureMessage: SPDXRef-DOCUMENT has to reference an object of type package.
    implementations:
      - name: spdx23
        variables:
          - name: main_spdxids
            fieldPath: relationships[spdxElementId=SPDXRef-DOCUMENT,relationshipType=DESCRIBES]relatedSpdxElement
        fieldPath: packages[SPDXID=${main_spdxids}]
        checker:
          neq: FIELD_NOT_FOUND
```

This rule filters all SPDXID values that are described by the SPDXRef-DOCUMENT and checks if
the element with such SPDXID exists in the packages list.

The value `FIELD_NOT_FOUND` is used do describe a field that is not present in the document.

Local variables take precedence before the global variables.

The `fieldPath` is the FieldPath query as mentioned above.


The complete list of checkers:

- `eq: val` Asserts that all queried fields are equal to the declared value
- `neq: val` Assert that none of the queried fields are equal to the declared value
- `in: [...]` Asserts that all queried fields are in the declared list
- `not_in: [...]` Assert that none of the queried fields are in the declared list
- `str_startswith: text` Asserts that all the queried fields are strings that start with the declared value
- `str_endswith: text` Asserts that all the queried fields are strings that end with the declared value
- `str_contains: text` Asserts that all the queried fields are strings that contain the declared value
- `str_matches_regex: pattern` Asserts that all the queried fields are strings that match the declared regex pattern
- `length_eq: integer` Asserts that all the queried fields are of the declared length
- `length_gt: integer` Asserts that all the queried fields have bigger length than the declared value
- `length_lt: integer` Asserts that all the queried fields have smaller length than the declared value
- `func_name: func` Runs the function on all queried fields and asserts that it returns either `True` or `None` for all of them

The `func_name` checker requires that the function declared takes the doc or an instance of the queried field
as an argument. The definition of this function must be located in a file `implementations/<rule_set_name>/<implementation>.py`
relative to the RuleSet named `<rule_set_name>.yml`.

The rules also store how many elements have been tested for each query. By default, the test fails
if it was not run on any field (no fields match the query). This can be overridden with
`minimumTestedElements` variable inside the implementation specification.
