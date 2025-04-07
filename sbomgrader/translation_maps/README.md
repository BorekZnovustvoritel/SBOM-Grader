# Translation Maps

Translation maps allows maintainers or users to create
a custom guideline for SBOM translation.

Translation Maps operate in `chunks`. Each chunk represents
a chunk of information that has to be preserved across two
SBOM formats.

Each chunk can map to more than a single instance in the SBOM.
This means that you can create a single chunk for all components
of a certain type and all of them will be matched separately
according to the chunk definition.

## Format

Translation Maps map information to two SBOM formats at the same time.
These formats are described by their abbreviations in the fields `first`
and `second`. All other information tracked in Translation Maps is
arranged in similar manner.

The other fields of a Translation Map are:

- `firstVariables`
- `secondVariables`
- `chunks`

> **_NOTE:_** The keywords `first` and `second` do not imply the direction
> of the SBOM translation. All Translation Maps are supposed to be bidirectional.

## Variables

Variables can be specified for both the first or the second SBOM format.

The variables have 2 use-cases:

- Usage in `FieldPath` queries
- Filling in the data in chunks (explained later)

When used in `FieldPath` queries, variable values are always loaded from
the currently processed format.

> **_NOTE:_** To learn more about FieldPath Queries, refer to 
> [this Document](../rulesets/README.md).

When used in data chunks, variables are always searched in **the opposite** format.

## Chunks

Chunks capture a piece of information inside two SBOM formats. If this piece
of information is found inside one of the formats, it shall be transferred
to the other format by a set of transformations defined by a chunk.

The attribute `chunks` is a list. Each item describes a single chunk.
Each chunk has the following attributes:

- `name`
- `firstVariables`
- `secondVariables`
- `firstData`
- `secondData`
- `firstFieldPath`
- `secondFieldPath`

### Name

This field is required, but not used in the actual process. Chunks should be named
to make the Translation Map file more readable.

### Variables

Unlike global variables (shown earlier), the chunk variables also hold a context
of the currently resolved chunk instance. This context allows relative
Field Path queries.

**Example:**

```yaml
---
first: spdx23
...
chunks:
  - name: packages
    firstFieldPath: packages[|]
    firstVariables:
      - name: foo
        fieldPath: '@.SPDXID'
```

For each found package, the variable `foo` will have a different value. For the
first package, the value will be equal to the list containing the value from path
`packages[0].SPDXID`, for the second package, the value list will only contain the
value from `packages[1].SPDXID` and so on.

---

There is also an option to specify relative path at a lower level (it only shares a
portion of the path with the chunk location).

**Example:**
```yaml
---
...
chunks:
  - name: packages_purls
    firstFieldPath: packages[|]externalRefs[referenceType=purl]referenceLocator
    firstVariables:
      - name: package_spdxid
        fieldPath: 'packages[@]SPDXID'
```

This way it is possible to create a chunk for each purl while also keeping
track of the SPDXID of the package which this purl is associated to.

### Data

This part of the Translation Map is a **string** holding a `jinja2` template. This
template is rendered with the use of variables. The rendered string is then loaded
as yaml and inserted into the translated document.

> **_NOTE:_** The variable values are always a list. To only use a single object
> of this list, use the special filter `unwrap`. (Like so: `{{ varname | unwrap }}`).

> **_NOTE:_** The variables in the templates must be specified in the opposite
> variable definition. (Variables referenced in `firstData` must be declared in
> `secondVariables`).


Data also allow additional filtering using Python functions. The functions have
to be located in a file called `first.py` or `<value of the field "first">.py`
for the `firstVariables` and `second.py` or `<value of the field "second">.py`
inside a directory structure `transformers/<name of the translation map file without an extension>`.

To use these functions as filters, use a `jinja2` filter `func` with parameter
`name` set to a string with the function's name.

**Example:**

For a translation map file `/home/me/foo.yml` with `first` containing `spdx23`
and `second` containing `cdx16`, we create files
`/home/me/transformers/foo/first.py` and `/home/me/transformers/foo/second.py`.

Inside the `first.py`, we define a function `def last(items): return items[-1]`.

We also define a variable `bar` in a field `firstVariables`.

In `secondData` of a sample chunk, we can now use the following expression:

```
{{ bar | func(name="last") }}
```
which will resolve into the last value of the variable `bar`.

More information about transformation functions is located [here](transformers/README.md).
There have also been added these Jinja2 filters:

- `unwrap`
  - Unwraps a list, returns the first value of the list. In case of a problem, returns an empty string instead.
- `slice`
  - Slices a list or a string. Takes 2 arguments, `start`, `end`, each of which can be omitted.
  - The `start` argument specifies the first index to include.
  - The `end` argument specifies the first index to exclude and end the slicing.
- `fallback`
  - Takes any number of arguments, to which any variables can be passed
  - Returns the first non-empty value, in a list
  - Returns an empty list as a fallback
  - Example use: ` {{ foo | fallback(bar, spam) | unwrap }}`
    - This returns either value of `foo`, `bar` or `spam`, whichever is non-empty.
    - Precedence is order-dependent.

### Field Path

These attributes specify at what path the chunk occurs in the SBOM. This path
does not need to resolve a single element. If more elements are fetched, the
chunk will perform the transformation on each of the found instances.

## Example:

- The attribute `first` has value `cdx16` and
  the attribute `second` has value `spdx23` and a document
  to be translated has the format `spdx23`
- Only the variables in the attribute `secondVariables`
  get populated from this `spdx23` document
- When resolving a FieldPath query for a chunk's attribute
  `secondFieldPath`, these variables are used
- When resolving a template for a chunk's attribute
  `firstData`, these variables are also used
- These variables will not be used for resolution of
  FieldPath queries of the `firstFieldPath`, which is
  used to determine where to place the converted chunk

```yaml
---
first: cdx16
second: spdx23
firstVariables:
  <omitted>
secondVariables:
  - name: foo
    fieldPath: spdxVersion  # In SPDX 2.3, this is always "SPDX-2.3"
...
chunks:
  - name: something
    firstFieldPath: components[<some query>]
    secondData: <omitted>
    secondFieldPath: packages[nonexistentField=${foo}]
    firstData: |-
      data: {{ foo | unwrap }}  # Will resolve to a dictionary `{"data": "SPDX-2.3"}`
                                # which will be inserted to a list at path `components`
```