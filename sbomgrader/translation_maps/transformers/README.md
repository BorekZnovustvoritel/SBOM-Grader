# Transformation Functions

These are functions that allow transforming variable values to the other format.

To add a transformer, create a file called `first.py`, `second.py`, `<first_format>.py`
or `<second_format>.py` in a directory with the same name as the Translation Map. Then
add a Python function to it. The name of the function will have to be referenced in
the TranslationMap to be executed.

To use the defined transformer, use the `func` filter in Jinja2 template in the
`firstData` od `secondData` of chunks. Provide the argument `name` to this filter.
Other arguments will be passed to the defined function.

The output of the function will be passes back to Jinja2 as-is. It is possible
to chain these filters if necessary.

Only the transformers associated with the input SBOM format will be used.
