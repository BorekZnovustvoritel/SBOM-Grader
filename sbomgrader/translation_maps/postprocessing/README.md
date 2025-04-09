# Postprocessors

Postprocessors are functions that allow normalization of data after processing.

To add a postprocessor, create a file called `first.py`, `second.py`, `<first_format>.py`
or `<second_format>.py` in a directory with the same name as the Translation Map. Then
add a Python function to it. The name of the function will have to be referenced in
the TranslationMap to be executed.

The function MUST take two arguments, the source SBOM dictionary (in the source format)
and the document to be adjusted (in the other format of the map).

If a postprocessor returns any value, the output document is replaced by this value.
If it does not return anything, it is assumed that all necessary mutations
were done in-place.

Do not forget to include th postprocessor name to the map to the keys `firstPostprocessing`
or `secondPostprocessing`. (This key holds a list of strings -- the names of the functions).

Only the preprocessors associated with the output SBOM format will be executed.

