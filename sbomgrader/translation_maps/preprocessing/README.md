# Preprocessors

Preprocessors are functions that allow normalization of data before processing.

To add a preprocessor, create a file called `first.py`, `second.py`, `<first_format>.py`
or `<second_format>.py` in a directory with the same name as the Translation Map. Then
add a Python function to it. The name of the function will have to be referenced in
the TranslationMap to be executed.

The function MUST take a single argument, the source SBOM dictionary.

If a preprocessor returns any value, the document is replaced by this value.
If it does not return anything, it is assumed that all necessary mutations
were done in-place.

Do not forget to include th preprocessor name to the map to the keys `firstPreprocessing`
or `secondPreprocessing`. (This key holds a list of strings -- the names of the functions).

Only the preprocessors associated with the input SBOM format will be executed.
