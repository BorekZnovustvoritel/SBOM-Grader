# SBOM Grader

This project grades SBOMs according to [Red Hat Product Security Guide to SBOMs](
https://redhatproductsecurity.github.io/security-data-guidelines/sbom/
).

Currently the script only fully supports SPDX v2.3 in json format. CycloneDX is
partially supported in version v1.5 for Product SBOMs.

## Installation

```bash
pip install sbomgrader
```
  
## Quick start

To show the command line options, run the following command:

```bash
sbomgrader --help
```

This script uses both STDOUT and STDERR. STDOUT receives the output of the grading, while STDERR reports 
anything causing troubles to the command execution unrelated to the SBOM file.

## Usage options


This application provides three subcommands:

- `grade`
- `convert`
- `list`

### `sbomgrader grade`

This command grades SBOMs.

If you only specify the SBOM document, the script will try to estimate the SBOM type and apply all time-related
cookbooks for that type (e.g. if it finds that an SBOM is for an RPM, it will run both rpm build and rpm release cookbooks).
The release-time cookbook will take precedence in establishing the final grade.

To specify the cookbook to be used, use `-c` option. This option must be a reference
to an `.y[a]ml` file in the filesystem or a default cookbook. Can be used multiple times
to create a Cookbook bundle. To list default cookbooks, use `sbomgrader list -c`.

To specify SBOM type, the tool lets you specify content type `-ct` and SBOM type `-st`.
Component type is either `product`, `image`, `image_index`, `rpm` or `generic`. Generic type
only checks the common features of other types, the other types are described [here]
(https://redhatproductsecurity.github.io/security-data-guidelines/sbom/). The SBOM types
are also explained in the article linked. You can select values `build` or `release`.

The default passing grade is B. This can be changed with the argument `-g` and the target value.

The script outputs data in three possible formats. The default one in Markdown,
you can also select `json` or `yaml`.


#### Architecture

This project uses terms like *Rules*, *RuleSets*, *Cookbooks* and *CookbookBundles*. These are all representations
of a test suite to run against an SBOM file.

CookbookBundles are composed of Cookbooks which reference RuleSets which are made of Rules.

Rules are specific tests to be run, RuleSets are suites of Rules.

Cookbook defines which *force* has to be applied on each rule for each SBOM type. You are completely
free to create your own cookbook if the provided ones don't suit your needs. CookbookBundles
are only aggregation of Cookbooks which ensures no test has to be run more than once on any document.

For details about Cookbooks, refer to the [sbomgrader/cookbooks/README.md](sbomgrader/cookbooks/README.md) file.

For details about RuleSets, refer to the [sbomgrader/rulesets/README.md](sbomgrader/rulesets/README.md) file.

### `sbomgrader convert`

This command converts SBOMs between standards.

To convert an SBOM, provide path to the JSON file containing the SBOM and a desired output format
using the option `-f`. To list all available conversion maps, use the command `sbomgrader list -m`.

You can even specify a custom translation map file yourself with the option `-m`. It must be a yaml file with
the format specified in [sbomgrader/translation_maps/README.md](sbomgrader/translation_maps/README.md). Can
be used multiple times (but only a single map will be used at a time).

User-defined maps can be ignored if the provided map is not suitable. If it is suitable, it will be preferred
to the default maps. The order to pick a map is the following:

- user-defined with an exact version match
- user-defined with a fallback version match
- default with an exact version match
- default with a fallback version match

If no match is found, translation will fail.

### `sbomgrader list`

This command lists default implementations.

To list the default conversion maps, use the flag `-m`.

To list the default cookbooks, use the flag `-c`.
