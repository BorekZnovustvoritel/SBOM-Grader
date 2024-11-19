# SBOM Grader

This project grades SBOMs according to [Red Hat Product Security Guide to SBOMs](
https://redhatproductsecurity.github.io/security-data-guidelines/sbom/
).

## Installation

- Clone this repository
- Run 
  ```bash 
  python3 -m venv .venv
  source .venv/bin/activate
  python3 -m pip install pdm
  pdm install
  ``` 
  
## Quick start

To show the command line options, run the following command:

```bash
python3 main.py --help
```

This script uses both STDOUT and STDERR. STDOUT receives the output of the grading, while STDERR reports 
anything causing troubles to the command execution unrelated to the SBOM file.

## Architecture

This project uses terms like *Rules*, *RuleSets*, *Cookbooks* and *CookbookBundles*. These are all representations
of a test suite to run against an SBOM file.

CookbookBundles are composed of Cookbooks which reference RuleSets which are made of Rules.

Rules are specific tests to be run, RuleSets are suites of Rules.

Cookbook defines which *force* has to be applied on each rule for each SBOM type. You are completely
free to create your own cookbook if the provided ones don't suit your needs. CookbookBundles
are only aggregation of Cookbooks which ensures no test has to be run more than once on any document.

For details about Cookbooks, refer to the [cookbooks/README.md](cookbooks/README.md) file.

For details about RuleSets, refer to the [rulesets/README.md](rulesets/README.md) file.
