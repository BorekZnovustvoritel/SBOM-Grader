# Cookbooks

Cookbooks aggregate RuleSets by the *force* that should be applied to each rule.

The rules can have three levels of force: MUST, SHOULD and MAY.

- If a MUST rule is broken, the grader returns grade F.
- If a SHOULD rule is broken, the grader lowers the grade.
- If a MAY rule is broken, the grade is not affected.

## Syntax

It is a yaml file with 4 fields: `MUST`, `SHOULD`, `MAY` and `rulesets`.

### `rulesets`

This is a list of ruleset names. If you want to reference a built-in ruleset,
simply write its name (only `general` and `specific` rulesets exist as of now).

If you wish to use your own ruleset, write the full path to the ruleset file.

Example value:

```yaml
---
rulesets:
  - general
  - /home/foo/Documents/my_rulesets/ultimate_ruleset.yml
```

Please keep in mind that you also have to create the ruleset implementation files if you want to use
any functions in your rulesets.

### `MUST` / `SHOULD` / `MAY`

All of these fields are a list of rule names to be applied with the appropriate force.
All of these rules must be present in some of the rulesets to actually be used.

```yaml
---
MUST:
  - Document passes schema validation
  - Main element is a package
SHOULD:
  - All packages have a versionInfo
  - License list has correct form
  - All packages are referenced in relationships
MAY:
  - All files SPDXIDs have format SPDXRef-File-filename-digest
```
