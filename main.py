import json
from rules.rule import RuleSet, Document
from definitions import get_mapping, RULESET_DIR

r = RuleSet.from_schema(RULESET_DIR / "specific.yml")
print(r)
d = Document(get_mapping("sample_sbom.json"))
res = r(d)
print(res)
