import json

from rules.cookbooks import Cookbook
from rules.rule import RuleSet, Document
from definitions import get_mapping, RULESET_DIR, COOKBOOKS_DIR

cookbook = Cookbook.from_schema(COOKBOOKS_DIR / "image_index_build.yml")
d = Document(get_mapping("sample_sbom.json"))
res = cookbook(d)
print(res)
