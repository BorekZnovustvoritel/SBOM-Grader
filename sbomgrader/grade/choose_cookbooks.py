import sys
from pathlib import Path

from sbomgrader.grade.cookbook_bundles import CookbookBundle
from sbomgrader.grade.cookbooks import Cookbook


def select_cookbook_bundle(cookbooks: list[str]) -> CookbookBundle:
    cookbook_bundles = []
    default_cookbooks = Cookbook.load_all_defaults()
    cookbook_bundle = CookbookBundle([])
    for cookbook in cookbooks:
        cookbook_obj = next(
            filter(lambda x: x.name == cookbook, default_cookbooks), None
        )
        if cookbook_obj:
            # It's a default cookbook name
            cookbook_bundle += cookbook_obj
            continue
        cookbook = Path(cookbook)
        if cookbook.is_dir():
            cookbook_bundle += CookbookBundle.from_directory(cookbook)
            if not cookbook_bundle.cookbooks:
                print(
                    f"Could not find any cookbooks in directory {cookbook.absolute()}",
                    file=sys.stderr,
                )
        elif cookbook.is_file() and (
            cookbook.name.endswith(".yml") or cookbook.name.endswith(".yaml")
        ):
            cookbook_bundles.append(CookbookBundle([Cookbook.from_file(cookbook)]))
        else:
            print(f"Could not find cookbook {cookbook.absolute()}", file=sys.stderr)

    for cb in cookbook_bundles:
        cookbook_bundle += cb
    return cookbook_bundle
