import logging
import sys
from pathlib import Path

from sbomgrader.grade.cookbook_bundles import CookbookBundle
from sbomgrader.grade.cookbooks import Cookbook

LOGGER = logging.getLogger(__name__)


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
        cookbook_path = Path(cookbook)
        if cookbook_path.is_dir():
            cookbook_bundle += CookbookBundle.from_directory(cookbook_path)
            if not cookbook_bundle.cookbooks:
                LOGGER.warning(
                    f"Could not find any cookbooks in directory {cookbook_path.absolute()}"
                )
        elif cookbook_path.is_file() and (
            cookbook_path.name.endswith(".yml") or cookbook_path.name.endswith(".yaml")
        ):
            cookbook_bundles.append(CookbookBundle([Cookbook.from_file(cookbook_path)]))
        else:
            LOGGER.warning(f"Could not find cookbook {cookbook_path.absolute()}")

    for cb in cookbook_bundles:
        cookbook_bundle += cb
    return cookbook_bundle
