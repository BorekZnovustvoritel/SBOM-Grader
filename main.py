import sys
from argparse import ArgumentParser, FileType
from pathlib import Path

from core.cookbook_bundles import CookbookBundle
from core.cookbooks import Cookbook
from core.documents import Document
from core.enums import Grade, SBOMTime, OutputType
from core.utils import get_mapping, validation_passed


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "input", type=Path, help="SBOM File to grade. Currently supports JSON."
    )
    parser.add_argument(
        "--cookbooks",
        "-c",
        action="append",
        type=Path,
        help="Cookbooks to use for validation. Might reference directories or files. Only files with '.yml' extension are taken into account.",
    )
    # parser.add_argument()
    parser.add_argument(
        "--time",
        "-t",
        choices=[v.value for v in SBOMTime],
        default=SBOMTime.RELEASE.value,
        help="If using the standard validation, specify which SBOM type (by time) is being validated. Ignored if cookbooks argument is specified.",
    )
    parser.add_argument(
        "--passing-grade",
        "-g",
        choices=[v.value for v in Grade],
        default=Grade.B.value,
        help="Minimal passing grade.",
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=[v.value for v in OutputType],
        default=OutputType.VISUAL.value,
        help="Specify the output format.",
    )

    args = parser.parse_args()

    sbom_file = args.input
    doc = Document(get_mapping(sbom_file))

    cookbook_bundles = []
    if args.cookbooks:
        cookbook_bundle = CookbookBundle([])
        for cookbook in args.cookbooks:
            cookbook: Path
            if cookbook.is_dir():
                cookbook_bundle += CookbookBundle.from_directory(cookbook)
                if not cookbook_bundle.cookbooks:
                    print(
                        f"Could not find any cookbooks in directory {cookbook.absolute()}",
                        file=sys.stderr,
                    )
            elif cookbook.is_file() and cookbook.name.endswith(".yml"):
                cookbook_bundles.append(CookbookBundle([Cookbook.from_file(cookbook)]))
            else:
                print(f"Could not find cookbook {cookbook.absolute()}", file=sys.stderr)

        for cb in cookbook_bundles:
            cookbook_bundle += cb
        if not cookbook_bundle.cookbooks:
            print("No cookbook(s) could be found.", file=sys.stderr)
            exit(1)
    else:
        # Nothing was specified, using defaults
        cookbook_bundle = CookbookBundle.for_document(doc, SBOMTime(args.time))

    result = cookbook_bundle(doc)

    print(result.output(OutputType(args.output)))
    if validation_passed(result.grade, Grade(args.passing_grade)):
        exit(0)
    exit(1)


if __name__ == "__main__":
    main()
