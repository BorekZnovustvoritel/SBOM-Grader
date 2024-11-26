import sys
from argparse import ArgumentParser
from pathlib import Path

from sbomgrader.core.cookbook_bundles import CookbookBundle
from sbomgrader.core.cookbooks import Cookbook
from sbomgrader.core.documents import Document
from sbomgrader.core.enums import Grade, SBOMTime, OutputType, SBOMType
from sbomgrader.core.utils import get_mapping, validation_passed


def main():
    parser = ArgumentParser("sbomgrader")
    parser.add_argument(
        "input", type=Path, help="SBOM File to grade. Currently supports JSON."
    )
    parser.add_argument(
        "--cookbooks",
        "-c",
        action="append",
        type=Path,
        help="Cookbooks to use for validation. Might reference directories or files. Only files with '.yml' or '.yaml' extensions are taken into account.",
    )
    parser.add_argument(
        "--type",
        "-tp",
        choices=[v.value for v in SBOMType if v is not SBOMType.UNSPECIFIED],
        default=SBOMType.UNSPECIFIED.value,
        help="Specify SBOM type. Ignored if cookbooks argument is specified.",
    )
    parser.add_argument(
        "--time",
        "-tm",
        choices=[v.value for v in SBOMTime if v is not SBOMTime.UNSPECIFIED],
        default=None,
        help="If using the standard validation, specify which SBOM type (by time) is being validated. Ignored if cookbooks argument is specified.",
    )
    parser.add_argument(
        "--passing-grade",
        "-g",
        choices=[v.value for v in Grade],
        default=Grade.B.value,
        help="Minimal passing grade. Default is B.",
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
            elif cookbook.is_file() and (
                cookbook.name.endswith(".yml") or cookbook.name.endswith(".yaml")
            ):
                cookbook_bundles.append(CookbookBundle([Cookbook.from_file(cookbook)]))
            else:
                print(f"Could not find cookbook {cookbook.absolute()}", file=sys.stderr)

        for cb in cookbook_bundles:
            cookbook_bundle += cb
        if not cookbook_bundle.cookbooks:
            print("No cookbook(s) could be found.", file=sys.stderr)
            exit(1)
    else:
        # Cookbooks weren't specified, using defaults
        type_ = SBOMType(args.type)
        if type_ is SBOMType.UNSPECIFIED:
            type_ = doc.sbom_type
        cookbook_bundle = CookbookBundle.for_document_type(type_, SBOMTime(args.time))

    result = cookbook_bundle(doc)

    print(result.output(OutputType(args.output)))
    if validation_passed(result.grade, Grade(args.passing_grade)):
        exit(0)
    exit(1)


if __name__ == "__main__":
    main()
