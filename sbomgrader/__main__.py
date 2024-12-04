import sys
from argparse import ArgumentParser
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown

from sbomgrader.core.cookbook_bundles import CookbookBundle
from sbomgrader.core.cookbooks import Cookbook
from sbomgrader.core.documents import Document
from sbomgrader.core.enums import Grade, SBOMTime, OutputType, SBOMType
from sbomgrader.core.utils import get_mapping, validation_passed


def main():
    parser = ArgumentParser("sbomgrader")
    parser.add_argument(
        "input",
        type=Path,
        help="SBOM File to grade. Currently supports JSON.",
        nargs="?",
    )
    parser.add_argument(
        "--cookbooks",
        "-c",
        action="append",
        type=str,
        help="Cookbooks to use for validation. "
        "Might reference default cookbooks, directories or files. "
        "Only files with '.yml' or '.yaml' extensions are taken into account if files or directories are specified.",
    )
    parser.add_argument(
        "--list-cookbooks",
        "-l",
        action="store_true",
        default=False,
        help="List available default cookbooks and exit.",
    )
    parser.add_argument(
        "--content-type",
        "-ct",
        choices=[v.value for v in SBOMType if v is not SBOMType.UNSPECIFIED],
        default=SBOMType.UNSPECIFIED.value,
        help="Specify SBOM content type. Ignored if cookbooks argument is specified.",
    )
    parser.add_argument(
        "--sbom-type",
        "-st",
        choices=[v.value for v in SBOMTime if v is not SBOMTime.UNSPECIFIED],
        default=None,
        help="If using the standard validation, specify which SBOM type (by time) is being validated. "
        "Ignored if cookbooks argument is specified.",
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
    console = Console()
    default_cookbooks = Cookbook.load_all_defaults()
    if args.list_cookbooks:
        console.print(Markdown("\n".join(f"- {cb.name}" for cb in default_cookbooks)))
        exit(0)

    sbom_file = args.input
    if not sbom_file:
        print("Please supply an SBOM file.", file=sys.stderr)
        parser.print_help(sys.stderr)
        exit(1)
    doc = Document(get_mapping(sbom_file))

    cookbook_bundles = []
    if args.cookbooks:
        cookbook_bundle = CookbookBundle([])
        for cookbook in args.cookbooks:
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
        if not cookbook_bundle.cookbooks:
            print("No cookbook(s) could be found.", file=sys.stderr)
            exit(1)
    else:
        # Cookbooks weren't specified, using defaults
        type_ = SBOMType(args.content_type)
        if type_ is SBOMType.UNSPECIFIED:
            type_ = doc.sbom_type
        cookbook_bundle = CookbookBundle.for_document_type(
            type_, SBOMTime(args.sbom_type)
        )

    result = cookbook_bundle(doc)

    output_type = OutputType(args.output)
    if output_type is OutputType.VISUAL:
        markdown = Markdown(result.output(output_type))
        console.print(markdown)
    else:
        console.print(result.output(output_type), output_type.value)
    if validation_passed(result.grade, Grade(args.passing_grade)):
        exit(0)
    exit(1)


if __name__ == "__main__":
    main()
