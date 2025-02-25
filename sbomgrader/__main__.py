import sys
from argparse import ArgumentParser
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown

from sbomgrader.core.formats import SBOMFormat
from sbomgrader.grade.choose_cookbooks import select_cookbook_bundle
from sbomgrader.grade.cookbook_bundles import CookbookBundle
from sbomgrader.grade.cookbooks import Cookbook
from sbomgrader.core.documents import Document
from sbomgrader.core.enums import Grade, SBOMTime, OutputType, SBOMType
from sbomgrader.core.utils import get_mapping, validation_passed
from sbomgrader.translate.choose_map import choose_map, get_all_map_list_markdown
from sbomgrader.translate.translation_map import TranslationMap


def grade():
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

    if args.cookbooks:
        cookbook_bundle = select_cookbook_bundle(args.cookbooks)
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


def convert():
    parser = ArgumentParser("sbomconv")
    parser.add_argument(
        "input",
        type=Path,
        help="SBOM File to convert. Currently supports JSON.",
        nargs="?",
    )
    parser.add_argument(
        "--list-maps",
        "-l",
        action="store_true",
        default=False,
        help="List available default translation maps and exit.",
    )
    parser.add_argument(
        "--output-format",
        "-f",
        choices=[v.value for v in SBOMFormat],
        required=not ("--list-maps" in sys.argv or "-l" in sys.argv),
        help="",
    )
    parser.add_argument(
        "--custom-map", "-m", type=Path, help="Custom translation map file.", nargs="*"
    )
    args = parser.parse_args()

    custom_map_files = args.custom_map or []
    custom_maps = [TranslationMap.from_file(f) for f in custom_map_files]

    if args.list_maps:
        console = Console()
        console.print(Markdown(get_all_map_list_markdown(*custom_maps)))
        exit(0)
    inp_file = args.input
    if not inp_file:
        print("Please supply an SBOM file.", file=sys.stderr)
        parser.print_help(sys.stderr)
        exit(1)
    doc = Document(get_mapping(inp_file))

    target_format = SBOMFormat(args.output_format)

    t_map = choose_map(doc, target_format, *custom_maps)
    print(t_map.convert(doc, target_format).json_dump)


if __name__ == "__main__":
    grade()
