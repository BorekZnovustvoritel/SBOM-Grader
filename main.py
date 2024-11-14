from argparse import ArgumentParser, FileType
from pathlib import Path

from core.cookbook_bundles import CookbookBundle
from core.documents import Document
from core.enums import Grade, SBOMTime, OutputType
from core.utils import get_mapping, validation_passed


def main():
    parser = ArgumentParser("sbomgrader")
    parser.add_argument("input", type=Path)
    parser.add_argument("--cookbooks", action="append", type=FileType())
    parser.add_argument(
        "--time", choices=[v.value for v in SBOMTime], default=SBOMTime.RELEASE.value
    )
    parser.add_argument(
        "--grade", choices=[v.value for v in Grade], default=Grade.B.value
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=[v.value for v in OutputType],
        default=OutputType.VISUAL.value,
    )

    args = parser.parse_args()

    sbom_file = args.input
    doc = Document(get_mapping(sbom_file))
    cookbook_bundle = CookbookBundle.for_document(doc, SBOMTime(args.time))
    result = cookbook_bundle(doc)

    print(result.output(OutputType(args.output)))
    if validation_passed(result.grade, Grade(args.grade)):
        exit(0)
    exit(1)


if __name__ == "__main__":
    main()
