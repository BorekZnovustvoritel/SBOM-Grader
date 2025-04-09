from sbomgrader.core.definitions import TRANSLATION_MAP_DIR
from sbomgrader.core.documents import Document
from sbomgrader.core.formats import SBOMFormat, get_fallbacks
from sbomgrader.core.utils import is_mapping
from sbomgrader.translate.translation_map import TranslationMap


def choose_map(
    document: Document, out: SBOMFormat, *custom_maps: TranslationMap
) -> TranslationMap:
    """Choose the translation map according to the document and output format."""
    for map_set in (custom_maps, get_default_maps()):
        # Prefer custom maps to default ones
        for match_type in ("exact", "suitable"):
            # Prefer exact matches to fallbacks
            for map_ in map_set:
                if getattr(map_, f"is_{match_type}_map")(document.sbom_format, out):
                    return map_
    raise NotImplementedError(
        f"Cannot convert from format {document.sbom_format.value} to {out.value}. No such map is implemented."
    )


def get_default_maps() -> list[TranslationMap]:
    """Returns the list of pre-installed maps."""
    ans = []
    for file in TRANSLATION_MAP_DIR.iterdir():
        if not is_mapping(file):
            continue
        ans.append(TranslationMap.from_file(file))
    return ans


def get_all_map_list_tuples(
    *custom_maps: TranslationMap,
) -> tuple[set[tuple[SBOMFormat, SBOMFormat]], set[tuple[SBOMFormat, SBOMFormat]]]:
    """
    Returns 2 tuples, each contains a pair of SBOMFormat instances.
    These represent available translation directions.
    """
    direction_tuples = set()
    all_maps = [*get_default_maps(), *custom_maps]
    for map_ in all_maps:
        formats = tuple(sorted((map_.first, map_.second), key=lambda x: x.value))
        direction_tuples.add(formats)
    # Add fallbacks, include transitive relations
    fallback_tuples = {*direction_tuples}
    starting_fallback_tuples = set()
    while starting_fallback_tuples != fallback_tuples:
        # Perform until no further changes occur
        starting_fallback_tuples = {*fallback_tuples}
        for tuple_ in starting_fallback_tuples:
            for format_ in SBOMFormat:
                fallbacks = get_fallbacks(format_)
                if tuple_[0] in fallbacks:
                    fallback_tuples.add((format_, tuple_[1]))
                if tuple_[1] in fallbacks:
                    fallback_tuples.add((tuple_[0], format_))
    fallback_tuples = fallback_tuples - direction_tuples
    return direction_tuples, fallback_tuples


def get_all_map_list_markdown(*custom_maps: TranslationMap) -> str:
    """Returns a Markdown string representing all possible translation directions."""
    map_directions, fallback_tuples = get_all_map_list_tuples(*custom_maps)
    ans = ""
    for tuple_ in map_directions:
        ans += f"- {tuple_[0].value} <-> {tuple_[1].value}\n"
    for tuple_ in fallback_tuples:
        ans += f"- {tuple_[0].value} <-> {tuple_[1].value} (fallback)\n"
    return ans
