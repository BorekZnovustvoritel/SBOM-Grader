from typing import Any

from sbomgrader.core.field_resolve import FieldResolver, Variable
from sbomgrader.translate.prune import prune
from sbomgrader.translation_maps.transformers.red_hat_spdx23_cdx16.spdx23 import (
    spdxid_to_bom_ref,
)


def deduplicate_srpm_midstreams(
    old_doc: dict[str, Any], new_doc: dict[str, Any]
) -> None:
    # First map the relationship correctly according to the old doc
    field_resolver = FieldResolver({})
    old_srpms_spdxids = field_resolver.get_objects(
        old_doc,
        "packages[externalRefs[referenceType=purl]"
        "referenceLocator%=pkg:rpm/,externalRefs[referenceType=purl]"
        "referenceLocator%arch=src]SPDXID",
    )
    midstream_bom_ref_map = {}

    for srpm_spdxid in old_srpms_spdxids:
        related_midstream_spdxids = field_resolver.get_objects(
            old_doc,
            f"relationships[spdxElementId={srpm_spdxid},"
            f"relationshipType=CONTAINS]relatedSpdxElement",
        )
        srpm_purls = field_resolver.get_objects(
            old_doc,
            f"packages[SPDXID={srpm_spdxid}]externalRefs[referenceType=purl]referenceLocator",
        )
        srpm_bom_ref = spdxid_to_bom_ref(srpm_spdxid, srpm_purls)
        midstream_bom_ref_map[srpm_bom_ref] = set()
        for related_midstream_spdxid in related_midstream_spdxids:
            related_midstream_purls = field_resolver.get_objects(
                old_doc,
                f"packages[SPDXID={related_midstream_spdxid}]externalRefs[referenceType=purl]referenceLocator",
            )
            midstream_bom_ref = spdxid_to_bom_ref(
                related_midstream_spdxid, related_midstream_purls
            )
            midstream_bom_ref_map[srpm_bom_ref].add(midstream_bom_ref)

    # Now perform the deduplication
    for component in new_doc.get("components", []):
        if not component.get("bom-ref") in midstream_bom_ref_map:
            continue
        to_remove = []
        ancestors = component.get("pedigree", {}).get("ancestors", [])
        for idx, ancestor in enumerate(ancestors):
            if (
                ancestor.get("bom-ref")
                not in midstream_bom_ref_map[component.get("bom-ref")]
            ):
                to_remove.append(ancestor.get("bom-ref"))
        for idx in reversed(to_remove):
            ancestors.pop(idx)
    prune(new_doc)


def deduplicate_srpm_upstreams(
    old_doc: dict[str, Any], new_doc: dict[str, Any]
) -> None:
    old_field_resolver = FieldResolver(
        {
            "srpm_packages_spdxids": Variable(
                "srpm_packages_spdxids",
                "packages[externalRefs[referenceType=purl]referenceLocator%=pkg:rpm/,externalRefs[referenceType=purl]referenceLocator%arch=src]SPDXID",
            )
        }
    )
    upstream_bom_ref_map = {}
    old_midstream_spdxids = old_field_resolver.get_objects(
        old_doc,
        "relationships[relationshipType=CONTAINS,spdxElementId=${srpm_packages_spdxids}]relatedSpdxElement",
    )
    for midstream_spdxid in old_midstream_spdxids:
        midstream_purls = old_field_resolver.get_objects(
            old_doc,
            f"packages[SPDXID={midstream_spdxid}]externalRefs[referenceType=purl]referenceLocator",
        )
        midstream_bom_ref = spdxid_to_bom_ref(midstream_spdxid, midstream_purls)
        upstream_bom_ref_map[midstream_bom_ref] = set()
        related_upstream_spdxids = old_field_resolver.get_objects(
            old_doc,
            f"relationships[relationshipType=GENERATED_FROM,spdxElementId={midstream_spdxid}]relatedSpdxElement",
        )
        for related_upstream_spdxid in related_upstream_spdxids:
            related_upstream_purls = old_field_resolver.get_objects(
                old_doc,
                f"packages[SPDXID={related_upstream_spdxid}]externalRefs[referenceType=purl]referenceLocator",
            )
            upstream_bom_ref = spdxid_to_bom_ref(
                related_upstream_spdxid, related_upstream_purls
            )
            upstream_bom_ref_map[midstream_bom_ref].add(upstream_bom_ref)
    # Deduplication
    new_field_resolver = FieldResolver({})
    for midstream in new_field_resolver.get_objects(
        new_doc, "components[|].?.pedigree.ancestors[|]"
    ):
        if midstream.get("bom-ref" not in upstream_bom_ref_map):
            continue
        to_remove = []
        ancestors = midstream.get("pedigree", {}).get("ancestors", [])
        for idx, ancestor in enumerate(ancestors):
            if (
                ancestor.get("bom-ref")
                not in upstream_bom_ref_map[midstream.get("bom-ref")]
            ):
                to_remove.append(idx)
        for idx in reversed(to_remove):
            ancestors.pop(idx)


def merge_dependencies(_, new_doc: dict[str, Any]) -> None:
    if "dependencies" not in new_doc:
        return
    new_dependencies = []
    for dep in new_doc.get("dependencies", []):
        dep_ref = dep["ref"]
        dep_obj = next(
            filter(lambda x: x.get("ref") == dep_ref, new_dependencies), None
        )
        if not dep_obj:
            dep_obj = {"ref": dep_ref}
            new_dependencies.append(dep_obj)
        for key in "provides", "dependsOn":
            item_list = dep.get(key)
            if item_list and key not in dep_obj:
                dep_obj[key] = []
            if item_list:
                dep_obj[key].extend(item_list)
    new_doc["dependencies"] = new_dependencies


def resolve_types(_, new_doc: dict[str, Any]) -> None:
    resolver = FieldResolver({})
    for component in resolver.get_objects(new_doc, "components[|]", {}):
        if "type" in component:
            continue
        cpes = resolver.get_objects(
            component, "?.evidence.identity[field=cpe]concludedValue"
        )
        if cpes:
            component["type"] = "operating-system"
        else:
            # Some reasonable fallback
            component["type"] = "data"


def try_to_restore_org_urls(_, new_doc: dict[str, Any]) -> None:
    main_supp = new_doc.get("metadata", {}).get("supplier", {})
    main_supp_name = main_supp.get("name")
    main_supp_url = main_supp.get("url")
    if not main_supp_name or not main_supp_url:
        return
    for component in new_doc.get("components", []):
        supp = component.get("supplier")
        if supp and supp.get("name") == main_supp_name:
            supp["url"] = main_supp_url


def clone_main_component(_, new_doc: dict[str, Any]) -> None:
    resolver = FieldResolver({})
    main_bom_ref = next(
        iter(resolver.get_objects(new_doc, "metadata.component.bom-ref")), None
    )
    if not main_bom_ref:
        return
    main_component = next(
        iter(resolver.get_objects(new_doc, f"components[bom-ref={main_bom_ref}]")), None
    )
    if main_component:
        new_doc["metadata"]["component"].update(main_component)
