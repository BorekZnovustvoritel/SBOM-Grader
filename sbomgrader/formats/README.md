# Formats

These files describe SBOM formats according to
standards. The purpose of this directory is to create
enums to be used later.

## Format

A yaml file is expected. Only the field `formats`
is supported and required at the same time. This field
contains a list of items.

The items in the list have the following properties:

### name

Required field, specifies the enum name.

### value

Required field, specifies the implementation abbreviation.

### expectedStructure

Required field, specifies fields in the SBOM which indicate
that the SBOM is in this standard.

### fallback

Optional field, specifies which format will serve as a fallback
if this exact format has no implementation.

For example, if a translation map exists for SPDX v2.3, and we
provide SBOM of format SPDX v2.2, we should define that these
formats can fall back to each other (mutually).
