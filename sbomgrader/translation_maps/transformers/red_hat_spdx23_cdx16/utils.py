SPDX_CDX_HASHES = {
    # Sources: https://spdx.github.io/spdx-spec/v2.3/package-information/
    # https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf
    ("SHA1", "SHA-1"),
    ("SHA224", "SHA-224"),  # This does not really exist in CDX
    ("SHA256", "SHA-256"),
    ("SHA384", "SHA-384"),
    ("SHA512", "SHA-512"),
    ("SHA3-256", "SHA-3"),
    ("SHA3-384", "SHA-3"),
    ("SHA3-512", "SHA-3"),
    ("BLAKE2b-256", "BLAKE2b"),
    ("BLAKE2b-384", "BLAKE2b"),
    ("BLAKE2b-512", "BLAKE2b"),
    ("BLAKE3", "BLAKE3"),
    ("MD2", "MD2"),  # Not
    ("MD4", "MD4"),  # supported
    ("MD5", "MD5"),  # in
    ("MD6", "MD6"),  # CDX
    ("ADLER32", "ADLER32"),  # either
}
SPDX_CDX_RELATIONSHIPS = {("PACKAGE_OF", "provides"), ("CONTAINS", "")}
