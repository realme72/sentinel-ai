"""Chunking for security advisories.

Generic recursive splitters cut on paragraph and sentence boundaries, which is
wrong here in a specific way: the most valuable sentence in an advisory is
usually the one naming the fixed version ("upgrade to 2.17.1"), and a split
that separates it from the package it refers to produces a chunk that is
retrievable but useless.

So chunks are built from semantic fields rather than by slicing raw text, and
every chunk carries the CVE id and affected packages in its own text. That
costs a little redundancy and buys two things: a chunk is self-contained when
the model reads it, and the lexical index has the identifier in every chunk
that mentions the vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass

# bge-small truncates at 512 tokens. Roughly 4 chars/token for English prose,
# so ~1400 chars leaves comfortable headroom for the header we prepend.
MAX_CHARS = 1400
OVERLAP_CHARS = 150


@dataclass(frozen=True)
class Chunk:
    index: int
    content: str
    cve_ids: list[str]
    source: str
    os_family: str | None = None


def _split_long(text: str, max_chars: int = MAX_CHARS,
                overlap: int = OVERLAP_CHARS) -> list[str]:
    """Split on sentence boundaries, only when a field genuinely exceeds the
    model's context. Overlap keeps a claim that straddles a boundary intact."""
    if len(text) <= max_chars:
        return [text]

    parts, start = [], 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        if end < len(text):
            # Prefer a sentence break, then any whitespace, then a hard cut.
            window = text[start:end]
            for sep in (". ", "\n", " "):
                cut = window.rfind(sep)
                if cut > max_chars * 0.5:
                    end = start + cut + len(sep)
                    break
        parts.append(text[start:end].strip())
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return [p for p in parts if p]


def chunk_cve(
    *,
    cve_id: str,
    description: str | None,
    cvss_severity: str | None,
    cvss_score: float | None,
    cwe_ids: list[str],
    kev_listed: bool,
    kev_ransomware: bool,
    kev_action: str | None,
    epss_score: float | None,
    fixes: list[tuple[str, str, str | None]],
) -> list[Chunk]:
    """Build self-contained chunks for one CVE.

    `fixes` is (package_name, installed_version, fixed_version) observed across
    the fleet -- the remediation facts, which is what a planner actually needs.
    """
    chunks: list[Chunk] = []
    # Repeated at the top of every chunk so each one stands alone and the
    # lexical index sees the identifier regardless of which chunk matches.
    header = f"{cve_id}"
    if cvss_severity:
        header += f" ({cvss_severity}"
        header += f", CVSS {cvss_score})" if cvss_score is not None else ")"

    def add(body: str, os_family: str | None = None) -> None:
        for part in _split_long(body):
            chunks.append(Chunk(
                index=len(chunks),
                content=f"{header}. {part}",
                cve_ids=[cve_id],
                source="nvd",
                os_family=os_family,
            ))

    if description:
        add(f"Description: {description}")

    signals = []
    if kev_listed:
        signals.append(
            "Listed in the CISA Known Exploited Vulnerabilities catalog: this "
            "vulnerability has been observed exploited in the wild."
        )
        if kev_ransomware:
            signals.append("Known to be used in ransomware campaigns.")
        if kev_action:
            signals.append(f"CISA required action: {kev_action}")
    if epss_score is not None:
        signals.append(
            f"EPSS exploit probability {epss_score:.5f} "
            f"({epss_score * 100:.2f}% chance of exploitation in the next 30 days)."
        )
    if cwe_ids:
        signals.append(f"Weakness classes: {', '.join(cwe_ids)}.")
    if signals:
        add("Exploitation and classification. " + " ".join(signals))

    # One chunk per package: a remediation query is about a package, and
    # mixing several into one chunk dilutes the vector for all of them.
    by_package: dict[str, set[tuple[str, str | None]]] = {}
    for pkg, installed, fixed in fixes:
        by_package.setdefault(pkg, set()).add((installed, fixed))
    for pkg, versions in sorted(by_package.items()):
        fixed_versions = sorted({f for _, f in versions if f})
        affected = sorted({i for i, _ in versions})
        body = f"Remediation for package {pkg}. Affected versions observed: {', '.join(affected)}."
        if fixed_versions:
            body += f" Fixed in version {', '.join(fixed_versions)}."
            body += f" Upgrade {pkg} to {fixed_versions[0]} or later to remediate {cve_id}."
        else:
            body += (
                f" No fixed version is currently published for {pkg}. "
                "Mitigation requires a compensating control rather than an upgrade."
            )
        add(body)

    return chunks
