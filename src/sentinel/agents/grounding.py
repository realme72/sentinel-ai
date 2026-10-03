"""The grounding gate: a non-LLM check that every identifier in a generated
plan actually appears in the retrieved context.

This is deliberately not a prompt. "Only use information from the provided
context" is a *request* -- models mostly comply, and the failure mode when
they don't is a confident, well-formatted ticket telling an engineer to
install a package version that does not fix the vulnerability, or does not
exist. A verbatim check is a *guarantee*: a plan cannot pass unless the exact
string is physically present in a document retrieved from NVD, CISA or Trivy.

Same wall as the risk engine: the model proposes, deterministic code disposes.
Plans that fail are stored with grounding_passed = false and never reach a
ticket.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Version-like tokens: at least three dot-separated segments (2.17.1), or a
# distro-style release suffix (1.1.1k-1, 3.0.1-23.el9, 1.1.1k-r0), optionally
# epoch-prefixed (1:1.2.11.dfsg-2).
#
# The >=3-segment requirement is what keeps CVSS scores out: "CVSS 10.0" and
# "severity 7.5" are two segments and would otherwise be checked as versions.
#
# Guards, each earned by a case that broke:
#   HEAD allows a preceding '-' so `openssl-1.1.1w` yields 1.1.1w; a missed
#        version is a fabricated version that slips through.
#   TAIL allows a trailing '.' (sentence end) but not '.<word>' (the version
#        continues). Without it "upgrade to 2.17.1." extracted "2.17.1." and
#        never matched context -- rejecting CORRECT plans. A gate with false
#        positives is one somebody eventually switches off, which is worse
#        than the fabrication it was built to catch.
_HEAD = r"(?<![\w.])"
_TAIL = r"(?![\w-])(?!\.\w)"

VERSION_RE = re.compile(
    rf"""
    {_HEAD}(?:\d+:)?                 # optional epoch, e.g. 1:
    \d+(?:\.\d+){{2,}}               # 1.2.3 -- three or more numeric segments
    (?:[a-z][\w+~]*)?               # 1.1.1k  (letter glued to the digits)
    (?:\.[a-z][\w+~]*)*            # .RELEASE, .dfsg
    (?:-[\w.+~]*[\w+~])?           # -1, -23.el9, -r0, -0+deb11u1
    {_TAIL}
    |
    {_HEAD}(?:\d+:)?\d+(?:\.\d+)+[a-z]*   # two-segment form, but only when
    -[\w.+~]*[\w+~]{_TAIL}         # it carries a release suffix -- a CVSS
                                    # score never does
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Commands a plan must not invent. These are not "dangerous" in the abstract --
# they are operations that a remediation ticket has no business instructing,
# and which no retrieved advisory would ever contain.
FORBIDDEN_RE = re.compile(
    r"\b(rm\s+-rf\s+/|mkfs|dd\s+if=/dev/zero|:\(\)\{|curl[^|\n]*\|\s*(ba)?sh)",
    re.IGNORECASE,
)


@dataclass
class GroundingReport:
    passed: bool
    missing_required: list[str] = field(default_factory=list)
    checked_cves: list[str] = field(default_factory=list)
    checked_versions: list[str] = field(default_factory=list)
    ungrounded_cves: list[str] = field(default_factory=list)
    ungrounded_versions: list[str] = field(default_factory=list)
    forbidden_matches: list[str] = field(default_factory=list)
    context_chars: int = 0

    def as_dict(self) -> dict:
        return {
            "passed": self.passed,
            "checked_cves": self.checked_cves,
            "checked_versions": self.checked_versions,
            "ungrounded_cves": self.ungrounded_cves,
            "ungrounded_versions": self.ungrounded_versions,
            "forbidden_matches": self.forbidden_matches,
            "missing_required": self.missing_required,
            "context_chars": self.context_chars,
        }

    def reason(self) -> str:
        if self.passed:
            return "grounded"
        bits = []
        if self.ungrounded_cves:
            bits.append(f"CVE ids not in context: {', '.join(self.ungrounded_cves)}")
        if self.ungrounded_versions:
            bits.append(f"versions not in context: {', '.join(self.ungrounded_versions)}")
        if self.forbidden_matches:
            bits.append(f"forbidden commands: {', '.join(self.forbidden_matches)}")
        if self.missing_required:
            bits.append(f"never names the target version: "
                        f"{', '.join(self.missing_required)}")
        return "; ".join(bits)


def _normalise(text: str) -> str:
    """Collapse whitespace so a version split across a line break still matches."""
    return re.sub(r"\s+", " ", text)


def extract_cves(text: str) -> list[str]:
    return sorted({m.upper() for m in CVE_RE.findall(text)})


# File extensions that look exactly like a dotted version qualifier. Without
# this, `log4j-core-2.15.0.jar` yields the "version" 2.15.0.jar, which is not
# in any advisory, so a CORRECT plan naming a jar filename gets rejected.
# Observed on the first live Groq call.
_FILE_EXTENSIONS = frozenset({
    "jar", "war", "ear", "zip", "tar", "gz", "tgz", "bz2", "xz", "zst",
    "whl", "egg", "deb", "rpm", "apk", "so", "dll", "dylib", "exe", "msi",
    "jsonc", "json", "yaml", "yml", "xml", "txt", "md", "sh", "py", "js",
    "pom", "sig", "asc", "sha256", "sha512",
    # Backup suffixes appear in generated rollback commands.
    "bak", "old", "orig", "save", "tmp", "backup",
})


def _looks_like_ipv4(token: str) -> bool:
    """Reject dotted quads that are addresses rather than versions.

    `127.0.0.1` matches the version pattern (four numeric segments) and was
    extracted as a version, rejecting a correct plan that mentioned a loopback
    address.

    Deliberately narrow: only loopback, the private ranges, the unspecified
    address and netmasks. A blanket "four numeric segments is an IP" rule also
    swallowed `2.17.1.2`, which is a real version. These ranges are what
    actually appears in remediation text ("bind to 127.0.0.1", "allow
    10.0.0.0/8"), and a public address in a patching instruction is rare
    enough that treating it as a version is the safer error.
    """
    parts = token.split(".")
    if len(parts) != 4 or not all(p.isdigit() and int(p) <= 255 for p in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    return (
        a == 127                          # loopback
        or a == 10                        # private /8
        or (a == 172 and 16 <= b <= 31)   # private /12
        or (a == 192 and b == 168)        # private /16
        or (a == 169 and b == 254)        # link-local
        or a == 0                         # unspecified
        or a == 255                       # broadcast / netmask
    )


def _strip_file_extension(token: str) -> str:
    """Drop a trailing file extension from a version-like token.

    Applied repeatedly so `log4j-core-2.15.0.tar.gz` reduces to 2.15.0. A
    genuine qualifier such as `.RELEASE` is not in the extension set and
    survives.
    """
    changed = True
    while changed and "." in token:
        changed = False
        head, _, tail = token.rpartition(".")
        if head and tail.lower() in _FILE_EXTENSIONS:
            token = head
            changed = True
    return token


def extract_versions(text: str) -> list[str]:
    # CVE ids contain digit groups that look version-ish; remove them first.
    without_cves = CVE_RE.sub(" ", text)
    found = set()
    for match in VERSION_RE.findall(without_cves):
        token = _strip_file_extension(match.strip())
        if _looks_like_ipv4(token):
            continue
        # A bare major.minor left after stripping (e.g. "1.2" from "1.2.zip")
        # is not a version this gate should assert on.
        if token and token.count(".") >= 2 or (token and "-" in token):
            found.add(token)
    return sorted(found)


def check_grounding(
    generated: str,
    context_chunks: list[str],
    *,
    required_versions: list[str] | None = None,
) -> GroundingReport:
    """Verify every CVE id and version string in `generated` appears verbatim
    in at least one retrieved chunk.

    `required_versions` closes a gap the provenance check alone leaves open.
    Asked for curl 7.74.0-1.3+deb11u14, a model answered with
    7.74.0-1.3+deb11u10 -- a real version, present in the corpus, but the fix
    for a different CVE. Provenance was satisfied; selection was not. When the
    caller knows the target, requiring the plan to name it turns that from an
    unverifiable judgement into a string comparison.
    """
    context = _normalise(" ".join(context_chunks))
    context_upper = context.upper()
    gen = _normalise(generated)

    cves = extract_cves(gen)
    versions = extract_versions(gen)

    ungrounded_cves = [c for c in cves if c not in context_upper]
    ungrounded_versions = [v for v in versions if v not in context]
    forbidden = sorted({m[0] if isinstance(m, tuple) else m
                        for m in FORBIDDEN_RE.findall(gen)})

    missing_required = [
        v for v in (required_versions or []) if v and v not in gen
    ]

    return GroundingReport(
        passed=not (ungrounded_cves or ungrounded_versions or forbidden
                    or missing_required),
        missing_required=missing_required,
        checked_cves=cves,
        checked_versions=versions,
        ungrounded_cves=ungrounded_cves,
        ungrounded_versions=ungrounded_versions,
        forbidden_matches=forbidden,
        context_chars=len(context),
    )
