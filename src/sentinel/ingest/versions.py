"""Choosing the right fixed version from a scanner's candidate list.

Trivy reports fixes across every maintained release branch, not just the one
you are on:

    CVE-2021-44228  installed 2.14.1  ->  "2.15.0, 2.3.1, 2.12.2"
    CVE-2021-45105  installed 2.14.1  ->  "2.12.3, 2.17.0, 2.3.1"

Taking the first entry gets CVE-2021-45105 badly wrong: 2.12.3 is a fix on the
2.12 branch, and instructing someone running 2.14.1 to install it is a
*downgrade* that leaves them exploitable. The right choice is the lowest
candidate strictly greater than what is installed -- the smallest step that
actually lands on a fixed release.
"""

from __future__ import annotations

import re

# Strip packaging decoration so semver-ish comparison can work across
# ecosystems: epochs (1:), distro releases (-23.el9, -r0, -1).
_EPOCH_RE = re.compile(r"^(\d+):")
_SEGMENT_RE = re.compile(r"\d+|[a-z]+", re.IGNORECASE)


def version_key(version: str) -> tuple:
    """A comparable key for a version string.

    Deliberately simple and total rather than ecosystem-perfect: it must never
    raise, because an unparseable version must degrade to "cannot compare",
    not crash an ingest of 100,000 findings. Numeric segments compare
    numerically, alphabetic ones lexically, and numbers sort after letters at
    the same position so 1.1.1k < 1.1.1 is avoided.
    """
    epoch_match = _EPOCH_RE.match(version)
    epoch = int(epoch_match.group(1)) if epoch_match else 0
    rest = version[epoch_match.end():] if epoch_match else version

    key: list[tuple[int, object]] = [(0, epoch)]
    for seg in _SEGMENT_RE.findall(rest):
        if seg.isdigit():
            key.append((1, int(seg)))
        else:
            key.append((0, seg.lower()))
    return tuple(key)


def compare(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


def parse_candidates(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def choose_fixed_version(raw: str | None, installed: str | None) -> str | None:
    """Pick the lowest candidate strictly greater than `installed`.

    Falls back to the lowest candidate overall when nothing is greater (which
    means the scanner and the installed version disagree about ordering), and
    to the first candidate when comparison is impossible.
    """
    candidates = parse_candidates(raw)
    if not candidates:
        return None
    if not installed:
        return candidates[0]

    try:
        installed_key = version_key(installed)
        greater = [c for c in candidates if version_key(c) > installed_key]
        if greater:
            return min(greater, key=version_key)
        # Nothing higher: the scanner's candidates are all on older branches.
        # Returning the max is the least-wrong answer and is still flagged by
        # being <= installed, which the corpus surfaces rather than hides.
        return max(candidates, key=version_key)
    except (TypeError, ValueError):
        return candidates[0]
