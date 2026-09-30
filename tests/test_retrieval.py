"""Retrieval logic that can be tested without a database."""

import pytest

from sentinel.rag.chunk import MAX_CHARS, chunk_cve
from sentinel.rag.hybrid import extract_cve_ids, reciprocal_rank_fusion
from sentinel.rag.store import SearchHit


def hit(chunk_id: int, backend: str = "x") -> SearchHit:
    return SearchHit(chunk_id=chunk_id, score=0.0, content=f"c{chunk_id}",
                     cve_ids=[], source="nvd", backend=backend)


# --- CVE extraction (drives the metadata prefilter) ------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("CVE-2021-44228", ["CVE-2021-44228"]),
        ("how do I fix cve-2021-44228 on prod", ["CVE-2021-44228"]),
        ("CVE-2021-44228 and CVE-2021-45046", ["CVE-2021-44228", "CVE-2021-45046"]),
        ("no identifiers here", []),
        # Five-digit sequence numbers are valid and increasingly common.
        ("CVE-2025-124513", ["CVE-2025-124513"]),
    ],
)
def test_extract_cve_ids(text, expected):
    assert extract_cve_ids(text) == expected


# --- Reciprocal Rank Fusion ------------------------------------------------


def test_rrf_rewards_agreement_between_branches():
    """A document both retrievers return must beat one that only a single
    retriever loves, even when the singleton is that branch's rank 1.

    This is the property the whole fusion rests on, and it is why the
    prefiltered Log4Shell query scored 0.033 against 0.026 unfiltered: both
    branches agreed.
    """
    # Doc 1 is rank 2 in both lists; docs 3 and 4 are rank 1 in one list each.
    fused = reciprocal_rank_fusion(
        {"lexical": [hit(3), hit(1)], "dense": [hit(4), hit(1)]}, k=3
    )
    assert fused[0].chunk_id == 1, "agreed-on doc should beat two rank-1 singletons"
    assert fused[0].lexical_rank == 2 and fused[0].dense_rank == 2
    # 2/(60+2) vs 1/(60+1)
    assert fused[0].rrf_score > fused[1].rrf_score


def test_rrf_uses_ranks_not_scores():
    """ts_rank_cd is unbounded and cosine is 0-1; fusion must ignore both."""
    huge = SearchHit(chunk_id=9, score=999.0, content="c9", cve_ids=[],
                     source="nvd", backend="x")
    tiny = SearchHit(chunk_id=8, score=0.001, content="c8", cve_ids=[],
                     source="nvd", backend="x")
    fused = reciprocal_rank_fusion({"lexical": [tiny, huge]}, k=2)
    assert fused[0].chunk_id == 8, "rank 1 wins regardless of raw score magnitude"


def test_rrf_records_which_branch_found_each_hit():
    fused = reciprocal_rank_fusion(
        {"lexical": [hit(1)], "dense": [hit(2), hit(1)]}, k=2
    )
    by_id = {f.chunk_id: f for f in fused}
    assert by_id[1].lexical_rank == 1 and by_id[1].dense_rank == 2
    assert by_id[2].lexical_rank is None and by_id[2].dense_rank == 1


def test_rrf_k_damps_the_top_rank_advantage():
    """With k=60, rank 1 vs rank 2 is a small gap -- that's deliberate, it
    stops one confident branch from dominating the other."""
    fused = reciprocal_rank_fusion({"lexical": [hit(1), hit(2)]}, k=2, rrf_k=60)
    gap = fused[0].rrf_score - fused[1].rrf_score
    assert gap < 0.001


# --- Chunking --------------------------------------------------------------


def _chunks(**over):
    base = dict(
        cve_id="CVE-2021-44228", description="Apache Log4j2 JNDI lookup flaw.",
        cvss_severity="CRITICAL", cvss_score=10.0, cwe_ids=["CWE-502"],
        kev_listed=True, kev_ransomware=True, kev_action="Apply updates.",
        epss_score=0.99999,
        fixes=[("log4j-core", "2.14.1", "2.17.1")],
    )
    base.update(over)
    return chunk_cve(**base)


def test_every_chunk_names_its_cve():
    """The lexical index is the half that handles exact identifiers, so the
    identifier has to appear in each chunk's own text."""
    for c in _chunks():
        assert "CVE-2021-44228" in c.content
        assert c.cve_ids == ["CVE-2021-44228"]


def test_fix_version_stays_with_its_package():
    """The single most valuable sentence in an advisory is the one naming the
    fixed version; splitting it from the package makes the chunk useless."""
    remediation = [c for c in _chunks() if "Remediation for package" in c.content]
    assert len(remediation) == 1
    assert "log4j-core" in remediation[0].content
    assert "2.17.1" in remediation[0].content


def test_missing_fix_is_stated_explicitly_not_omitted():
    """A planner must be able to tell 'no patch exists' from 'we don't know'."""
    chunks = _chunks(fixes=[("openssl", "1.1.1k", None)])
    body = " ".join(c.content for c in chunks)
    assert "No fixed version" in body
    assert "compensating control" in body


def test_chunks_respect_the_model_context_limit():
    chunks = _chunks(description="x" * 6000)
    assert len(chunks) > 1
    for c in chunks:
        # header + body; allow the header's overhead above the body budget
        assert len(c.content) <= MAX_CHARS + 120


def test_each_package_gets_its_own_chunk():
    """Mixing packages into one chunk dilutes the vector for all of them."""
    chunks = _chunks(fixes=[("log4j-core", "2.14.1", "2.17.1"),
                            ("jackson-databind", "2.9.8", "2.9.10")])
    remediation = [c for c in chunks if "Remediation for package" in c.content]
    assert len(remediation) == 2
