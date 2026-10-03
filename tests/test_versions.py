"""Choosing the right fixed version from a scanner's multi-branch candidate list.

This had a real bug: taking the first entry told hosts on log4j 2.14.1 to
"upgrade" to 2.12.3 -- an older release on a different branch that leaves them
exploitable. 4,668 findings in the fleet were affected.
"""

import pytest

from sentinel.ingest.versions import choose_fixed_version, compare, parse_candidates


@pytest.mark.parametrize(
    "raw,installed,expected",
    [
        # The three real Log4j cases from this fleet.
        ("2.15.0, 2.3.1, 2.12.2", "2.14.1", "2.15.0"),
        ("2.16.0, 2.12.2", "2.14.1", "2.16.0"),
        # The bug: 2.12.3 is listed first but is a DOWNGRADE from 2.14.1.
        ("2.12.3, 2.17.0, 2.3.1", "2.14.1", "2.17.0"),
        # Distro formats.
        ("1.1.1l", "1.1.1k", "1.1.1l"),
        ("1.33.1-r6", "1.33.1-r3", "1.33.1-r6"),
        ("2.34-30.el9", "2.34-28.el9", "2.34-30.el9"),
        # Double-digit minor must beat single-digit: 2.9.10 > 2.9.8.
        ("2.9.10, 2.8.11.5", "2.9.8", "2.9.10"),
    ],
)
def test_chooses_the_lowest_candidate_above_installed(raw, installed, expected):
    assert choose_fixed_version(raw, installed) == expected


def test_never_recommends_a_downgrade_when_an_upgrade_exists():
    """The property that matters, stated directly."""
    chosen = choose_fixed_version("2.12.3, 2.17.0, 2.3.1", "2.14.1")
    assert compare(chosen, "2.14.1") > 0


def test_lexical_comparison_does_not_decide_numeric_order():
    """String comparison would put 2.9.10 below 2.9.8."""
    assert compare("2.9.10", "2.9.8") > 0
    assert compare("1.33.1-r10", "1.33.1-r9") > 0


def test_handles_an_epoch_prefix():
    assert compare("1:1.2.11", "1.2.12") > 0, "a higher epoch always wins"


def test_empty_and_missing_inputs_are_safe():
    assert choose_fixed_version(None, "1.0.0") is None
    assert choose_fixed_version("", "1.0.0") is None
    assert parse_candidates(None) == []
    # No installed version to compare against: take the first offered.
    assert choose_fixed_version("2.1.0, 1.0.0", None) == "2.1.0"


def test_unparseable_versions_degrade_rather_than_raise():
    """An ingest of 100,000 findings must not die on one odd version string."""
    assert choose_fixed_version("not-a-version", "1.0.0") is not None


def test_all_candidates_below_installed_still_returns_something():
    """The scanner and the installed version disagree about ordering; return
    the highest available rather than nothing, and let the corpus show it."""
    chosen = choose_fixed_version("1.0.0, 1.2.0", "9.9.9")
    assert chosen == "1.2.0"


# --- rate limiter ----------------------------------------------------------


def test_limiter_paces_to_the_token_budget_not_the_request_count():
    """8,000 tokens/min at ~1,840 tokens per call is four calls per minute --
    the token cap binds long before the 28 requests/min one."""
    import time

    from sentinel.util.ratelimit import SyncRollingWindowLimiter

    lim = SyncRollingWindowLimiter(requests=28, window=0.6, tokens=8000)
    immediate = 0
    for _ in range(4):
        if lim.acquire(1650) == 0.0:
            immediate += 1
        lim.record_actual(1839)
    assert immediate == 4, "four calls must fit inside one window"

    t0 = time.perf_counter()
    waited = lim.acquire(1650)
    assert waited > 0, "the fifth must wait"
    assert time.perf_counter() - t0 < 1.5, "and only until the window clears"


def test_limiter_ceiling_can_be_raised_from_a_response_header():
    """The planner learns the real quota from x-ratelimit-limit-tokens rather
    than trusting a hardcoded guess."""
    from sentinel.util.ratelimit import SyncRollingWindowLimiter

    lim = SyncRollingWindowLimiter(requests=28, window=60.0, tokens=2000)
    lim.acquire(1650)
    lim.record_actual(1839)
    lim.tokens = 8000                      # what _observe_limits does
    assert lim.acquire(1650) == 0.0, "a raised ceiling must free capacity"
