"""The deterministic plan-quality rubric.

This is the half of evaluation that cannot flatter the model: no LLM judge, no
shared failure modes, no token cost. It measures what the grounding gate
structurally cannot -- whether a plan that invents nothing is also worth
acting on.
"""

import pytest

from sentinel.evals.metrics import aggregate, extract_commands, score_plan

GOOD = """Upgrade openssl to 1.1.1w-0+deb11u8 to remediate CVE-2021-3711.

**Commands**
```bash
apt-get update
apt-get install -y openssl=1.1.1w-0+deb11u8
systemctl restart nginx
```

**Rollback**
apt-get install -y openssl=1.1.1k-1
"""


def s(md, *, grounded=True, target="1.1.1w-0+deb11u8", os_family="debian"):
    return score_plan(md, grounded=grounded, target_version=target,
                      os_family=os_family)


def test_a_complete_plan_scores_full_marks():
    r = s(GOOD)
    assert r.score == 1.0
    assert r.actionable
    assert r.failures() == []


def test_grounded_but_vague_is_caught():
    """The exact gap the grounding gate leaves: "apply vendor updates" invents
    nothing, so the gate passes it, and it is useless."""
    r = s("Apply vendor updates and restart the service.\n**Rollback**\nRevert.",
          grounded=True)
    assert not r.actionable
    assert "not_vague" in r.failures()
    assert "names_target" in r.failures()


@pytest.mark.parametrize("phrase", [
    "Apply vendor updates.",
    "Upgrade to the latest version.",
    "Follow vendor instructions.",
    "Consult the documentation for details.",
])
def test_vague_phrasings(phrase):
    assert not s(phrase).not_vague


def test_placeholders_are_caught():
    """Observed live: an otherwise correct Log4Shell plan said
    `cp /path/to/log4j-core-2.14.1.jar /path/to/backup/` -- grounded, version
    correct, and not runnable by anyone."""
    md = """Upgrade log4j-core.
```bash
cp /path/to/log4j-core-2.14.1.jar /path/to/backup/
```
**Rollback** restore
"""
    r = s(md, target="2.15.0")
    assert not r.no_placeholders
    assert not r.actionable
    assert "/path/to/" in str(r.detail["placeholders"])


@pytest.mark.parametrize("placeholder", [
    "/path/to/jar", "<your-service-name>", "restart your-service",
    "https://example.com/pkg", "TODO: confirm version",
])
def test_placeholder_forms(placeholder):
    assert not s(f"Run: {placeholder}").no_placeholders


def test_wrong_packaging_tool_is_not_actionable():
    """Telling a Debian host to run `apk add` is not a small flaw -- the plan
    cannot be executed at all."""
    md = """Upgrade openssl to 1.1.1w-0+deb11u8.
```bash
apk add --upgrade openssl=1.1.1w-0+deb11u8
```
**Rollback** reinstall previous
"""
    r = s(md)
    assert not r.commands_match_os
    assert r.detail["wrong_os_tooling"] == ["alpine"]
    assert not r.actionable


@pytest.mark.parametrize("os_family,cmd", [
    ("debian", "apt-get install -y openssl=1.1.1w-0+deb11u8"),
    ("rhel", "dnf install -y openssl-1.1.1w"),
    ("alpine", "apk add --upgrade openssl=1.1.1w-0+deb11u8"),
])
def test_each_packaging_system_is_recognised(os_family, cmd):
    md = f"Upgrade to 1.1.1w-0+deb11u8.\n```bash\n{cmd}\n```\n**Rollback** x"
    assert s(md, os_family=os_family).commands_match_os


def test_ecosystem_tooling_counts_for_any_os():
    """mvn and pip are OS-independent, so a Java plan on Debian is fine
    without apt."""
    md = ("Upgrade to 2.17.1.\n```bash\n"
          "mvn versions:use-dep-version -DdepVersion=2.17.1\n```\n**Rollback** x")
    assert s(md, target="2.17.1").commands_match_os


def test_ungrounded_plan_is_never_actionable():
    assert not s(GOOD, grounded=False).actionable


def test_missing_target_version_is_caught():
    assert not s(GOOD, target="9.9.9").names_target


def test_extract_commands_reads_fenced_blocks():
    assert extract_commands(GOOD) == [
        "apt-get update",
        "apt-get install -y openssl=1.1.1w-0+deb11u8",
        "systemctl restart nginx",
    ]


def test_aggregate_reports_per_check_rates():
    out = aggregate([s(GOOD), s("Apply vendor updates.")])
    assert out["plans"] == 2
    assert out["actionable_rate"] == 0.5
    assert out["grounded_rate"] == 1.0
    assert out["not_vague_rate"] == 0.5


def test_aggregate_handles_no_plans():
    assert aggregate([])["plans"] == 0
