"""Package catalog of real, genuinely vulnerable versions.

The fleet is synthetic; the vulnerabilities are not. Every version below is a
real release that Trivy's database has real CVEs for. That matters: fabricated
findings would let every downstream stage (enrichment, scoring, retrieval,
grounding) pass tests against data that could never occur in production.

Versions are pinned deliberately old. Do not "update" them.
"""

from __future__ import annotations

# --- language ecosystems (no distro context needed for matching) -----------

NPM = [
    ("lodash", "4.17.15"),
    ("minimist", "1.2.0"),
    ("axios", "0.21.0"),
    ("node-fetch", "2.6.0"),
    ("ejs", "3.1.6"),
    ("semver", "7.3.4"),
    ("ws", "7.4.0"),
    ("tar", "6.1.0"),
    ("express", "4.16.0"),
    ("handlebars", "4.7.6"),
]

PYPI = [
    ("django", "3.2.4"),
    ("requests", "2.19.1"),
    ("urllib3", "1.25.8"),
    ("pyyaml", "5.3.1"),
    ("jinja2", "2.11.2"),
    ("cryptography", "3.3.1"),
    ("pillow", "8.1.0"),
    ("flask", "1.1.1"),
    ("werkzeug", "1.0.1"),
    ("lxml", "4.6.2"),
]

MAVEN = [
    ("org.apache.logging.log4j", "log4j-core", "2.14.1"),      # Log4Shell
    ("com.fasterxml.jackson.core", "jackson-databind", "2.9.8"),
    ("org.springframework", "spring-core", "5.2.9.RELEASE"),
    ("org.apache.tomcat.embed", "tomcat-embed-core", "9.0.30"),
    ("commons-collections", "commons-collections", "3.2.1"),
    ("org.yaml", "snakeyaml", "1.27"),
]

# --- OS packages (purl needs the distro qualifier to match Trivy's DB) -----

DEB_BULLSEYE = [
    ("openssl", "1.1.1k-1"),
    ("curl", "7.74.0-1"),
    ("zlib1g", "1:1.2.11.dfsg-2"),
    ("libc6", "2.31-13"),
    ("openssh-server", "1:8.4p1-5"),
    ("sudo", "1.9.5p2-3"),
    ("bash", "5.1-2"),
    ("nginx", "1.18.0-6.1"),
    ("libxml2", "2.9.10+dfsg-6.7"),
    ("perl", "5.32.1-4"),
]

RPM_EL9 = [
    ("openssl", "3.0.1-23.el9"),
    ("curl", "7.76.1-14.el9"),
    ("glibc", "2.34-28.el9"),
    ("openssh-server", "8.7p1-8.el9"),
    ("vim-minimal", "8.2.2637-16.el9"),
    ("python3", "3.9.10-2.el9"),
]

APK_314 = [
    ("openssl", "1.1.1k-r0"),
    ("busybox", "1.33.1-r3"),
    ("musl", "1.2.2-r3"),
    ("zlib", "1.2.11-r3"),
    ("libcrypto1.1", "1.1.1k-r0"),
]

OS_PROFILES = {
    "debian": {"packages": DEB_BULLSEYE, "purl_type": "deb", "namespace": "debian",
               "distro": "debian-11", "os_version": "11"},
    "rhel":   {"packages": RPM_EL9, "purl_type": "rpm", "namespace": "redhat",
               "distro": "rhel-9", "os_version": "9"},
    "alpine": {"packages": APK_314, "purl_type": "apk", "namespace": "alpine",
               "distro": "alpine-3.14", "os_version": "3.14"},
}

# Which language stacks a host role carries on top of its OS packages.
ROLE_STACKS = {
    "web":     ["npm"],
    "api":     ["maven"],
    "worker":  ["pypi"],
    "data":    ["pypi"],
    "edge":    [],
    "db":      [],
    "cache":   [],
    "bastion": [],
}

OWNER_TEAMS = [
    ("platform", "platform-eng@example.com"),
    ("payments", "payments-team@example.com"),
    ("identity", "identity@example.com"),
    ("data-eng", "data-engineering@example.com"),
    ("web", "web-team@example.com"),
    ("mobile-backend", "mobile-be@example.com"),
    ("infra", "infra-ops@example.com"),
]
