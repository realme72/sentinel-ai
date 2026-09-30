"""Generate a synthetic asset fleet plus a real CycloneDX SBOM per host.

Deterministic: the same seed always produces the same fleet, so a regression in
risk scoring or retrieval is never confounded by the fleet changing underneath
it.
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sentinel.ingest.catalog import (
    MAVEN,
    NPM,
    OS_PROFILES,
    OWNER_TEAMS,
    PYPI,
    ROLE_STACKS,
)

ROLES = ["web", "api", "worker", "data", "edge", "db", "cache", "bastion"]
ENVIRONMENTS = [("prod", 0.40), ("staging", 0.25), ("dev", 0.35)]
OS_WEIGHTS = [("debian", 0.55), ("rhel", 0.30), ("alpine", 0.15)]

# Roles that plausibly sit at the edge. Used to make `internet_facing`
# correlate with role instead of being uniform noise -- otherwise the exposure
# component of the risk score carries no real signal.
EDGE_ROLES = {"edge", "web"}


def _weighted(rng: random.Random, pairs: list[tuple[str, float]]) -> str:
    r, acc = rng.random(), 0.0
    for name, w in pairs:
        acc += w
        if r <= acc:
            return name
    return pairs[-1][0]


def generate_assets(count: int = 500, seed: int = 20260930) -> list[dict]:
    rng = random.Random(seed)
    assets: list[dict] = []
    for i in range(1, count + 1):
        role = rng.choice(ROLES)
        env = _weighted(rng, ENVIRONMENTS)
        os_family = _weighted(rng, OS_WEIGHTS)
        team, email = rng.choice(OWNER_TEAMS)

        if role in EDGE_ROLES:
            internet_facing = rng.random() < (0.75 if env == "prod" else 0.35)
        else:
            internet_facing = rng.random() < 0.04

        # Criticality skews high in prod, low in dev.
        base = {"prod": 4, "staging": 3, "dev": 2}[env]
        criticality = max(1, min(5, base + rng.choice([-1, 0, 0, 1])))

        if role in {"db", "data"}:
            data_class = rng.choice(["restricted", "confidential", "confidential"])
        elif env == "prod":
            data_class = rng.choice(["confidential", "internal", "internal"])
        else:
            data_class = rng.choice(["internal", "internal", "public"])

        assets.append(
            {
                "hostname": f"{role}-{env[:4]}-{i:03d}",
                "ip_address": (
                    f"10.{rng.randint(0, 40)}.{rng.randint(0, 255)}"
                    f".{rng.randint(1, 254)}"
                ),
                "os_family": os_family,
                "os_version": OS_PROFILES[os_family]["os_version"],
                "environment": env,
                "business_criticality": criticality,
                "internet_facing": internet_facing,
                "data_classification": data_class,
                "owner_team": team,
                "owner_email": email,
                "tags": {
                    "role": role,
                    "region": rng.choice(["ap-south-1", "us-east-1", "eu-west-1"]),
                },
            }
        )
    return assets


def _purl_os(profile: dict, name: str, version: str) -> str:
    return (
        f"pkg:{profile['purl_type']}/{profile['namespace']}/{name}@{version}"
        f"?arch=amd64&distro={profile['distro']}"
    )


def build_sbom(asset: dict, seed: int = 20260930) -> dict:
    """CycloneDX 1.5 SBOM for one host.

    Package selection is seeded off the hostname so a host's inventory is
    stable across regenerations -- findings must not churn between runs.
    """
    rng = random.Random(f"{seed}:{asset['hostname']}")
    profile = OS_PROFILES[asset["os_family"]]
    role = asset["tags"]["role"]

    components: list[dict] = []

    # Every host carries most of its OS packages.
    for name, version in profile["packages"]:
        if rng.random() < 0.85:
            components.append(
                {
                    "type": "library",
                    "bom-ref": f"{name}@{version}",
                    "name": name,
                    "version": version,
                    "purl": _purl_os(profile, name, version),
                }
            )

    for stack in ROLE_STACKS.get(role, []):
        if stack == "npm":
            for name, version in rng.sample(NPM, k=rng.randint(4, len(NPM))):
                components.append({
                    "type": "library", "bom-ref": f"npm:{name}@{version}",
                    "name": name, "version": version,
                    "purl": f"pkg:npm/{name}@{version}",
                })
        elif stack == "pypi":
            for name, version in rng.sample(PYPI, k=rng.randint(4, len(PYPI))):
                components.append({
                    "type": "library", "bom-ref": f"pypi:{name}@{version}",
                    "name": name, "version": version,
                    "purl": f"pkg:pypi/{name}@{version}",
                })
        elif stack == "maven":
            for group, artifact, version in rng.sample(MAVEN, k=rng.randint(3, len(MAVEN))):
                components.append({
                    "type": "library", "bom-ref": f"maven:{group}:{artifact}@{version}",
                    "group": group, "name": artifact, "version": version,
                    "purl": f"pkg:maven/{group}/{artifact}@{version}",
                })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_DNS, asset['hostname'])}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "operating-system",
                "bom-ref": asset["hostname"],
                "name": profile["namespace"],
                "version": profile["os_version"],
            },
        },
        "components": components,
    }


def write_fleet(out_dir: Path, count: int = 500, seed: int = 20260930) -> list[dict]:
    """Write one SBOM per host and return the asset records."""
    out_dir.mkdir(parents=True, exist_ok=True)
    assets = generate_assets(count, seed)
    for asset in assets:
        sbom = build_sbom(asset, seed)
        (out_dir / f"{asset['hostname']}.cdx.json").write_text(json.dumps(sbom, indent=1))
    return assets
