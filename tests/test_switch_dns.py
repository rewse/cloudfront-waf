"""Tests for scripts/switch-dns.sh, run with --dry-run only."""

import json
import os
import subprocess
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "switch-dns.sh"
SUBDOMAINS = [
    "couchdb",
    "grafana",
    "hass",
    "litellm",
    "nas",
    "nvr",
    "teslamate",
    "zabbix",
]
ZONE_NAMES = {f"{name}.rewse.jp." for name in SUBDOMAINS} | {"www.rewse.jp."}


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "DISTRIBUTION": "d123.cloudfront.net"}
    return subprocess.run(
        [str(SCRIPT), *args], capture_output=True, text=True, env=env, check=False
    )


def _changes(mode: str) -> list[dict[str, Any]]:
    result = _run(mode, "--dry-run")
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["Changes"]


def _record_sets(mode: str) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (c["ResourceRecordSet"]["Name"], c["ResourceRecordSet"]["Type"]): c[
            "ResourceRecordSet"
        ]
        for c in _changes(mode)
    }


def test_cloudfront_batch_points_every_name_at_the_distribution() -> None:
    changes = _changes("cloudfront")

    assert len(changes) == 11
    assert {c["Action"] for c in changes} == {"UPSERT"}
    records = _record_sets("cloudfront")
    for name in ZONE_NAMES:
        record = records[(name, "CNAME")]
        assert record["TTL"] == 300
        assert record["ResourceRecords"] == [{"Value": "d123.cloudfront.net"}]
    for record_type in ("A", "AAAA"):
        assert records[("rewse.jp.", record_type)]["AliasTarget"] == {
            "DNSName": "d123.cloudfront.net",
            "EvaluateTargetHealth": False,
            "HostedZoneId": "Z2FDTNDATAQYW2",
        }


def test_origin_batch_restores_todays_records() -> None:
    changes = _changes("origin")

    assert len(changes) == 11
    assert {c["Action"] for c in changes} == {"UPSERT"}
    records = _record_sets("origin")
    for name in SUBDOMAINS:
        record = records[(f"{name}.rewse.jp.", "CNAME")]
        assert record["TTL"] == 300
        assert record["ResourceRecords"] == [{"Value": "fox.rewse.jp"}]
    www = records[("www.rewse.jp.", "CNAME")]
    assert www["TTL"] == 300
    assert www["ResourceRecords"] == [{"Value": "rewse.jp"}]
    for record_type, value in (
        ("A", "106.163.184.9"),
        ("AAAA", "240f:143:f60c:1:2ecf:67ff:fe0f:f65d"),
    ):
        record = records[("rewse.jp.", record_type)]
        assert record["TTL"] == 300
        assert record["ResourceRecords"] == [{"Value": value}]
        assert "AliasTarget" not in record


def test_unknown_mode_exits_with_usage() -> None:
    result = _run("foo")

    assert result.returncode == 2
    assert "usage" in result.stderr.lower()


def test_blog_and_rds_names_are_never_touched() -> None:
    forbidden = ("blog.", "rewse-my.", "rewse-pg.")
    for mode in ("cloudfront", "origin"):
        for change in _changes(mode):
            name = change["ResourceRecordSet"]["Name"]
            assert not name.startswith(forbidden)
            assert "-db." not in name


def _run_with_stub_aws(
    tmp_path: Path, distribution: str | None
) -> tuple[subprocess.CompletedProcess[str], str]:
    calls = tmp_path / "calls.txt"
    stub = tmp_path / "bin" / "aws"
    stub.parent.mkdir()
    stub.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = cloudformation ]; then echo None; exit 0; fi\n'
        f'echo "$*" >> "{calls}"\n'
    )
    stub.chmod(0o755)
    env = {**os.environ, "PATH": f"{stub.parent}:{os.environ['PATH']}"}
    env.pop("DISTRIBUTION", None)
    if distribution is not None:
        env["DISTRIBUTION"] = distribution
    result = subprocess.run(
        [str(SCRIPT), "cloudfront"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    return result, calls.read_text() if calls.exists() else ""


def test_missing_stack_output_is_rejected_before_any_change(tmp_path: Path) -> None:
    result, calls = _run_with_stub_aws(tmp_path, None)

    assert result.returncode != 0
    assert "invalid CloudFront domain" in result.stderr
    assert "change-resource-record-sets" not in calls


def test_non_cloudfront_distribution_is_rejected(tmp_path: Path) -> None:
    result, calls = _run_with_stub_aws(tmp_path, "evil.example.com")

    assert result.returncode != 0
    assert "change-resource-record-sets" not in calls


def test_placeholder_is_rejected_outside_a_dry_run(tmp_path: Path) -> None:
    result, calls = _run_with_stub_aws(tmp_path, "<DistributionDomainName>")

    assert result.returncode != 0
    assert "invalid CloudFront domain" in result.stderr
    assert "change-resource-record-sets" not in calls


def test_dry_run_without_a_distribution_prints_the_placeholder() -> None:
    env = {k: v for k, v in os.environ.items() if k != "DISTRIBUTION"}
    result = subprocess.run(
        [str(SCRIPT), "cloudfront", "--dry-run"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    values = {
        record["Value"]
        for change in json.loads(result.stdout)["Changes"]
        for record in change["ResourceRecordSet"].get("ResourceRecords", [])
    }
    assert values == {"<DistributionDomainName>"}
