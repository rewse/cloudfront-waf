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
