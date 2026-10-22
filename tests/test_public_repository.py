"""Checks that the public repository names no public address it should not."""

import ipaddress
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IPV4_LITERAL = re.compile(r"(?<![\d.v])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d.])")
# Public addresses the repository may name: the home WAN address (public in
# DNS), a CloudFront origin-facing range, and the EC2 address of an
# unidentified webhook caller. Private, loopback, and documentation ranges
# reveal nothing and are always allowed.
PUBLIC_ALLOWED = {"106.163.184.9", "130.176.0.0/18", "54.64.81.21"}
# A prefix written with a wildcard in place of the last octets.
IPV4_WILDCARD = re.compile(r"(?<![\d.v])\d{1,3}(?:\.\d{1,3}){1,2}\.[x*](?![\w.])")


def _tracked_text_files() -> list[Path]:
    names = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.split(b"\0")
    return [
        ROOT / name.decode() for name in names if name and not name.endswith(b".lock")
    ]


def _is_allowed(literal: str) -> bool:
    if literal in PUBLIC_ALLOWED:
        return True
    try:
        network = ipaddress.ip_network(literal, strict=False)
    except ValueError:
        # Four dotted numbers that are not an address, such as a version.
        return True
    return network.is_private


def test_only_known_ipv4_addresses_appear() -> None:
    found = {
        f"{path.relative_to(ROOT)}: {literal}"
        for path in _tracked_text_files()
        for literal in IPV4_LITERAL.findall(path.read_text(errors="ignore"))
        if not _is_allowed(literal)
    }

    assert found == set()


def test_no_address_prefix_is_written_with_a_wildcard() -> None:
    found = {
        f"{path.relative_to(ROOT)}: {match}"
        for path in _tracked_text_files()
        for match in IPV4_WILDCARD.findall(path.read_text(errors="ignore"))
    }

    assert found == set()
