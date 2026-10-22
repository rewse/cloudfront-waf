"""Checks that the public repository carries no private network addresses."""

import ipaddress
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IPV4_LITERAL = re.compile(r"(?<![\d.v])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d.])")
# A prefix written with a wildcard, such as "198.51.100.x".
IPV4_WILDCARD = re.compile(r"(?<![\d.v])\d{1,3}(?:\.\d{1,3}){1,2}\.[x*](?![\w.])")
# Addresses the repository may name: the home WAN address (public in DNS),
# the home LAN and the VPC behind the VPN, loopback, a CloudFront
# origin-facing range, and the EC2 address of an unidentified webhook caller.
ALLOWED = {
    "10.0.0.0/16",
    "106.163.184.9",
    "127.0.0.1",
    "130.176.0.0/18",
    "192.168.0.0/24",
    "192.168.0.10",
    "54.64.81.21",
}
# RFC 5737 documentation ranges, free for examples and test data.
DOCUMENTATION = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def _tracked_text_files() -> list[Path]:
    names = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.split(b"\0")
    return [
        ROOT / name.decode()
        for name in names
        if name and not name.endswith(b".lock")
    ]


def _is_documentation(literal: str) -> bool:
    network = ipaddress.ip_network(literal, strict=False)
    return any(network.subnet_of(range_) for range_ in DOCUMENTATION)


def test_only_known_ipv4_addresses_appear() -> None:
    found = {
        f"{path.relative_to(ROOT)}: {literal}"
        for path in _tracked_text_files()
        for literal in IPV4_LITERAL.findall(path.read_text(errors="ignore"))
        if literal not in ALLOWED and not _is_documentation(literal)
    }

    assert found == set()


def test_no_address_prefix_is_written_with_a_wildcard() -> None:
    found = {
        f"{path.relative_to(ROOT)}: {match}"
        for path in _tracked_text_files()
        for match in IPV4_WILDCARD.findall(path.read_text(errors="ignore"))
    }

    assert found == set()
