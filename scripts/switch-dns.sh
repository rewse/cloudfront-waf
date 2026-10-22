#!/usr/bin/env bash
# Moves the public names of rewse.jp between CloudFront and the home origin
# with one Route 53 UPSERT batch.
#
# usage: switch-dns.sh <cloudfront|origin> [--dry-run]
#
# --dry-run prints the ChangeBatch JSON and changes nothing. In cloudfront
# mode the distribution domain name comes from $DISTRIBUTION, or from the
# stack output DistributionDomainName when $DISTRIBUTION is empty.
set -euo pipefail

readonly HOSTED_ZONE_ID="Z34LVKL0P9KD74"
readonly REGION="us-east-1"
readonly STACK_NAME="cloudfront-waf"

usage() {
  echo "usage: ${0##*/} <cloudfront|origin> [--dry-run]" >&2
  exit 2
}

mode="${1:-}"
dry_run=false
case "${2:-}" in
  "") ;;
  --dry-run) dry_run=true ;;
  *) usage ;;
esac
[[ $# -le 2 ]] || usage
[[ "${mode}" == "cloudfront" || "${mode}" == "origin" ]] || usage

require_distribution_domain() {
  if [[ -z "$1" || "$1" == "None" || "$1" != *.cloudfront.net ]]; then
    echo "error: invalid CloudFront domain name: '$1'" >&2
    exit 1
  fi
}

distribution="${DISTRIBUTION:-}"
if [[ "${mode}" == "cloudfront" && -z "${distribution}" ]]; then
  if "${dry_run}"; then
    distribution="<DistributionDomainName>"
  else
    distribution="$(aws cloudformation describe-stacks \
      --region "${REGION}" --stack-name "${STACK_NAME}" \
      --query "Stacks[0].Outputs[?OutputKey=='DistributionDomainName'].OutputValue" \
      --output text)"
  fi
fi
if [[ "${mode}" == "cloudfront" && "${distribution}" != "<DistributionDomainName>" ]]; then
  require_distribution_domain "${distribution}"
fi

build_batch() {
  python3 -I -c '
import json
import sys

mode, distribution = sys.argv[1], sys.argv[2]
ZONE = "rewse.jp."
CLOUDFRONT_ALIAS_ZONE_ID = "Z2FDTNDATAQYW2"
TTL = 300
HOME_IPV4 = "106.163.184.9"
HOME_IPV6 = "240f:143:f60c:1:2ecf:67ff:fe0f:f65d"
HOME_HOST = "fox.rewse.jp"
SUBDOMAINS = ["couchdb", "grafana", "hass", "litellm", "nas", "nvr",
              "teslamate", "www", "zabbix"]


def upsert(record_set):
    return {"Action": "UPSERT", "ResourceRecordSet": record_set}


def cname(name, value):
    return upsert({"Name": f"{name}.{ZONE}", "Type": "CNAME", "TTL": TTL,
                   "ResourceRecords": [{"Value": value}]})


def apex_record(record_type, value):
    return upsert({"Name": ZONE, "Type": record_type, "TTL": TTL,
                   "ResourceRecords": [{"Value": value}]})


def apex_alias(record_type):
    return upsert({"Name": ZONE, "Type": record_type, "AliasTarget": {
        "HostedZoneId": CLOUDFRONT_ALIAS_ZONE_ID,
        "DNSName": distribution,
        "EvaluateTargetHealth": False}})


changes = []
if mode == "cloudfront":
    changes += [cname(name, distribution) for name in SUBDOMAINS]
    changes += [apex_alias("A"), apex_alias("AAAA")]
else:
    for name in SUBDOMAINS:
        changes.append(cname(name, "rewse.jp" if name == "www" else HOME_HOST))
    changes += [apex_record("A", HOME_IPV4), apex_record("AAAA", HOME_IPV6)]

print(json.dumps({"Comment": f"switch rewse.jp to {mode}", "Changes": changes},
                 indent=2))
' "${mode}" "${distribution}"
}

batch="$(build_batch)"

if "${dry_run}"; then
  printf '%s\n' "${batch}"
  exit 0
fi

change_id="$(aws route53 change-resource-record-sets \
  --hosted-zone-id "${HOSTED_ZONE_ID}" \
  --change-batch "${batch}" \
  --query "ChangeInfo.Id" --output text)"
aws route53 wait resource-record-sets-changed --id "${change_id}"
echo "switched rewse.jp to ${mode} (${change_id})"
