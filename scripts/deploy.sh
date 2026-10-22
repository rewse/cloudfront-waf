#!/usr/bin/env bash
# Deploys the cloudfront-waf stack. Secrets are read from 1Password at deploy
# time and are never printed. The other parameters come from
# infra/parameters.json on every deploy, because aws cloudformation deploy
# keeps the previous value of a parameter it is not given, so a changed
# template Default would never reach a stack that already exists.
#
# usage: deploy.sh
set -euo pipefail

readonly OP_ORIGIN_VERIFY_REF="op://ansible/kgap2pevj7exae5jnvlsewbs7y/password"
readonly OP_PENTEST_HEADER_REF="op://ansible/m6obpvalg7ekdi5nsf4yx6wi3q/password"
readonly OP_OFFICE_CIDRS_REF="op://ansible/rocgj7m2grqpdwb4gvcqbktvhm/ipv4"
readonly PARAMETERS_FILE="infra/parameters.json"
readonly REGION="us-east-1"
readonly STACK_NAME="cloudfront-waf"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

origin_verify="$(op read -n "${OP_ORIGIN_VERIFY_REF}")"
pentest_header="$(op read -n "${OP_PENTEST_HEADER_REF}")"
office_cidrs="$(op read -n "${OP_OFFICE_CIDRS_REF}")"

if [[ ! "${office_cidrs}" =~ ^[0-9a-fA-F:.]+/[0-9]+(,[0-9a-fA-F:.]+/[0-9]+)*$ ]]; then
  echo "error: the office CIDR value is not a comma-separated CIDR list" >&2
  exit 1
fi

# Keep secret values out of argv: pass the overrides as a JSON file.
overrides="$(mktemp)"
trap 'rm -f "${overrides}"' EXIT
chmod 600 "${overrides}"
ORIGIN_VERIFY="${origin_verify}" PENTEST_HEADER="${pentest_header}" \
  OFFICE_CIDRS="${office_cidrs}" python3 -I -c '
import json
import os
import sys

with open(sys.argv[1]) as file:
    committed = json.load(file)
print(json.dumps([f"{name}={value}" for name, value in sorted(committed.items())] + [
    "OriginVerifyHeaderValue=" + os.environ["ORIGIN_VERIFY"],
    "PentestHeaderValue=" + os.environ["PENTEST_HEADER"],
    "OfficeCidrs=" + os.environ["OFFICE_CIDRS"],
]))
' "${PARAMETERS_FILE}" > "${overrides}"

aws cloudformation deploy \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --template-file infra/template.yaml \
  --no-fail-on-empty-changeset \
  --parameter-overrides "file://${overrides}"
