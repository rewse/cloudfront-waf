#!/usr/bin/env bash
# Deploys the cloudfront-waf stack. Secrets are read from 1Password at deploy
# time and are never printed.
#
# usage: deploy.sh
set -euo pipefail

readonly OP_ORIGIN_VERIFY_REF="op://ansible/kgap2pevj7exae5jnvlsewbs7y/password"
readonly OP_PENTEST_HEADER_REF="op://ansible/m6obpvalg7ekdi5nsf4yx6wi3q/password"
readonly OP_OFFICE_CIDRS_REF="op://ansible/rocgj7m2grqpdwb4gvcqbktvhm/ipv4"
readonly REGION="us-east-1"
readonly STACK_NAME="cloudfront-waf"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

origin_verify="$(op read -n "${OP_ORIGIN_VERIFY_REF}")"
pentest_header="$(op read -n "${OP_PENTEST_HEADER_REF}")"
office_cidrs="$(op read -n "${OP_OFFICE_CIDRS_REF}")"

aws cloudformation deploy \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --template-file infra/template.yaml \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
  "OriginVerifyHeaderValue=${origin_verify}" \
  "PentestHeaderValue=${pentest_header}" \
  "OfficeCidrs=${office_cidrs}"
