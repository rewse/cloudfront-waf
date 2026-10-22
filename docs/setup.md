# Setup

This runbook deploys the stack `cloudfront-waf` in Region `us-east-1`, moves the ten public names of `rewse.jp` onto it, and covers routine operations afterward. The stack creates one CloudFront distribution, an AWS WAF web ACL, the ACM certificate, the WAF log group, and the record `origin.rewse.jp`. The Apache and UDM changes are in `rewse/ansible-playbooks`.

The default AWS profile is ReadOnly. Commands that write to AWS need the Admin profile, so they carry the `AWS_PROFILE=admin` prefix.

## Prerequisites

You need the AWS CLI, `uv`, and the 1Password CLI (`op`) signed in. The deploy reads three items from the 1Password vault `ansible`, referenced by item ID. Nothing in this repository holds their values.

| Item | ID | Field | Used for |
| --- | --- | --- | --- |
| Amazon CloudFront - Origin Verify | `kgap2pevj7exae5jnvlsewbs7y` | `password` | The `X-Origin-Verify` header that CloudFront adds to every origin request |
| AWS Security Agent pentest header | `m6obpvalg7ekdi5nsf4yx6wi3q` | `password` | The `X-Security-Agent-Pentest` value that lets the pentest bypass the WAF |
| Amazon Corporate Network - Egress | `rocgj7m2grqpdwb4gvcqbktvhm` | `ipv4` | Comma-separated egress CIDRs for the geo label and the Apache allowlists |

The Ansible roles read the same items. If `op` asks for approval, approve it in 1Password and rerun the command.

## Deploy the stack

```sh
uv run cfn-lint infra/template.yaml
AWS_PROFILE=admin scripts/deploy.sh
```

`scripts/deploy.sh` reads the three items with `op read` and passes them to `aws cloudformation deploy` in a temporary JSON file, so they never appear in argv. The file is removed on exit. The first deployment is slow because the certificate validates through DNS and the distribution has to propagate.

Every managed rule group starts in count mode, so only the pentest allow rule and the rate-based rules act on requests. The stack outputs `DistributionDomainName`, which `scripts/switch-dns.sh` reads. Rerun the same command for any later template or secret change.

## Switch DNS

The ten public names are `rewse.jp` and nine subdomains (`couchdb`, `grafana`, `hass`, `litellm`, `nas`, `nvr`, `teslamate`, `www`, `zabbix`). The template cannot own their records: they were created by hand, and a manually created record cannot be imported into `AWS::Route53::RecordSet`. Recreating them through CloudFormation would leave resolvers with a cached NXDOMAIN for up to 900 seconds, the negative-caching time in the zone's SOA.

`scripts/switch-dns.sh` moves all ten names in one atomic UPSERT batch.

```sh
scripts/switch-dns.sh cloudfront --dry-run
AWS_PROFILE=admin scripts/switch-dns.sh cloudfront
AWS_PROFILE=admin scripts/switch-dns.sh origin
```

`cloudfront` points the subdomains at the distribution with CNAME records and the apex with alias A and AAAA records. `origin` points the subdomains back at `fox.rewse.jp` (and `www` at `rewse.jp`) and sets the apex A and AAAA to the home addresses. `--dry-run` prints the change batch and changes nothing. The CNAME and apex origin records have a 300 second TTL, so a switch takes up to five minutes to reach every resolver. Alias records carry no TTL of their own.

## Cutover order

Do the steps in order and check each result before the next. The `httpd` and `udm` roles are in `rewse/ansible-playbooks`; apply them with the commands in that repository's `AGENTS.md`.

1. Deploy the stack as above. To undo it, delete the stack, which is safe only while no public name points at the distribution. Ask the owner first.
2. Install `mod_remoteip` on fox and hotel by applying the `httpd` role with `httpd_cloudfront_origin_enforce` left `false`. Apache then reads the real client address from CloudFront and does not yet check the secret header. To undo it, revert the role change and apply the `httpd` role again.
3. Switch the public DNS with `AWS_PROFILE=admin scripts/switch-dns.sh cloudfront`, then run the checklist in the verification section of the design document, `docs/superpowers/specs/2026-10-22-cloudfront-waf-design.md` (written in Japanese). To undo it, run `AWS_PROFILE=admin scripts/switch-dns.sh origin`.
4. Set `httpd_cloudfront_origin_enforce` to `true` and apply the `httpd` role to fox and hotel. Requests without `X-Origin-Verify` now get a 403, except those from the home network, the VPN, and loopback. To undo it, set the variable to `false` and apply again.
5. Set `udm_cloudfront_enforce` to `true` and apply the `udm` role. WAN port 443 then accepts only the CloudFront origin-facing ranges, port 80 and IPv6 80 and 443 are closed, and SSH stays open. To undo it, set the variable to `false` and apply again.
6. Watch the WAF logs for one to two weeks, remove false positives, then turn on blocking as described next. To undo it, set `BlockManagedRules` back to `"false"` and deploy again.

## Turn on blocking

`BlockManagedRules` defaults to `"false"`. Set it to `"true"` once the count period shows no false positives. The IP reputation list, the Anonymous IP list (except `HostingProviderIPList`, which always counts), and the other managed groups then block.

`scripts/deploy.sh` passes only the three secrets, so change the `Default` of `BlockManagedRules` in `infra/template.yaml` to `"true"`, commit it, and run the deploy command again. To go back, restore the default to `"false"` and deploy again.

## Rotate a secret

The pentest header and the egress CIDRs change in 1Password and take effect on the next deploy. After changing the CIDRs, also apply the `httpd` role, because Apache renders the same list into its allowlists.

The origin verification header needs the order below. CloudFront and Apache must hold the same value, and while they differ, Apache would answer 403 to every request that arrives through CloudFront.

1. Set `httpd_cloudfront_origin_enforce` to `false` and apply the `httpd` role to fox and hotel.
2. Update the password of "Amazon CloudFront - Origin Verify" in 1Password.
3. Deploy the stack, which gives CloudFront the new value.
4. Apply the `httpd` role to fox and hotel so Apache reads the new value.
5. Set `httpd_cloudfront_origin_enforce` back to `true` and apply the `httpd` role again.

## Read the WAF logs

The web ACL logs to the CloudWatch Logs group `aws-waf-logs-cloudfront-waf` in `us-east-1`, kept for 90 days. The `authorization` and `cookie` headers and the pentest header are redacted. In CloudWatch Logs Insights, select the group and a time range, then run:

```
stats count(*) as requests by
    terminatingRuleId,
    ruleGroupList.0.ruleGroupId,
    ruleGroupList.0.terminatingRule.ruleId,
    ruleGroupList.0.nonTerminatingMatchingRules.0.ruleId,
    nonTerminatingMatchingRules.0.ruleId,
    httpRequest.clientIp,
    httpRequest.uri
| sort requests desc
| limit 50
```

A managed rule group in count mode reports its matches under `ruleGroupList[].nonTerminatingMatchingRules`, and once blocking is on the matching sub-rule appears under `ruleGroupList[].terminatingRule`. The top-level `nonTerminatingMatchingRules` holds only rules attached directly to the web ACL, such as the geo label. The query reads the first entry of each list, so a request that matched several rules shows only one of them.

After the first deployment, run the query against real log lines and adjust the field paths if the output has empty columns. When a sub-rule flags legitimate traffic, add a rule action override for it in `infra/template.yaml` before you turn on blocking.
