# Setup

This runbook deploys the stack `cloudfront-waf` in Region `us-east-1`, moves the ten public names of `rewse.jp` onto it, and covers the routine operations afterward. The stack holds one CloudFront distribution, an AWS WAF web ACL, the ACM certificate, the WAF log group, and the record `origin.rewse.jp`. The Apache and UDM side lives in `rewse/ansible-playbooks`.

The default AWS profile is ReadOnly. Every step that writes to AWS needs the Admin profile, so prefix those commands with `AWS_PROFILE=admin`. Read what a step changes before you run it.

## Prerequisites

You need the AWS CLI, `uv`, and the 1Password CLI (`op`) signed in. The deploy reads three items from the 1Password vault `ansible`, referenced by item ID. Nothing in this repository holds their values.

| Item | ID | Field | Used for |
| --- | --- | --- | --- |
| Amazon CloudFront - Origin Verify | `kgap2pevj7exae5jnvlsewbs7y` | `password` | The `X-Origin-Verify` header that CloudFront adds to every origin request |
| AWS Security Agent pentest header | `m6obpvalg7ekdi5nsf4yx6wi3q` | `password` | The `X-Security-Agent-Pentest` value that lets the pentest bypass the WAF |
| Amazon Corporate Network - Egress | `rocgj7m2grqpdwb4gvcqbktvhm` | `ipv4` | Comma-separated egress CIDRs, used for the geo label and the Apache allowlists |

Apache and the Ansible roles read the same items. If `op` asks for approval, approve it in 1Password and rerun the command.

## 1. Deploy the stack

```sh
uv run cfn-lint infra/template.yaml
AWS_PROFILE=admin scripts/deploy.sh
```

`scripts/deploy.sh` reads the three items with `op read`, passes them to `aws cloudformation deploy` as a temporary JSON file so they never appear in argv, and removes the file on exit. The first deployment takes a while because the certificate is validated through DNS and the distribution has to propagate.

Every managed rule group starts in count mode, so a deployment blocks nothing except the rate-based rules. The stack outputs `DistributionDomainName`, which `scripts/switch-dns.sh` reads.

## DNS

The ten public names are `rewse.jp` and nine subdomains (`couchdb`, `grafana`, `hass`, `litellm`, `nas`, `nvr`, `teslamate`, `www`, `zabbix`). Their records are not in the template. They were created by hand, and a manually created record cannot be imported into `AWS::Route53::RecordSet`. Recreating them through CloudFormation would delete them first and leave resolvers with a cached NXDOMAIN for up to 900 seconds, the negative-caching time in the zone's SOA. The template keeps only `origin.rewse.jp`, which is new.

`scripts/switch-dns.sh` moves all ten names in one atomic UPSERT batch, so they switch together or not at all.

```sh
scripts/switch-dns.sh cloudfront --dry-run
AWS_PROFILE=admin scripts/switch-dns.sh cloudfront
AWS_PROFILE=admin scripts/switch-dns.sh origin
```

`cloudfront` points the subdomains at the distribution with CNAME records and the apex at it with alias A and AAAA records. `origin` points them back at `fox.rewse.jp` (and `www` at `rewse.jp`), with the apex A and AAAA set to the home addresses. `--dry-run` prints the change batch and changes nothing. Records have a 300 second TTL, so a switch takes up to five minutes to reach every resolver.

## Cutover order

Follow these steps in order, and check the result of each before starting the next. Each step lists the command that undoes it. The `httpd` and `udm` roles are in `rewse/ansible-playbooks`; apply them with the playbook commands in that repository's `AGENTS.md`.

1. Deploy the stack with `AWS_PROFILE=admin scripts/deploy.sh`. Only the allow rule for the pentest and the rate-based rules are active; the rest count. To undo it, delete the stack, which is only safe while no public name points at the distribution. Ask the owner before you do.
2. Install `mod_remoteip` on fox and hotel by applying the `httpd` role with `httpd_cloudfront_origin_enforce` left `false`. Apache then reads the real client address from CloudFront but does not yet check the secret header. To undo it, revert the role change and apply the `httpd` role again.
3. Switch the public DNS with `AWS_PROFILE=admin scripts/switch-dns.sh cloudfront`, then run the checks in the "確認項目" section of `docs/superpowers/specs/2026-10-22-cloudfront-waf-design.md`. To undo it, run `AWS_PROFILE=admin scripts/switch-dns.sh origin`.
4. Turn on the secret header check by setting `httpd_cloudfront_origin_enforce` to `true` and applying the `httpd` role to fox and hotel. Requests from outside the home network and the VPN without `X-Origin-Verify` now get a 403. To undo it, set the variable back to `false` and apply again.
5. Close the WAN firewall by setting `udm_cloudfront_enforce` to `true` and applying the `udm` role. WAN port 443 then accepts only the CloudFront origin-facing ranges, port 80 and IPv6 80 and 443 are closed, and SSH stays open. To undo it, set the variable back to `false` and apply again.
6. Watch the WAF logs for one to two weeks, remove false positives, then turn on blocking as described below. To undo it, set `BlockManagedRules` back to `"false"` and run `AWS_PROFILE=admin scripts/deploy.sh`.

## Turn on blocking

`BlockManagedRules` defaults to `"false"`. Set it to `"true"` once the count period shows no false positives. The IP reputation list, the Anonymous IP list (except `HostingProviderIPList`, which always counts), and the other managed groups then block.

`scripts/deploy.sh` passes only the three secrets, so change the `Default` of `BlockManagedRules` in `infra/template.yaml` to `"true"`, commit it, and run the deploy again.

```sh
AWS_PROFILE=admin scripts/deploy.sh
```

To go back, restore the default to `"false"` and deploy again.

## Rotate a secret

The pentest header and the egress CIDRs change in 1Password and take effect on the next `AWS_PROFILE=admin scripts/deploy.sh`. For the CIDRs, also apply the `httpd` role, because Apache renders the same list into its allowlists.

The origin verification header needs the order below, because CloudFront and Apache must agree on the value. Apache has to stop checking it while the two sides differ, or every request returns 403.

1. Set `httpd_cloudfront_origin_enforce` to `false` and apply the `httpd` role to fox and hotel.
2. Update the password of "Amazon CloudFront - Origin Verify" in 1Password.
3. Run `AWS_PROFILE=admin scripts/deploy.sh`, which gives CloudFront the new value.
4. Apply the `httpd` role to fox and hotel so Apache reads the new value.
5. Set `httpd_cloudfront_origin_enforce` back to `true` and apply the `httpd` role again.

## Read the WAF logs

The web ACL logs to the CloudWatch Logs group `aws-waf-logs-cloudfront-waf` in `us-east-1`, kept for 90 days. The `authorization` and `cookie` headers and the pentest header are redacted. In CloudWatch Logs Insights, select the group and a time range, then run this query to list the rules that matched, split by whether they ended the request, with the client and the path:

```
fields @timestamp, terminatingRuleId, nonTerminatingMatchingRules, httpRequest.clientIp, httpRequest.uri
| stats count(*) as requests by terminatingRuleId, nonTerminatingMatchingRules.0.ruleId, httpRequest.clientIp, httpRequest.uri
| sort requests desc
| limit 50
```

A rule in count mode appears under `nonTerminatingMatchingRules` (the query shows the first one per request). When it flags legitimate traffic, add a rule action override for it in `infra/template.yaml` before you turn on blocking.
