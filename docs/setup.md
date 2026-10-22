# Setup

This runbook deploys the stack `cloudfront-waf` in Region `us-east-1`, moves the ten public names of `rewse.jp` onto it, and covers routine operations afterward. The stack creates one CloudFront distribution, an AWS WAF web ACL, the ACM certificate, the WAF log group, and the record `origin.rewse.jp`. The Apache and UDM changes are in `rewse/ansible-playbooks`.

The default AWS profile is ReadOnly. Commands that write to AWS need the Admin profile, so they start with `AWS_PROFILE=admin`.

## Prerequisites

You need the AWS CLI, `uv`, and the 1Password CLI (`op`) signed in. The deploy reads three items from the 1Password vault `ansible`, referenced by item ID. Nothing in this repository contains their values.

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

`scripts/deploy.sh` reads the three items with `op read` and passes them to `aws cloudformation deploy` in a temporary JSON file, so they never appear in argv. The file is removed on exit. The same file carries every value in `infra/parameters.json`, the committed state of the parameters that are not secret (`BlockManagedRules` and `HomePublicIpv4`). The first deployment is slow because the certificate validates through DNS and the distribution has to propagate.

Every managed rule group starts in count mode, so only the pentest allow rule and the rate-based rules act on requests. The stack outputs `DistributionDomainName`, which `scripts/switch-dns.sh` reads. Rerun the same command for any later template or secret change.

## Switch DNS

The ten public names are `rewse.jp` and nine subdomains (`couchdb`, `grafana`, `hass`, `litellm`, `nas`, `nvr`, `teslamate`, `www`, `zabbix`). The template cannot own their records: they were created by hand, and a manually created record cannot be imported into `AWS::Route53::RecordSet`. Recreating them through CloudFormation would leave resolvers with a cached NXDOMAIN for up to 900 seconds, the negative-caching time in the zone's SOA.

`scripts/switch-dns.sh` moves all ten names in one atomic UPSERT batch.

```sh
scripts/switch-dns.sh cloudfront --dry-run
AWS_PROFILE=admin scripts/switch-dns.sh cloudfront
AWS_PROFILE=admin scripts/switch-dns.sh origin
```

`cloudfront` points the subdomains at the distribution with CNAME records and the apex with alias A and AAAA records. `origin` points the subdomains back at `fox.rewse.jp` (and `www` at `rewse.jp`) and sets the apex A and AAAA to the home addresses. `--dry-run` prints the change batch and changes nothing. The CNAME and apex origin records have a 300 second TTL, so a switch takes up to five minutes to reach every resolver. Alias records have no TTL.

## Cutover order

Do the stages in order and check each result before the next. The `httpd`, `udm`, and service roles are in `rewse/ansible-playbooks`; run the commands below from that checkout, as its `AGENTS.md` describes.

### Stage 1: deploy the stack

Deploy the stack as above. To undo it, delete the stack, which is safe only while no public name points at the distribution. Ask the owner first.

### Stage 2: apply the Apache changes

Apply the changes to fox and hotel with `httpd_cloudfront_origin_enforce` left `false`:

```sh
ansible-playbook -i inventory home-primary.yml -l fox.rewse.jp \
  --tags httpd,filebrowser_apache,teslamate_apache,couchdb_fail2ban,filebrowser_fail2ban,homeassistant_fail2ban,litellm_fail2ban,nvr_fail2ban,teslamate_fail2ban,zabbix_server_fail2ban
ansible-playbook -i inventory home-secondary.yml -l hotel.rewse.jp \
  --tags httpd,homeassistant_ha_secondary_failover,homeassistant_ha_secondary_fail2ban
```

The `httpd` tag installs `mod_remoteip` and the log formats that record the restored client address, exempts the CloudFront origin-facing ranges from every fail2ban jail, installs the action that makes Apache deny banned addresses, and adds the drift check described under "Watch for new CloudFront ranges". Apache does not check the secret header yet. `filebrowser_apache` and `teslamate_apache` update the `nas` and `grafana` vhosts, which forward or log the client address themselves. The `*_fail2ban` tags give each HTTP jail the Apache ban action next to its firewall action. On hotel, `homeassistant_ha_secondary_failover` installs the `homeassistant-name-switch` that moves only the 443 forward, which has to be in place before stage 5 removes the 80 forward.

Before stage 3, send a few requests through CloudFront without changing DNS, for example `curl -sI --resolve hass.rewse.jp:443:<CloudFront IP> https://hass.rewse.jp/`. Then check on fox that no CloudFront origin-facing address appears as the client in the Apache logs that fail2ban reads:

```sh
sudo python3 - <<'EOF'
import ipaddress
import json
import urllib.request

with urllib.request.urlopen("https://ip-ranges.amazonaws.com/ip-ranges.json") as response:
    ranges = [
        ipaddress.ip_network(entry["ip_prefix"])
        for entry in json.load(response)["prefixes"]
        if entry["service"] == "CLOUDFRONT_ORIGIN_FACING"
    ]
# Each log and the field that holds the client address.
logs = {
    "/var/log/apache2/access.log": 0,
    "/var/log/apache2/grafana_basic_auth.log": 1,
    "/var/log/apache2/other_vhosts_access.log": 1,
}
for path, field in logs.items():
    with open(path, errors="replace") as log:
        for line in log:
            try:
                address = ipaddress.ip_address(line.split()[field])
            except (IndexError, ValueError):
                continue
            if any(address in network for network in ranges):
                print(path, line.rstrip())
EOF
```

Lines written before stage 2, such as a test request through CloudFront right after stage 1, show the edge server and can be ignored. A later line means that log still records the edge server instead of the client; fix it before switching DNS.

To undo stage 2, revert the role changes and run the same commands again.

### Stage 3: switch DNS

Switch the public DNS with `AWS_PROFILE=admin scripts/switch-dns.sh cloudfront`, then run the checklist in the verification section of the design document, `docs/superpowers/specs/2026-10-22-cloudfront-waf-design.md` (written in Japanese).

While going through the checklist, watch CouchDB replication. A `_changes` long poll waits up to 60 seconds by default, as long as the origin read timeout, so a poll that runs the full minute can end in a 504 from CloudFront. Check the distribution's `504ErrorRate` metric in CloudWatch (`us-east-1`, `Region=Global`) before creating the Zabbix 5xx trigger. If CouchDB polls cause 504s, have the clients send a `heartbeat` shorter than 60 seconds, so the connection carries data before the timeout.

To undo stage 3, run `AWS_PROFILE=admin scripts/switch-dns.sh origin`.

### Stage 4: enforce the origin header

Before enforcing, look for clients on the Docker bridge networks (`172.16.0.0/12`) that call the public names. Containers on fox reach Apache from those addresses, which are not exempt, so they would get a 403 once the header is enforced:

```sh
sudo awk '$2 ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ { print $1, $2 }' /var/log/apache2/other_vhosts_access.log | sort | uniq -c
sudo awk '$1 ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ { print $1 }' /var/log/apache2/access.log | sort | uniq -c
```

Point any such client at a name or address that does not go through the gate, or add its network to the exemptions in the `httpd` role, before you continue.

Set `httpd_cloudfront_origin_enforce` to `true` for both host groups and apply the `httpd_cloudfront_origin` tag to fox and hotel. Requests without `X-Origin-Verify` now get a 403, except those from the home network, the VPN, and loopback. To undo it, set the variable to `false` and apply again.

### Stage 5: close the WAN ports

Set `udm_cloudfront_enforce` to `true` and apply `udm.yml` with `--tags udm_cloudfront`. WAN port 443 then accepts only the CloudFront origin-facing ranges, port 80 and IPv6 80 and 443 are closed, and SSH stays open. The run stops before changing anything if an IPv6 rule also opens other ports, and fails if the 443 source limit did not stick or an IPv6 web rule remains.

Before it changes anything, the run saves the forwards and policies it is about to change to `~/.local/state/udm-cloudfront/originals-<UTC time>.json` on the machine that runs Ansible. Setting `udm_cloudfront_enforce` back to `false` does not undo the change; with `false` the component only keeps the address group in step with `ip-ranges.json`.

To undo stage 5, first set `udm_cloudfront_enforce` to `false`, so a later run does not close the ports again. Then restore the saved objects in the UniFi UI:

- On the 443 port forward, turn off the source limit.
- Recreate the 80 port forward with the values under `port_forwards` in the saved file.
- Recreate the IPv6 firewall rules under `firewall_policies`. The file holds one policy per destination zone, and the UI shows each rule once.

Then check from outside the home network that `106.163.184.9` and fox's IPv6 address answer on 80 and 443 again.

### Stage 6: turn on blocking

Watch the WAF logs for one to two weeks, remove false positives, then turn on blocking as described next. To undo it, set `BlockManagedRules` back to `"false"` in `infra/parameters.json` and deploy again.

### Roll back

Undo the stages in reverse order, starting from the last one done. In particular, run `switch-dns.sh origin` only after stages 5 and 4 are undone. Until the UDM forwards 443 and 80 from any source again and Apache accepts requests without the origin header, a client that follows DNS to the home address is refused, so every name would stop working.

## Turn on blocking

`BlockManagedRules` is `"false"` in `infra/parameters.json`. Set it to `"true"` once the count period shows no false positives. The IP reputation list, the Anonymous IP list, and the other managed groups then block. A few sub-rules keep counting either way, through the rule action overrides in `infra/template.yaml`: `HostingProviderIPList`, `SizeRestrictions_BODY`, `NoUserAgent_HEADER`, `CategoryHttpLibrary`, and `SignalNonBrowserUserAgent`. They match legitimate API callers: Home Assistant webhooks sent by Go-http-client, and Alexa and Tesla, which call too rarely for the count period to show them.

`aws cloudformation deploy` keeps the previous value of a parameter it is not given, so changing a template `Default` alone never reaches the stack. Change the value in `infra/parameters.json` and the matching `Default` in `infra/template.yaml` (the tests check that the two agree), commit both, and run the deploy command again. To go back, set both to `"false"` and deploy again.

## Rotate a secret

The egress CIDRs change in 1Password and take effect on the next deploy. After changing them, also apply the `httpd_conf` tag to fox and hotel and the `zabbix_server_frontend` tag to fox, because Apache renders the same list into the `/admin`, `/server-status`, and `/zabbix` allowlists.

The pentest header has three copies besides 1Password: the WAF allow rule in this stack, `security-agent-pentest.conf` in Apache (fail2ban leaves alone any address that sent the header), and the Secrets Manager secret `security-agent/pentest-header` that `rewse/security-agent` sends with each pentest. After changing the password in 1Password, update all three:

1. Deploy this stack.
2. Apply the `httpd_security_agent` tag to fox and hotel.
3. Copy the value to Secrets Manager and trigger an update of `HomePentest`, as the last paragraph of step 10 in `docs/setup.md` of `rewse/security-agent` describes:

   ```sh
   op read -n op://ansible/m6obpvalg7ekdi5nsf4yx6wi3q/password | AWS_PROFILE=admin aws secretsmanager put-secret-value \
     --region us-east-1 --secret-id security-agent/pentest-header --secret-string file:///dev/stdin
   ```

Until the three agree, the WAF blocks the pentest or fail2ban bans it partway through a run.

The origin verification header needs the order below. CloudFront and Apache must hold the same value, and while they differ, Apache would answer 403 to every request that arrives through CloudFront.

1. Set `httpd_cloudfront_origin_enforce` to `false` and apply the `httpd` role to fox and hotel.
2. Update the password of "Amazon CloudFront - Origin Verify" in 1Password.
3. Deploy the stack, which gives CloudFront the new value.
4. Apply the `httpd` role to fox and hotel so Apache reads the new value.
5. Set `httpd_cloudfront_origin_enforce` back to `true` and apply the `httpd` role again.

## Watch for new CloudFront ranges

AWS adds CloudFront origin-facing ranges to `ip-ranges.json` from time to time. The `mod_remoteip` trust list, the fail2ban exemption, and the UDM address group take them in only when Ansible runs. Until then, a request through an edge server in a new range is refused at the UDM once stage 5 is done. Before stage 5, Apache logs such a request under the edge address, and fail2ban could ban that edge, since its exemption comes from the same run.

The `httpd` role installs the Zabbix agent key `apache.remoteip.missing_prefixes` on fox and hotel. It returns the number of origin-facing prefixes in `ip-ranges.json` that `remoteip.conf` does not trust, and nothing when either cannot be read. Create the item and a trigger on a non-zero value in Zabbix by hand. When the trigger fires, apply the `httpd_remoteip` tag to fox and hotel and the `udm_cloudfront` tag to the UDM.

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

A managed rule group in count mode reports its matches under `ruleGroupList[].nonTerminatingMatchingRules`, and once blocking is on the matching sub-rule appears under `ruleGroupList[].terminatingRule`. The top-level `nonTerminatingMatchingRules` contains only rules attached directly to the web ACL, such as the geo label. The query reads the first entry of each list, so a request that matched several rules shows only one of them.

After the first deployment, run the query against real log lines and adjust the field paths if the output has empty columns. When a sub-rule flags legitimate traffic, add a rule action override for it in `infra/template.yaml` before you turn on blocking.
