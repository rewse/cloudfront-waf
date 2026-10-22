# CloudFront と AWS WAF の導入 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** fox の 10 個の公開名へのインターネットからのリクエストをすべて CloudFront と AWS WAF に通し、自宅への直接の 80 / 443 を閉じる。

**Architecture:** AWS 側は新しい公開リポジトリ `rewse/cloudfront-waf` の CloudFormation スタック 1 つ（us-east-1）で、秘密の値はデプロイ時に 1Password から NoEcho パラメータで渡す。自宅側は ansible-playbooks の `httpd`、`udm`、`homeassistant_ha_secondary`、`zabbix_aws` ロールを直す。最後に、設計書の 6 段階の順番で本番に切り替える。

**Tech Stack:** CloudFormation（AWS::CloudFront、AWS::WAFv2、AWS::CertificateManager、AWS::Route53、AWS::Logs）、aws-cli、1Password CLI（`op`）、Bash、Python 3.13 と pytest、uv、cfn-lint、Ansible、Apache 2.4（mod_remoteip）、UniFi Site Manager API、Zabbix。

**Spec:** `docs/superpowers/specs/2026-10-22-cloudfront-waf-design.md`

## Global Constraints

- 対象の名前は `rewse.jp`、`www.rewse.jp`、`hass.rewse.jp`、`nas.rewse.jp`、`nvr.rewse.jp`、`couchdb.rewse.jp`、`litellm.rewse.jp`、`teslamate.rewse.jp`、`grafana.rewse.jp`、`zabbix.rewse.jp` の 10 個。`blog.rewse.jp` と RDS の CNAME には触らない。
- スタック名は `cloudfront-waf`、リージョンは us-east-1。公開ゾーンは `Z34LVKL0P9KD74`。
- オリジンは `origin.rewse.jp`。A レコード（`106.163.184.9`）だけを作り、AAAA は作らない。
- 秘密の値（オリジン検証ヘッダーの値、`X-Security-Agent-Pentest` の値、社内の出口の CIDR）は 1Password の `ansible` vault を正とし、リポジトリにも CloudFormation のテンプレートにも書かない。社内の出口の CIDR は ansible-playbooks の `site.yml` から消す。git の履歴は書き換えない。
- オリジン検証ヘッダーの名前は `X-Origin-Verify` とする。
- 秘密ヘッダーの検証を免除するのは、loopback、`home_private_ipv4`、`home_private_ipv6`、`home_public_ipv6`、`aws_private_ipv4`、`aws_public_ipv6`。
- `mod_remoteip` が信頼するのは、`ip-ranges.json` の `CLOUDFRONT_ORIGIN_FACING` だけ。
- WAN の 80 は IPv4 と IPv6 の両方で閉じる。443 は IPv4 で CloudFront のオリジン向けレンジだけに絞り、IPv6 では閉じる。SSH の 11022 / 21022 は変えない。
- `blog.rewse.jp` の Amplify の Web ACL と `coa-dev-cloudfront-waf` には触らない。
- ansible-playbooks の変更は、同リポジトリの AGENTS.md の規約（ロール設計、タグ、変数の置き場所、引用符、1Password、UniFi、Zabbix）に従う。
- `.github` 一式は `~/git/AGENTS.md` の GitHub の規約に従う。リポジトリは public なので、OSV-Scanner の SARIF はアップロードする。
- 本番を変える手順（スタックのデプロイ、DNS の切り替え、Apache / UDM への適用、WAF の Block 化、GitHub への公開）は、実行の直前に所有者の確認を取る。
- ブラウザでの確認は `browser-automation` スキルに従う。
- GitHub への push は `github-push-via-fox` スキルに従う。

## Review Focus

- `X-Forwarded-For` を偽装した直接のリクエスト: CloudFront 以外から来た偽の `X-Forwarded-For` で、クライアント IP（`%a`、`Require ip`、fail2ban）が変わってはいけない。Task 6 の設定テストと Task 13 の実地確認で押さえる。
- 秘密ヘッダーを持たない内部からのリクエスト: 家の中と VPN の向こうの VPC からは、今まで通り 200 で通るべき。`/admin`、`/server-status`、`/zabbix` の許可リストは秘密ヘッダーの判定と AND で効くべき。Task 7 のテストで押さえる。
- HA のフェイルオーバー先の hotel: hotel も httpd ロールを通じて同じ `mod_remoteip` と秘密ヘッダーの検証を持ち、切り替え後も CloudFront 経由で HA が使えるべき。Task 7 のテストと Task 14 の確認で押さえる。
- 長時間の接続と大きな本文: WebSocket、CouchDB のロングポール、`nas` の大きいアップロードが、オリジンのタイムアウト（60 秒）と WAF の本文検査で切れないべき。Task 2 のテストで `SizeRestrictions_BODY` が常に Count であることを、Task 14 で実地を押さえる。
- 秘密の漏れ: `X-Security-Agent-Pentest` の値が WAF のログに残らないこと、社内の出口の CIDR が公開リポジトリに残らないこと。Task 2 のテストでログの redaction を、Task 5 のテストで `site.yml` を押さえる。

---

## ファイル構成

`rewse/cloudfront-waf`（`~/git/cloudfront-waf`）

- `AGENTS.md`: リポジトリの目的、秘密の扱い、検証コマンド、デプロイ手順への案内
- `pyproject.toml`、`uv.lock`、`.python-version`（3.13）、`.pre-commit-config.yaml`、`.gitignore`
- `.github/dependabot.yml`、`.github/workflows/{lint,test,gitleaks,trufflehog,dependency-scan}.yml`
- `infra/template.yaml`: スタック全体
- `scripts/deploy.sh`: 1Password から秘密を読んでデプロイする
- `scripts/switch-dns.sh`: 10 個の名前を CloudFront とオリジンの間で切り替える
- `docs/setup.md`: 英語の運用手順（初回デプロイ、DNS の切り替え、戻し方、Block 化、値の更新）
- `tests/cfn.py`: CloudFormation の短縮タグを読む YAML ローダー
- `tests/test_template.py`、`tests/test_switch_dns.py`

`rewse/ansible-playbooks`（`~/git/ansible-playbooks`）

- 変更: `inventory/group_vars/all/site.yml`（`office_public_ipv4` を 1Password の参照に）
- 作成: `roles/httpd/tasks/remoteip.yml`、`roles/httpd/templates/remoteip.conf.j2`
- 作成: `roles/httpd/tasks/cloudfront_origin.yml`、`roles/httpd/templates/cloudfront-origin.conf.j2`、`roles/httpd/defaults/main.yml`
- 変更: `roles/httpd/tasks/main.yml`、`roles/httpd/vars/main.yml`、`roles/httpd/files/log-format.conf`、`roles/httpd/templates/admin.conf.j2`、`roles/httpd/templates/status.conf.j2`、`roles/zabbix_server/templates/zabbix-api.conf.j2`
- 作成: `inventory/group_vars/home_primary/httpd.yml`、`inventory/group_vars/home_secondary/httpd.yml`
- 変更: `roles/homeassistant_ha_secondary/templates/homeassistant-name-switch.j2`
- 作成: `roles/udm/tasks/cloudfront.yml`、`roles/udm/vars/main.yml`、`roles/udm/defaults/main.yml`。変更: `roles/udm/tasks/main.yml`
- 作成: `roles/zabbix_aws/files/cloudfront_waf.sh`、`roles/zabbix_aws/files/cloudfront_waf.conf`、`roles/zabbix_aws/tasks/cloudfront_waf.yml`。変更: `roles/zabbix_aws/tasks/main.yml`
- テスト: `tests/test_cloudfront_origin.py`（新規）、`tests/test_internet_exposure.py`、`tests/test_privilege_hardening.py`

## フェーズ A: `rewse/cloudfront-waf`

### Task 1: リポジトリの土台と CI

**Files:**
- Create: `AGENTS.md`、`pyproject.toml`、`.python-version`、`.pre-commit-config.yaml`、`.gitignore`、`.github/dependabot.yml`、`.github/workflows/{lint,test,gitleaks,trufflehog,dependency-scan}.yml`、`tests/cfn.py`、`tests/test_smoke.py`

**Interfaces:**
- Produces: `tests/cfn.py` の `load_template(path: Path) -> dict[str, Any]`。security-agent の `tests/test_infra.py` の `_CfnLoader` と同じく、`!Ref`、`!Sub`、`!GetAtt`、`!If` などを素の値として読む。
- Produces: 検証コマンド `uv run pytest -q` と `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`。

- [ ] **Step 1:** `~/git/security-agent` の `pyproject.toml`、`.pre-commit-config.yaml`、`.github` を手本に写す。`[project]` の name は `cloudfront-waf`、依存はなし、dev グループは `cfn-lint`、`pytest`、`pyyaml`。`[tool.uv] exclude-newer = "4 days"`、`exclude-newer-package` は持ち込まない。`lint.yml` の cfn-lint の対象は `infra/template.yaml`。`gitleaks.yml`、`trufflehog.yml`、`dependency-scan.yml` の cron の分は、`~/git` の他リポジトリと重ならない値を選ぶ（`rg -n "cron:" ~/git/*/.github/workflows` で確かめる）。`dependency-scan.yml` は public なので `upload-sarif` を渡さない。
- [ ] **Step 2:** `AGENTS.md` を英語で書く。目的、`~/git/AGENTS.md` の GitHub 規約に従うこと、秘密は 1Password の `ansible` vault にだけ置いてデプロイ時に `scripts/deploy.sh` が読むこと、検証コマンド、`docs/setup.md` への案内。README は作らない（言語を所有者に聞いていないため）。
- [ ] **Step 3:** `tests/test_smoke.py` に `test_load_template_reads_short_form_tags` を書く。`!Ref Foo` と `!Sub "a-${B}"` を含む一時 YAML を読んで、値がそれぞれ `"Foo"` と `"a-${B}"` になることを確かめる。
- [ ] **Step 4:** `XDG_CONFIG_HOME=$(mktemp -d /tmp/uvcfg.XXXXXX) uv lock`、`uv run pytest -q`（PASS）、pre-commit（PASS）。
- [ ] **Step 5:** commit `chore: scaffold the repository and CI`

### Task 2: CloudFormation テンプレート

**Files:**
- Create: `infra/template.yaml`
- Test: `tests/test_template.py`

**Interfaces:**
- Consumes: `tests/cfn.py` の `load_template`。
- Produces: パラメータ `OriginVerifyHeaderValue`（String、NoEcho）、`PentestHeaderValue`（String、NoEcho）、`OfficeCidrs`（CommaDelimitedList、NoEcho）、`HomePublicIpv4`（Default `106.163.184.9`）、`BlockManagedRules`（`"true"` / `"false"`、Default `"false"`）。
- Produces: Outputs `DistributionId`、`DistributionDomainName`、`WebAclArn`、`WebAclName`（`cloudfront-waf`）。

- [ ] **Step 1: 失敗するテストを書く**

`tests/test_template.py` に次を書く。値は Global Constraints と下の表から写す。

```python
NAMES = {"rewse.jp", "www.rewse.jp", "hass.rewse.jp", "nas.rewse.jp", "nvr.rewse.jp",
         "couchdb.rewse.jp", "litellm.rewse.jp", "teslamate.rewse.jp",
         "grafana.rewse.jp", "zabbix.rewse.jp"}

def test_distribution_serves_exactly_the_home_names(): ...      # Aliases == NAMES
def test_cache_is_disabled_and_viewer_request_is_forwarded(): ... # CachePolicyId == "4135ea2d-6df8-44a3-9df3-4b5a84be39ad", OriginRequestPolicyId == "216adef6-5c7f-47e4-b989-5492eafa07d3", AllowedMethods は 7 種
def test_origin_is_https_only_with_the_verify_header(): ...       # DomainName == "origin.rewse.jp", OriginProtocolPolicy == "https-only", OriginReadTimeout == 60, OriginCustomHeaders に HeaderName "X-Origin-Verify" と HeaderValue == Ref OriginVerifyHeaderValue
def test_origin_record_is_ipv4_only(): ...                        # RecordSet が origin.rewse.jp. の A だけで、AAAA がない
def test_secret_parameters_are_noecho(): ...                      # 3 つの秘密パラメータが NoEcho: true で Default を持たない
def test_rule_order(): ...                                        # 下の表の Name と Priority の並びと一致
def test_pentest_rule_allows_on_exact_header(): ...               # Priority 0、Action Allow、ByteMatch の header x-security-agent-pentest、PositionalConstraint EXACTLY、SearchString == Ref PentestHeaderValue
def test_hosting_provider_list_is_count(): ...                    # AnonymousIpList の RuleActionOverrides に HostingProviderIPList → Count
def test_body_size_rule_is_always_count(): ...                    # CommonRuleSet の RuleActionOverrides に SizeRestrictions_BODY → Count（BlockManagedRules に関係なく）
def test_count_phase_rule_groups_follow_parameter(): ...          # Count 段階のグループの OverrideAction が !If [BlockManagedRules, None, Count]
def test_geo_rule_only_labels(): ...                              # GeoLabel の Action が Count、RuleLabels を持つ、NOT(OR(Geo JP, IPSet Office))
def test_rate_limits(): ...                                       # RateLimitAll: Limit 3000、EvaluationWindowSec 300、AggregateKeyType IP、Block。RateLimitLogin: Limit 100、Block、scope-down は下の表のパス
def test_logs_redact_secrets(): ...                               # LoggingConfiguration の RedactedFields に x-security-agent-pentest、authorization、cookie。LogGroupName は aws-waf-logs- で始まる
def test_office_cidrs_come_from_parameter(): ...                  # IPSet の Addresses == Ref OfficeCidrs、テンプレートに自宅の WAN IP 以外の IPv4 リテラルが現れない
```

ルールの並び（Name / Priority / 動作）:

| Priority | Name | 内容 |
|---|---|---|
| 0 | AllowSecurityAgentPentest | ヘッダー一致で Allow |
| 1 | AWSManagedRulesAmazonIpReputationList | Block（OverrideAction None） |
| 2 | AWSManagedRulesAnonymousIpList | Block。`HostingProviderIPList` だけ Count |
| 3 | RateLimitLogin | 100 / 300 秒 / IP。パスが `/auth/`、`/login`、`/api/login` で始まるもの |
| 4 | RateLimitAll | 3000 / 300 秒 / IP |
| 5 | AWSManagedRulesKnownBadInputsRuleSet | `BlockManagedRules` に従う |
| 6 | AWSManagedRulesCommonRuleSet | `BlockManagedRules` に従う。`SizeRestrictions_BODY` は常に Count |
| 7 | AWSManagedRulesLinuxRuleSet | `BlockManagedRules` に従う |
| 8 | AWSManagedRulesUnixRuleSet | `BlockManagedRules` に従う |
| 9 | AWSManagedRulesPHPRuleSet | `BlockManagedRules` に従う |
| 10 | AWSManagedRulesBotControlRuleSet | InspectionLevel COMMON。`BlockManagedRules` に従う |
| 11 | GeoLabel | Count とラベル `cloudfront-waf:outside-japan-and-office` |

レートのしきい値は、2 週間のログで本人の IP の最大が 5 分あたり 1,100 件、ログイン系のパスが 11 件だったことから決めた。

- [ ] **Step 2:** `uv run pytest tests/test_template.py -q` → FAIL（テンプレートがない）。
- [ ] **Step 3: `infra/template.yaml` を書く**

リソースは `Certificate`（`rewse.jp` と `*.rewse.jp`、DNS 検証、`HostedZoneId: Z34LVKL0P9KD74`）、`OriginRecord`、`OfficeIpSet`（IPV4、Scope CLOUDFRONT）、`WebAcl`（名前 `cloudfront-waf`、DefaultAction Allow、VisibilityConfig は各ルールで CloudWatch メトリクスとサンプリングを有効）、`WafLogGroup`（`aws-waf-logs-cloudfront-waf`、保持 90 日）、`WafLogging`、`Distribution`（ViewerCertificate は SNI と `TLSv1.2_2021`、HttpVersion `http2and3`、IPV6Enabled true、PriceClass_All、ViewerProtocolPolicy `redirect-to-https`、Compress false、OriginSSLProtocols `TLSv1.2`、OriginKeepaliveTimeout 60、WebACLId は WebAcl の Arn）、`MonitoringSubscription`（追加メトリクスを有効にして、Zabbix が `OriginLatency` を読めるようにする）。公開名の DNS レコードはテンプレートに入れない（Task 3 で理由を書く）。各リソースの上に、なぜその値かを英語のコメントで書く（security-agent の書き方にそろえる）。

- [ ] **Step 4:** `uv run pytest -q` → PASS。`uv run cfn-lint infra/template.yaml` → 指摘なし。
- [ ] **Step 5:** commit `feat(infra): add the CloudFront distribution and WAF web ACL`

### Task 3: デプロイと DNS 切り替えのスクリプト

**Files:**
- Create: `scripts/deploy.sh`、`scripts/switch-dns.sh`
- Test: `tests/test_switch_dns.py`

**Interfaces:**
- Consumes: Task 2 のパラメータ名と Outputs `DistributionDomainName`。
- Produces: `scripts/deploy.sh`（引数なし）。`scripts/switch-dns.sh <cloudfront|origin> [--dry-run]`。`--dry-run` は Route 53 の ChangeBatch の JSON を標準出力に出すだけで、AWS を変えない。

DNS をテンプレートに入れない理由: 公開ゾーンの既存のレコードは手で作られていて、`AWS::Route53::RecordSet` はインポートできない。テンプレートで作り直すには一度消す必要があり、そのあいだ NXDOMAIN が最大 900 秒（SOA のネガティブキャッシュ）残る。UPSERT のバッチなら一度に置き換えられ、戻すのも同じスクリプトでできる。設計書の「Route 53 の公開レコードは CloudFormation」からの変更として、`docs/setup.md` にも書く。

- [ ] **Step 1: 失敗するテストを書く**

```python
def test_cloudfront_batch_points_every_name_at_the_distribution(): ...
#   DISTRIBUTION=d123.cloudfront.net scripts/switch-dns.sh cloudfront --dry-run の出力を json で読む。
#   Changes は 12 件、すべて UPSERT。サブドメイン 8 つ（www を含む）は CNAME で値 d123.cloudfront.net、TTL 300。
#   rewse.jp. は A と AAAA の alias、DNSName d123.cloudfront.net、HostedZoneId Z2FDTNDATAQYW2、EvaluateTargetHealth false。
def test_origin_batch_restores_todays_records(): ...
#   origin --dry-run は、hass/nas/nvr/couchdb/litellm/teslamate/grafana/zabbix を CNAME fox.rewse.jp、www を CNAME rewse.jp、
#   rewse.jp. を A 106.163.184.9 と AAAA 240f:143:f60c:1:2ecf:67ff:fe0f:f65d（TTL 300）に戻す。
def test_unknown_mode_exits_with_usage(): ...
#   引数 foo で終了コード 2、stderr に usage。
def test_blog_and_rds_names_are_never_touched(): ...
#   どちらのバッチにも blog.、-db.、rewse-pg.、rewse-my. で始まる名前がない。
```

- [ ] **Step 2:** `uv run pytest tests/test_switch_dns.py -q` → FAIL。
- [ ] **Step 3:** `scripts/switch-dns.sh` を書く。`--dry-run` でないときは、`DISTRIBUTION` が空なら `aws cloudformation describe-stacks --region us-east-1 --stack-name cloudfront-waf` の Output から読み、`aws route53 change-resource-record-sets --hosted-zone-id Z34LVKL0P9KD74` で投げ、`aws route53 wait resource-record-sets-changed` で待つ。`set -euo pipefail`。JSON の組み立ては `python3 -I -c` で行う（jq に頼らない）。
- [ ] **Step 4:** `scripts/deploy.sh` を書く。`op read` で 3 つの値を読み、`aws cloudformation deploy --region us-east-1 --stack-name cloudfront-waf --template-file infra/template.yaml --no-fail-on-empty-changeset --parameter-overrides ...` に渡す。値をエコーしない（`set -x` を使わない）。1Password の参照（item ID と field）は、スクリプトの先頭の定数に置く。Task 5 で作る項目 ID と、既存の `op://ansible/m6obpvalg7ekdi5nsf4yx6wi3q/password` を使う。オリジン検証ヘッダーの項目は Task 5 で作る。
- [ ] **Step 5:** `uv run pytest -q` と pre-commit（shellcheck を含む）→ PASS。
- [ ] **Step 6:** commit `feat: add the deploy and DNS switch scripts`

### Task 4: 運用手順

**Files:**
- Create: `docs/setup.md`

- [ ] **Step 1:** 英語で書く。前提（1Password の 3 項目、ReadOnly ではなく Admin のプロファイルが要る操作）、初回デプロイ、DNS の切り替えと戻し（`switch-dns.sh origin`）、`BlockManagedRules` を `"true"` にする手順、秘密の値を変えるときの手順（オリジン検証ヘッダーなら、`httpd_cloudfront_origin_enforce` を一時的に `false` にして適用 → 1Password を更新 → `deploy.sh` → httpd ロールを fox と hotel に適用 → `true` に戻して適用、の順。値が食い違うあいだに 403 を返さないため）、WAF ログの見方（CloudWatch Logs Insights のクエリ例をひとつ）。humanizer の §1、§2、§6、§8、§19 を見直す。
- [ ] **Step 2:** pre-commit → PASS。commit `docs: add the setup and operations runbook`

## フェーズ B: `rewse/ansible-playbooks`

各タスクの検証コマンドは、ansible-playbooks の AGENTS.md の Validation にある `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files --show-diff-on-failure` と `uv run --with pytest --with ansible-core pytest tests`。作業の前に `git pull` する。

### Task 5: 社内の出口の CIDR とオリジン検証ヘッダーを 1Password へ

**Files:**
- Modify: `inventory/group_vars/all/site.yml`
- Modify: `roles/httpd/vars/main.yml`
- Test: `tests/test_cloudfront_origin.py`

**Interfaces:**
- Produces: 1Password の項目 `Amazon Corporate Network - Egress`（field `ipv4`、カンマ区切りの 1 行。notes に、いま `site.yml` にある社内 wiki の 2 つの URL と範囲の説明を移す）。
- Produces: 1Password の項目 `Amazon CloudFront - Origin Verify`（field `password`、ランダム 48 文字以上の英数字）。
- Produces: `networks.office_public_ipv4` は、今まで通り CIDR の list。
- Produces: `httpd_cloudfront_origin_verify_token`（`roles/httpd/vars/main.yml` の Secret Reference）。

- [ ] **Step 1:** テスト `test_site_holds_no_office_cidr_literals` を書く。`site.yml` に自宅、VPC、WAN 以外の IPv4 リテラルと `w.amazon.com` が現れず、`office_public_ipv4` の値が `lookup('pipe', 'op read op://ansible/<id>/ipv4')` を `split(',')` する式であることを確かめる。FAIL を確認する。
- [ ] **Step 2:** 所有者に確認してから、`op item create` で 2 つの項目を `ansible` vault に作る。CIDR は今の `site.yml` の 27 個をそのまま入れる。`direnv exec . op read op://ansible/<id>/ipv4` で読めることを確かめる。
- [ ] **Step 3:** `site.yml` を書き換え、`httpd/vars/main.yml` に `httpd_cloudfront_origin_verify_token` を足す。`ansible -i inventory fox.rewse.jp -m debug -a "msg={{ networks.office_public_ipv4 | length }}"` が 27 を返す。
- [ ] **Step 4:** テストと pre-commit → PASS。`tests/test_privilege_hardening.py` も PASS のまま。
- [ ] **Step 5:** commit `refactor(site): read the office egress ranges from 1Password`

### Task 6: `mod_remoteip` とログ形式

**Files:**
- Create: `roles/httpd/tasks/remoteip.yml`、`roles/httpd/templates/remoteip.conf.j2`
- Modify: `roles/httpd/tasks/main.yml`（`remoteip.yml` を `httpd_remoteip` と `update` のタグで import。conf より前）、`roles/httpd/files/log-format.conf`
- Test: `tests/test_cloudfront_origin.py`、`tests/test_internet_exposure.py`

**Interfaces:**
- Produces: Apache の conf `remoteip`（`/etc/apache2/conf-available/remoteip.conf`）。`a2enmod remoteip`。
- Produces: アクセスログの第 2 欄が、本当のクライアント IP（`%a`）になる。

- [ ] **Step 1: 失敗するテストを書く**

`test_remoteip_trusts_only_cloudfront_origin_facing`: テンプレートを `ansible-core` の Jinja で、`httpd_remoteip_cloudfront_prefixes=["130.176.0.0/18"]` を与えて描画する（`roles/teslamate/tests/render_templates.yml` の方式でもよい）。`RemoteIPHeader X-Forwarded-For` があり、`RemoteIPTrustedProxy 130.176.0.0/18` があり、`RemoteIPInternalProxy` と、それ以外の `RemoteIPTrustedProxy` がないことを確かめる。

`test_log_formats_use_the_client_address`: `log-format.conf` の `vhost_combined` と `combined` が `%a` を使い、`%h` を使わないこと。`tests/test_internet_exposure.py` の `access_line` と fail2ban のフィルターのテストが、そのまま PASS すること。

- [ ] **Step 2:** FAIL を確認する。
- [ ] **Step 3:** `remoteip.yml` を書く。`ansible.builtin.uri` で `https://ip-ranges.amazonaws.com/ip-ranges.json` を取り、`service == 'CLOUDFRONT_ORIGIN_FACING'` の `ip_prefix` を `__httpd_remoteip_cloudfront_prefixes` にする（`set_fact` は実行時に計算するため）。この GET は読み取りだけなので `check_mode: false` にし、check モードでもテンプレートが描画できるようにする。取得に失敗したら、そのタスクで失敗させる（空のリストで描画しない）。`community.general.apache2_module` で remoteip を有効にし、テンプレートを置いて `a2enconf`。ハンドラーは `Restart Apache`（モジュールの追加）と `Reload Apache`。`log-format.conf` の `%h` を `%a` に変え、コメントに理由（`%h` は mod_remoteip が書き換えない接続元のため）を書き足す。
- [ ] **Step 4:** テストと pre-commit → PASS。`ansible-playbook -i inventory home-primary.yml --tags httpd_remoteip --check --diff -l fox.rewse.jp` が失敗しない。
- [ ] **Step 5:** commit `feat(httpd): restore client addresses behind CloudFront with mod_remoteip`

### Task 7: オリジン検証ヘッダー

**Files:**
- Create: `roles/httpd/tasks/cloudfront_origin.yml`、`roles/httpd/templates/cloudfront-origin.conf.j2`、`roles/httpd/defaults/main.yml`、`inventory/group_vars/home_primary/httpd.yml`、`inventory/group_vars/home_secondary/httpd.yml`
- Modify: `roles/httpd/tasks/main.yml`（`httpd_cloudfront_origin` タグで import）、`roles/httpd/templates/admin.conf.j2`、`roles/httpd/templates/status.conf.j2`、`roles/zabbix_server/templates/zabbix-api.conf.j2`
- Test: `tests/test_cloudfront_origin.py`

**Interfaces:**
- Consumes: Task 5 の `httpd_cloudfront_origin_verify_token`。
- Produces: `httpd_cloudfront_origin_enforce`（bool。`defaults/main.yml` は `false`。両方のグループの inventory でも当面 `false`）。
- Produces: 環境変数 `cloudfront_origin`（ヘッダーの値が一致したときに立つ）。

- [ ] **Step 1: 失敗するテストを書く**

```python
def test_header_is_matched_exactly_and_removed(): ...
#   描画結果に SetEnvIf X-Origin-Verify "^<token>$" cloudfront_origin と RequestHeader unset X-Origin-Verify がある。
def test_not_enforced_renders_no_require(): ...
#   enforce=false では Require が一行もない。
def test_enforced_allows_header_or_internal_networks(): ...
#   enforce=true では <Location "/"> の中の <RequireAny> に Require env cloudfront_origin と、
#   127.0.0.1、::1、home_private_ipv4、home_private_ipv6、home_public_ipv6、aws_private_ipv4、aws_public_ipv6 の Require ip がある。
#   home_public_ipv4 と office_public_ipv4 は入っていない。
def test_restricted_locations_and_with_the_origin_gate(): ...
#   admin.conf.j2、status.conf.j2、zabbix-api.conf.j2 の各 <Location> に AuthMerging And がある。
def test_hotel_gets_the_same_gate(): ...
#   roles/homeassistant_ha_secondary/meta/main.yml が httpd に依存し、
#   inventory/group_vars/home_primary/httpd.yml と home_secondary/httpd.yml の httpd_cloudfront_origin_enforce が同じ値。
```

- [ ] **Step 2:** FAIL を確認する。
- [ ] **Step 3:** 実装する。テンプレートは `security-agent-pentest.conf.j2` と同じく、`diff: false` と mode `"0640"` で置く（値を含むため）。ファイル名は `00-` を付けず、`a2enconf cloudfront-origin` で有効にする。`AuthMerging And` を足す理由（後ろの `<Location>` がオリジンの判定を置き換えないようにするため）をコメントに書く。
- [ ] **Step 4:** テストと pre-commit → PASS。`--check --diff` を fox と hotel に `--tags httpd_cloudfront_origin` で流して失敗しない。
- [ ] **Step 5:** commit `feat(httpd): gate requests on the CloudFront origin header`

### Task 8: HA の切り替えスクリプトを 443 だけに

**Files:**
- Modify: `roles/homeassistant_ha_secondary/templates/homeassistant-name-switch.j2`（`FORWARDED_PORTS=(443)`、冒頭のコメントから 80 の行を消す）
- Test: `tests/test_internet_exposure.py`

- [ ] **Step 1:** テスト `test_name_switch_moves_only_the_https_forward` を書く。テンプレートに `FORWARDED_PORTS=(443)` があり、`80` のフォワードに触れる記述がない。FAIL を確認する。
- [ ] **Step 2:** 直す。テストと pre-commit → PASS。
- [ ] **Step 3:** commit `fix(homeassistant_ha_secondary): move only the HTTPS forward on failover`

UDM で 80 のフォワードを消すのは Task 16 なので、それまでにこの変更を hotel に適用しておく（Task 13）。この変更の後、80 のフォワードは切り替わらなくなるが、その間 80 は fox の force-SSL リダイレクトにしか使われていないので影響はない。

### Task 9: UDM の WAN を CloudFront に絞る

**Files:**
- Create: `roles/udm/tasks/cloudfront.yml`、`roles/udm/vars/main.yml`、`roles/udm/defaults/main.yml`
- Modify: `roles/udm/tasks/main.yml`（`udm_cloudfront` と `update` のタグで import）
- Test: `tests/test_internet_exposure.py`

**Interfaces:**
- Consumes: UniFi の Site Manager API キー。`homeassistant_ha_secondary` と同じ 1Password の項目を、`udm/vars/main.yml` の Secret Reference として持つ。
- Produces: `udm_cloudfront_enforce`（bool、既定 `false`）。`false` のあいだはファイアウォールグループの作成と更新だけを行う。

- [ ] **Step 1: 読み取りだけで API を調べる**

`api.ui.com` のコネクター経由で、次を GET して、実際のフィールド名を確かめる。`/proxy/network/api/s/default/rest/firewallgroup`、`/proxy/network/api/s/default/rest/portforward`（ソース制限のフィールド名。たとえば `src_limiting_enabled`、`src_firewallgroup_id` があるか）、IPv6 の 443 / 80 / 11022 / 21022 を許可しているポリシー（ゾーンベースのファイアウォールのポリシーの一覧の場所）。分かったことを、このタスクの commit メッセージと `cloudfront.yml` のコメントに残す。ポートフォワードにソース制限を API から付けられないと分かったら、ここで止めて所有者に報告する（UI での手作業に切り替えるかどうかは所有者が決める）。

- [ ] **Step 2:** テスト `test_udm_cloudfront_tasks_never_touch_ssh_forwards` を書く。`cloudfront.yml` が 11022 と 21022 を参照せず、ポートフォワードをポート番号（443、80）で探していること（AGENTS.md の UniFi の規約）を確かめる。FAIL を確認する。
- [ ] **Step 3:** 実装する。`delegate_to: localhost` と `ansible.builtin.uri` で、(a) `ip-ranges.json` の `CLOUDFRONT_ORIGIN_FACING` を取得、(b) IPv4 のアドレスグループ `CloudFront origin-facing` を作るか中身を合わせる、(c) `udm_cloudfront_enforce` のときに 443 のフォワードのソースをそのグループに限る、(d) 同じく 80 のフォワードを消す、(e) 同じく fox の IPv6 への 443 / 80 の許可を消す（11022 の許可は残す）。legacy の更新は、オブジェクトを丸ごと読んで返す。check モードでも GET は `check_mode: false` で実行し、変更の API 呼び出しだけを止める。2 回目の実行で `changed=0` になるように、変更前に中身を比べる。
- [ ] **Step 4:** テストと pre-commit → PASS。`ansible-playbook -i inventory udm.yml --tags udm_cloudfront --check` が失敗しない。
- [ ] **Step 5:** commit `feat(udm): limit WAN HTTPS to CloudFront origin-facing ranges`

### Task 10: Zabbix の収集スクリプト

**Files:**
- Create: `roles/zabbix_aws/files/cloudfront_waf.sh`、`roles/zabbix_aws/files/cloudfront_waf.conf`、`roles/zabbix_aws/tasks/cloudfront_waf.yml`
- Modify: `roles/zabbix_aws/tasks/main.yml`（`zabbix_aws_cloudfront_waf` タグで import）

**Interfaces:**
- Produces: UserParameter `cloudfront_waf.sender`。トラッパーのキー `cloudfront.requests`、`cloudfront.error_rate.4xx`、`cloudfront.error_rate.5xx`、`cloudfront.origin_latency`、`waf.requests.blocked`、`waf.requests.counted`、`waf.requests.allowed`（いずれも直近 5 分の値）。

- [ ] **Step 1:** スタックのデプロイ（Task 12）の後に、alfa で `aws cloudwatch list-metrics --region us-east-1 --namespace AWS/WAFV2` と `--namespace AWS/CloudFront` を実行して、ディメンション（`WebACL`、`Rule`、`DistributionId`、`Region=Global` など）を確かめる。alfa の IAM ロールが us-east-1 の `cloudwatch:GetMetricData` を呼べることも確かめる。デプロイ前に書く場合は、このステップだけ Task 12 の後に回す。
- [ ] **Step 2:** `roles/zabbix_agent/files/ec2.sh` と同じく、GetMetricData を 1 回だけ呼んで `zabbix_sender` で一度に送るスクリプトを書く。region は `us-east-1`。値が読めないキーは送らない（AGENTS.md の Zabbix の規約）。
- [ ] **Step 3:** pre-commit（shellcheck）→ PASS。`--check --diff` を alfa に流す。
- [ ] **Step 4:** commit `feat(zabbix_aws): collect CloudFront and WAF metrics`

## フェーズ C: 本番への切り替え

各タスクは、実行の直前に所有者の確認を取る。戻し方を書いてあるとおりに実行できることを、先に確かめておく。

### Task 11: GitHub に公開する

- [ ] **Step 1:** 所有者の確認を取ってから、`gh repo create rewse/cloudfront-waf --public` を実行し、`github-push-via-fox` スキルに従って push する。新しいリポジトリなので、fox で git bundle から clone して push する。
- [ ] **Step 2:** Actions の lint、test、gitleaks、dependency-scan が緑であることを確かめる。

### Task 12: スタックをデプロイする（段階 1）

- [ ] **Step 1:** `aws sts get-caller-identity --profile admin` で Admin であることを確かめ、`AWS_PROFILE=admin scripts/deploy.sh` を実行する。`BlockManagedRules` は `"false"`。
- [ ] **Step 2:** 証明書が ISSUED、ディストリビューションが Deployed になったことを確かめる。`curl -sI --resolve hass.rewse.jp:443:<CloudFront の IP> https://hass.rewse.jp/` が 200 か 302 を返す（DNS はまだ切り替えていない）。
- 戻し方: `aws cloudformation delete-stack --region us-east-1 --stack-name cloudfront-waf`。

### Task 13: Apache を適用する（段階 2）

- [ ] **Step 1:** ansible-playbooks の Task 5〜8 の変更を、fox と hotel に `--tags httpd_remoteip,httpd_cloudfront_origin,httpd_conf,homeassistant_ha_secondary_failover` で適用する（タグ名は実在するものを確かめる）。`httpd_cloudfront_origin_enforce` は `false` のまま。
- [ ] **Step 2:** 家の外の回線（たとえばスマートフォンのテザリング）から、`curl -s -H "X-Forwarded-For: 192.168.0.10" https://rewse.jp/server-status` が 403 になることを確かめる。直接届いたリクエストの偽の `X-Forwarded-For` を、Apache が信じないことを見るため。`other_vhosts_access.log` の第 2 欄が、本当の送信元の IP になっていることも確かめる。
- 戻し方: `a2disconf remoteip cloudfront-origin && a2dismod remoteip && systemctl restart apache2` と、ansible-playbooks の revert。

### Task 14: DNS を切り替えて確かめる（段階 3）

- [ ] **Step 1:** `scripts/switch-dns.sh cloudfront --dry-run` の中身を所有者に見せてから、本番で実行する。
- [ ] **Step 2:** 設計書の「確認項目」を、上から順に確かめる（ブラウザでの確認は `browser-automation` スキルに従う）。WAF のログで、`54.64.81.21` のリクエストと、Count になったルールを確かめる。HA のフェイルオーバーの確認は、`homeassistant-name-switch standby` と `primary` を所有者の確認を取ってから実行する。
- 戻し方: `scripts/switch-dns.sh origin`。

### Task 15: オリジン検証を有効にする（段階 4）

- [ ] **Step 1:** 両方のグループの inventory で `httpd_cloudfront_origin_enforce: true` にして commit し、fox と hotel に適用する。
- [ ] **Step 2:** 家の外の回線から `curl -sk --resolve hass.rewse.jp:443:106.163.184.9 https://hass.rewse.jp/` が 403、CloudFront 経由が 200 であることを確かめる。家の中と alfa からの直接のアクセスが今まで通り通ることも確かめる。
- 戻し方: `false` に戻して適用する。

### Task 16: UDM を閉じる（段階 5）

- [ ] **Step 1:** `udm_cloudfront_enforce: true` にして、`udm.yml` を `--tags udm_cloudfront` で適用する。
- [ ] **Step 2:** 家の外の回線から、`106.163.184.9` の 443 と 80、fox の IPv6 の 443 と 80 に TCP でつながらないことを確かめる（`nc -vz -w 5`）。11022 と 21022 には今まで通りつながる。CloudFront 経由で 10 個の名前すべてが開ける。
- 戻し方: UniFi の UI で、443 のフォワードのソース制限を外し、80 のフォワードと IPv6 の許可を作り直す。消す前に、元のオブジェクトの JSON を `/tmp` の実行ディレクトリに保存しておく。

### Task 17: Zabbix のアイテムとトリガー

- [ ] **Step 1:** Task 10 のスクリプトを alfa に適用し、Zabbix にトラッパーアイテム（Task 10 のキー）とトリガーを直接作る。トリガーは、`cloudfront.error_rate.5xx` の 15 分平均が 5% を超えたら High、`waf.requests.blocked` が 5 分で 500 を超えたら Warning、`cloudfront.requests` が 30 分届かなければ Warning。作ったら `zabbix-server` を再起動する（AGENTS.md の Zabbix の規約）。
- [ ] **Step 2:** 値が届いていることを Zabbix の Latest data で確かめる。

### Task 18: Block に切り替える（段階 6）

- [ ] **Step 1:** 段階 3 から 1〜2 週間後、WAF のログで Count のルールに当たったリクエストを洗い、本人の利用や連携に当たったルールを `RuleActionOverrides` で Count に残すか、scope-down で外す。テストを足して `infra/template.yaml` を直す。
- [ ] **Step 2:** `infra/parameters.json` の `BlockManagedRules` を `"true"` にし、`infra/template.yaml` の Default もそろえて commit する。`aws cloudformation deploy` は渡されないパラメータの前の値を使い続けるので、Default を変えるだけではスタックに届かない。所有者の確認を取ってから `scripts/deploy.sh` を実行する。設計書の確認項目を、もう一度通す。
- [ ] **Step 3:** security-agent の自宅サービス向けのオンデマンドのペンテストを、所有者の確認を取ってから回し、WAF に止められずに最後まで走ることを確かめる。
- 戻し方: `infra/parameters.json` とテンプレートの Default の `BlockManagedRules` を `"false"` に戻してデプロイする。
