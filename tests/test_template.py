"""Checks on infra/template.yaml against the design's fixed values."""

import re
from pathlib import Path
from typing import Any

import pytest

from tests.cfn import load_template

TEMPLATE_PATH = Path(__file__).parent.parent / "infra" / "template.yaml"

NAMES = {
    "couchdb.rewse.jp",
    "expense.rewse.jp",
    "grafana.rewse.jp",
    "hass.rewse.jp",
    "litellm.rewse.jp",
    "mail-mcp.rewse.jp",
    "nas.rewse.jp",
    "nvr.rewse.jp",
    "rewse.jp",
    "teslamate.rewse.jp",
    "www.rewse.jp",
    "zabbix.rewse.jp",
    "zabbix-mcp.rewse.jp",
}

RULE_ORDER = [
    "AllowSecurityAgentPentest",
    "FragmentInPath",
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
    "RateLimitLogin",
    "RateLimitZabbixApi",
    "RateLimitAll",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesLinuxRuleSet",
    "AWSManagedRulesUnixRuleSet",
    "AWSManagedRulesPHPRuleSet",
    "AWSManagedRulesBotControlRuleSet",
    "GeoLabel",
]

COUNT_PHASE_RULE_GROUPS = [
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
    "AWSManagedRulesBotControlRuleSet",
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesLinuxRuleSet",
    "AWSManagedRulesPHPRuleSet",
    "AWSManagedRulesUnixRuleSet",
]

IPV4_LITERAL = re.compile(r"(?<![\d.v])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d.])")

SECRET_PARAMETERS = ["OfficeCidrs", "OriginVerifyHeaderValue", "PentestHeaderValue"]

# Decoding and normalizing before matching makes spellings such as
# /%61uth/, //auth/, and /./auth/ count against the same limit as /auth/.
PATH_TRANSFORMATIONS = [
    {"Priority": 0, "Type": "URL_DECODE"},
    {"Priority": 1, "Type": "NORMALIZE_PATH"},
    {"Priority": 2, "Type": "LOWERCASE"},
]

# Sign-in prefixes of RateLimitLogin in one anchored regex, which costs fewer
# WCU than one transformed byte match per prefix. Zabbix also serves its
# login form at the bare directory URL, so /zabbix/ and /zabbix match as
# whole paths while other pages under /zabbix/ do not.
LOGIN_PATH_REGEX = r"^/(?:auth/|login|api/(?:auth/|login)|zabbix(?:/index|/?$))"


@pytest.fixture(scope="module")
def template() -> dict[str, Any]:
    return load_template(TEMPLATE_PATH)


def _resources_of_type(template: dict[str, Any], type_: str) -> list[dict[str, Any]]:
    return [r for r in template["Resources"].values() if r["Type"] == type_]


def _only_resource(template: dict[str, Any], type_: str) -> dict[str, Any]:
    resources = _resources_of_type(template, type_)
    assert len(resources) == 1
    return resources[0]


def _distribution_config(template: dict[str, Any]) -> dict[str, Any]:
    distribution = _only_resource(template, "AWS::CloudFront::Distribution")
    return distribution["Properties"]["DistributionConfig"]


def _rules(template: dict[str, Any]) -> dict[str, dict[str, Any]]:
    web_acl = _only_resource(template, "AWS::WAFv2::WebACL")
    return {rule["Name"]: rule for rule in web_acl["Properties"]["Rules"]}


def _action_overrides(rule: dict[str, Any]) -> dict[str, dict[str, Any]]:
    overrides = rule["Statement"]["ManagedRuleGroupStatement"]["RuleActionOverrides"]
    return {o["Name"]: o["ActionToUse"] for o in overrides}


def _logical_id(template: dict[str, Any], type_: str) -> str:
    ids = [k for k, v in template["Resources"].items() if v["Type"] == type_]
    assert len(ids) == 1
    return ids[0]


def test_distribution_serves_exactly_the_home_names(
    template: dict[str, Any],
) -> None:
    aliases = _distribution_config(template)["Aliases"]

    assert len(aliases) == len(NAMES)
    assert set(aliases) == NAMES


def test_cache_is_disabled_and_viewer_request_is_forwarded(
    template: dict[str, Any],
) -> None:
    behavior = _distribution_config(template)["DefaultCacheBehavior"]

    assert behavior["CachePolicyId"] == "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    assert behavior["OriginRequestPolicyId"] == "216adef6-5c7f-47e4-b989-5492eafa07d3"
    assert set(behavior["AllowedMethods"]) == {
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "POST",
        "PUT",
    }


def test_origin_is_https_only_with_the_verify_header(
    template: dict[str, Any],
) -> None:
    (origin,) = _distribution_config(template)["Origins"]
    custom = origin["CustomOriginConfig"]

    assert origin["DomainName"] == "origin.rewse.jp"
    assert custom["OriginProtocolPolicy"] == "https-only"
    assert custom["OriginReadTimeout"] == 60
    assert {
        "HeaderName": "X-Origin-Verify",
        "HeaderValue": "OriginVerifyHeaderValue",
    } in (origin["OriginCustomHeaders"])


def test_origin_record_is_ipv4_only(template: dict[str, Any]) -> None:
    records = _resources_of_type(template, "AWS::Route53::RecordSet")

    assert [(r["Properties"]["Name"], r["Properties"]["Type"]) for r in records] == [
        ("origin.rewse.jp.", "A")
    ]
    assert records[0]["Properties"]["ResourceRecords"] == ["HomePublicIpv4"]
    assert template["Parameters"]["HomePublicIpv4"]["Default"] == "106.163.184.9"


def test_secret_parameters_are_noecho(template: dict[str, Any]) -> None:
    parameters = template["Parameters"]

    for name in SECRET_PARAMETERS:
        assert parameters[name]["NoEcho"] is True, name
        assert "Default" not in parameters[name], name
    assert parameters["OfficeCidrs"]["Type"] == "CommaDelimitedList"


def test_rule_order(template: dict[str, Any]) -> None:
    web_acl = _only_resource(template, "AWS::WAFv2::WebACL")
    rules = web_acl["Properties"]["Rules"]

    assert [(r["Priority"], r["Name"]) for r in rules] == list(enumerate(RULE_ORDER))


def test_pentest_rule_allows_on_exact_header(template: dict[str, Any]) -> None:
    rule = _rules(template)["AllowSecurityAgentPentest"]
    match = rule["Statement"]["ByteMatchStatement"]

    assert rule["Priority"] == 0
    assert rule["Action"] == {"Allow": {}}
    assert match["FieldToMatch"] == {
        "SingleHeader": {"Name": "x-security-agent-pentest"}
    }
    assert match["PositionalConstraint"] == "EXACTLY"
    assert match["SearchString"] == "PentestHeaderValue"


def test_fragment_in_path_is_counted(template: dict[str, Any]) -> None:
    rule = _rules(template)["FragmentInPath"]
    match = rule["Statement"]["ByteMatchStatement"]

    # Counts until the logs show no false positives; then switch to Block.
    assert rule["Action"] == {"Count": {}}
    assert match["FieldToMatch"] == {"UriPath": {}}
    assert match["PositionalConstraint"] == "CONTAINS"
    assert match["SearchString"] == "#"
    assert match["TextTransformations"] == [{"Priority": 0, "Type": "NONE"}]
    assert rule["VisibilityConfig"] == {
        "CloudWatchMetricsEnabled": True,
        "MetricName": "FragmentInPath",
        "SampledRequestsEnabled": True,
    }


def test_hosting_provider_list_is_count(template: dict[str, Any]) -> None:
    rule = _rules(template)["AWSManagedRulesAnonymousIpList"]

    # A plain mapping, not an !If on BlockManagedRules, so the rule counts
    # whether or not the group blocks.
    assert _action_overrides(rule) == {"HostingProviderIPList": {"Count": {}}}


def test_common_rule_set_overrides_are_always_count(template: dict[str, Any]) -> None:
    rule = _rules(template)["AWSManagedRulesCommonRuleSet"]

    # Large bodies come from webhooks, CouchDB, and nas uploads; requests
    # without a User-Agent from rare callers such as Alexa and Tesla.
    assert _action_overrides(rule) == {
        "NoUserAgent_HEADER": {"Count": {}},
        "SizeRestrictions_BODY": {"Count": {}},
    }


def test_bot_control_api_client_rules_are_always_count(
    template: dict[str, Any],
) -> None:
    rule = _rules(template)["AWSManagedRulesBotControlRuleSet"]

    # Home Assistant webhooks arrive from Go-http-client, and Alexa and Tesla
    # call too rarely for the count period to show them. The other two
    # categories match link previews and Hatena fetching old rewse.jp links.
    assert _action_overrides(rule) == {
        "CategoryHttpLibrary": {"Count": {}},
        "CategoryScrapingFramework": {"Count": {}},
        "CategorySocialMedia": {"Count": {}},
        "SignalNonBrowserUserAgent": {"Count": {}},
    }


def test_count_phase_rule_groups_follow_parameter(template: dict[str, Any]) -> None:
    rules = _rules(template)

    for name in COUNT_PHASE_RULE_GROUPS:
        condition, if_true, if_false = rules[name]["OverrideAction"]
        assert template["Conditions"][condition] == [
            "BlockManagedRules",
            "true",
        ], name
        assert if_true == {"None": {}}, name
        assert if_false == {"Count": {}}, name
    parameter = template["Parameters"]["BlockManagedRules"]
    assert parameter["AllowedValues"] == ["true", "false"]
    assert parameter["Default"] == "true"


def test_bot_control_inspects_common_level(template: dict[str, Any]) -> None:
    statement = _rules(template)["AWSManagedRulesBotControlRuleSet"]["Statement"]

    assert statement["ManagedRuleGroupStatement"]["ManagedRuleGroupConfigs"] == [
        {"AWSManagedRulesBotControlRuleSet": {"InspectionLevel": "COMMON"}}
    ]


def test_geo_rule_only_labels(template: dict[str, Any]) -> None:
    rule = _rules(template)["GeoLabel"]
    ip_set_id = _logical_id(template, "AWS::WAFv2::IPSet")

    assert rule["Action"] == {"Count": {}}
    assert rule["RuleLabels"] == [{"Name": "cloudfront-waf:outside-japan-and-office"}]
    assert rule["Statement"] == {
        "NotStatement": {
            "Statement": {
                "OrStatement": {
                    "Statements": [
                        {"GeoMatchStatement": {"CountryCodes": ["JP"]}},
                        {"IPSetReferenceStatement": {"Arn": f"{ip_set_id}.Arn"}},
                    ]
                }
            }
        }
    }


def test_rate_limits(template: dict[str, Any]) -> None:
    rules = _rules(template)
    rate_all = rules["RateLimitAll"]["Statement"]["RateBasedStatement"]
    rate_login = rules["RateLimitLogin"]["Statement"]["RateBasedStatement"]

    assert rate_all["Limit"] == 3000
    assert rate_all["EvaluationWindowSec"] == 300
    assert rate_all["AggregateKeyType"] == "IP"
    assert "ScopeDownStatement" not in rate_all
    assert rules["RateLimitAll"]["Action"] == {"Block": {}}
    assert rate_login["Limit"] == 100
    assert rate_login["EvaluationWindowSec"] == 300
    assert rate_login["AggregateKeyType"] == "IP"
    assert rules["RateLimitLogin"]["Action"] == {"Block": {}}
    match = rate_login["ScopeDownStatement"]["RegexMatchStatement"]
    assert match["FieldToMatch"] == {"UriPath": {}}
    assert match["RegexString"] == LOGIN_PATH_REGEX
    assert match["TextTransformations"] == PATH_TRANSFORMATIONS


# The transformations run before the regex, so the samples are already
# decoded, normalized, and lowercased. The regex keeps the prefix semantics
# of STARTS_WITH, so /loginx matches as /login does. NORMALIZE_PATH may or
# may not keep a trailing slash, so //zabbix// and /Zabbix/ reach the regex
# as either /zabbix/ or /zabbix, and both must match.
@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/", False),
        ("/api/auth/login", True),
        ("/api/login", True),
        ("/api/other", False),
        ("/auth/x", True),
        ("/grafana/login", False),
        ("/login", True),
        ("/loginx", True),
        ("/zabbix", True),
        ("/zabbix/", True),
        ("/zabbix/api_jsonrpc.php", False),
        ("/zabbix/index.php", True),
        ("/zabbix/index_mfa.php", True),
        ("/zabbix/zabbix.php", False),
        ("/zabbixx", False),
        ("/zabbix//x", False),
    ],
)
def test_login_path_regex_matches_prefixes(
    template: dict[str, Any], path: str, expected: bool
) -> None:
    rate_login = _rules(template)["RateLimitLogin"]["Statement"]["RateBasedStatement"]
    regex = rate_login["ScopeDownStatement"]["RegexMatchStatement"]["RegexString"]

    assert bool(re.search(regex, path)) is expected


def test_zabbix_api_rate_limit(template: dict[str, Any]) -> None:
    rule = _rules(template)["RateLimitZabbixApi"]
    rate = rule["Statement"]["RateBasedStatement"]
    assert rule["Action"] == {"Block": {}}
    assert rate["Limit"] == 300
    assert rate["EvaluationWindowSec"] == 300
    assert rate["AggregateKeyType"] == "IP"
    match = rate["ScopeDownStatement"]["ByteMatchStatement"]
    assert match["FieldToMatch"] == {"UriPath": {}}
    assert match["PositionalConstraint"] == "STARTS_WITH"
    assert match["SearchString"] == "/zabbix/api_jsonrpc.php"
    assert match["TextTransformations"] == PATH_TRANSFORMATIONS


def test_logs_redact_secrets(template: dict[str, Any]) -> None:
    logging = _only_resource(template, "AWS::WAFv2::LoggingConfiguration")
    log_group = _only_resource(template, "AWS::Logs::LogGroup")
    redacted = {
        field["SingleHeader"]["Name"]
        for field in logging["Properties"]["RedactedFields"]
    }

    assert {"authorization", "cookie", "x-security-agent-pentest"} <= redacted
    assert log_group["Properties"]["LogGroupName"].startswith("aws-waf-logs-")
    assert logging["Properties"]["LogDestinationConfigs"] == [
        "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:"
        + log_group["Properties"]["LogGroupName"]
    ]


def test_office_cidrs_come_from_parameter(template: dict[str, Any]) -> None:
    ip_set = _only_resource(template, "AWS::WAFv2::IPSet")

    assert ip_set["Properties"]["Addresses"] == "OfficeCidrs"
    # The home WAN address is public in DNS; any other IPv4 literal would be
    # an egress range that belongs in 1Password.
    assert set(IPV4_LITERAL.findall(TEMPLATE_PATH.read_text())) == {"106.163.184.9"}


def test_every_rule_emits_metrics_and_samples(template: dict[str, Any]) -> None:
    web_acl = _only_resource(template, "AWS::WAFv2::WebACL")
    configs = [web_acl["Properties"]["VisibilityConfig"]] + [
        rule["VisibilityConfig"] for rule in web_acl["Properties"]["Rules"]
    ]

    for config in configs:
        assert config["CloudWatchMetricsEnabled"] is True
        assert config["SampledRequestsEnabled"] is True
