"""Checks on infra/deploy-role.yaml, the role that deploys the stack."""

from pathlib import Path
from typing import Any

from tests.cfn import load_template

TEMPLATE_PATH = Path(__file__).parent.parent / "infra" / "deploy-role.yaml"


def _role() -> dict[str, Any]:
    return load_template(TEMPLATE_PATH)["Resources"]["DeployRole"]["Properties"]


def test_only_tats_and_the_admin_role_may_assume_it() -> None:
    statements = _role()["AssumeRolePolicyDocument"]["Statement"]

    assert len(statements) == 1
    assert statements[0]["Action"] == "sts:AssumeRole"
    assert set(statements[0]["Principal"]["AWS"]) == {
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/Admin",
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:user/tats",
    }


def test_it_holds_full_access_to_each_service_in_the_stack() -> None:
    managed = {arn.rsplit("/", 1)[-1] for arn in _role()["ManagedPolicyArns"]}

    assert managed == {
        "AWSCertificateManagerFullAccess",
        "AWSCloudFormationFullAccess",
        "AWSWAFFullAccess",
        "AmazonRoute53FullAccess",
        "CloudFrontFullAccess",
        "CloudWatchLogsFullAccess",
        "ReadOnlyAccess",
    }


def test_it_has_no_inline_policies() -> None:
    assert "Policies" not in _role()
