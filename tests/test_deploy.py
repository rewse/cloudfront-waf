"""Tests for scripts/deploy.sh with op and aws replaced by stubs."""

import json
import os
import subprocess
from pathlib import Path

from tests.cfn import load_template

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "deploy.sh"
PARAMETERS = ROOT / "infra" / "parameters.json"
TEMPLATE = ROOT / "infra" / "template.yaml"
SECRETS = {
    "OfficeCidrs": "192.0.2.0/24,198.51.100.0/24",
    "OriginVerifyHeaderValue": "fake-origin-secret",
    "PentestHeaderValue": "fake-pentest-secret",
}
OP_VALUES = {
    "op://ansible/kgap2pevj7exae5jnvlsewbs7y/password": SECRETS[
        "OriginVerifyHeaderValue"
    ],
    "op://ansible/m6obpvalg7ekdi5nsf4yx6wi3q/password": SECRETS["PentestHeaderValue"],
    "op://ansible/rocgj7m2grqpdwb4gvcqbktvhm/ipv4": SECRETS["OfficeCidrs"],
}


def _run_deploy(tmp_path: Path) -> tuple[subprocess.CompletedProcess[str], str, list]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    values = tmp_path / "op-values.json"
    values.write_text(json.dumps(OP_VALUES))
    op = bin_dir / "op"
    op.write_text(
        "#!/bin/sh\n"
        '[ "$1" = read ] && [ "$2" = -n ] || exit 1\n'
        f"exec python3 -I -c 'import json, sys; "
        f'sys.stdout.write(json.load(open("{values}"))[sys.argv[1]])\' "$3"\n'
    )
    argv = tmp_path / "aws-argv.txt"
    overrides = tmp_path / "overrides.json"
    aws = bin_dir / "aws"
    aws.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{argv}"\n'
        'for arg in "$@"; do\n'
        '  case "$arg" in file://*) '
        f'cp "${{arg#file://}}" "{overrides}" ;; esac\n'
        "done\n"
    )
    for stub in (op, aws):
        stub.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    result = subprocess.run(
        [str(SCRIPT)], capture_output=True, text=True, env=env, check=False
    )
    passed = json.loads(overrides.read_text()) if overrides.exists() else []
    return result, argv.read_text() if argv.exists() else "", passed


def test_deploy_passes_committed_parameters_and_secrets(tmp_path: Path) -> None:
    result, argv, overrides = _run_deploy(tmp_path)

    assert result.returncode == 0, result.stderr
    committed = json.loads(PARAMETERS.read_text())
    expected = {**SECRETS, **committed}
    assert dict(item.split("=", 1) for item in overrides) == expected
    for value in SECRETS.values():
        assert value not in argv
        assert value not in result.stdout + result.stderr


def test_committed_parameters_are_every_non_secret_parameter() -> None:
    parameters = load_template(TEMPLATE)["Parameters"]
    committed = json.loads(PARAMETERS.read_text())

    assert sorted(committed) == sorted(set(parameters) - set(SECRETS))
    for name, value in committed.items():
        assert isinstance(value, str), name
        # The template default only documents the value; the file is what
        # every deploy sends.
        assert parameters[name]["Default"] == value, name
