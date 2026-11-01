# cloudfront-waf

## Purpose

cloudfront-waf is a CloudFormation stack that puts CloudFront and AWS WAF in front of the home services on fox, plus the scripts that deploy and operate it. [README.md](README.md) describes how it works and the routine operations, and [docs/setup.md](docs/setup.md) deploys it and cuts the names over. The Apache and UDM side is in `rewse/ansible-playbooks`.

## Conventions

- Follow the GitHub configuration rules in `~/git/AGENTS.md` for everything under `.github` and `.pre-commit-config.yaml`.
- Keep secrets in the 1Password `ansible` vault only. `scripts/deploy.sh` reads them at deploy time; never write them to the repository, logs, or terminal output.
- This repository is public. Name no public address other than those `tests/test_public_repository.py` allows.

## Validation

- `uv run pytest -q`
- `uv run cfn-lint infra/deploy-role.yaml infra/template.yaml`
- `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`
