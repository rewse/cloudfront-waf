# cloudfront-waf

A CloudFormation stack that puts CloudFront and AWS WAF in front of home services, plus the scripts that deploy and operate it.

## Conventions

- Follow the GitHub configuration rules in `~/git/AGENTS.md` for everything under `.github` and `.pre-commit-config.yaml`.
- Keep secrets in the 1Password `ansible` vault only. `scripts/deploy.sh` reads them at deploy time; never write them to the repository, logs, or terminal output.
- Do not create a README until the owner has chosen its language.

## Validation

- `uv run pytest -q`
- `uv run cfn-lint infra/template.yaml`
- `uvx --with pre-commit-uv==4.3.0 pre-commit@4.6.2 run --all-files`

## Documentation

Setup steps live in `docs/setup.md`.
