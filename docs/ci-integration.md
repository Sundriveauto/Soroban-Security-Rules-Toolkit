# CI integration

## GitHub Actions (recommended)

```yaml
# .github/workflows/stellar-guard.yml
name: stellar-guard
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # upload SARIF to code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: petermuazu/Soroban-Security-Rules-Toolkit/integrations/github-action@v0.1.0
        with:
          path: contracts
          fail-on: warning
```

This:

1. installs stellar-guard (built from source and cached, or a prebuilt binary with `version:`),
2. annotates the pull request diff,
3. writes a findings table to the job summary,
4. uploads SARIF so findings appear under **Security → Code scanning**,
5. fails the job when a finding meets `fail-on`.

All inputs are documented in [the action README](../integrations/github-action/README.md). A
complete example is in [examples/stellar-guard.yml](examples/stellar-guard.yml).

> Pull requests from forks get a read-only token, so SARIF upload is not allowed there. Set
> `upload-sarif: ${{ github.event.pull_request.head.repo.fork == false }}` to skip it for forks.

## Any other CI

Install and run the binary; use the exit code.

```sh
cargo install --locked --git https://github.com/petermuazu/Soroban-Security-Rules-Toolkit guard-cli
stellar-guard scan contracts --fail-on warning --format sarif --output stellar-guard.sarif
```

GitLab CI example:

```yaml
stellar-guard:
  image: rust:1
  script:
    - cargo install --locked --git https://github.com/petermuazu/Soroban-Security-Rules-Toolkit guard-cli
    - stellar-guard scan contracts --format json --output stellar-guard.json
  artifacts:
    when: always
    paths: [stellar-guard.json]
```

## Adopting on an existing codebase

1. Run once with `--fail-on never` and review the findings.
2. Fix what is real; suppress intentional patterns inline with a reason
   (`// stellar-guard-ignore SG-001 -- <reason>`).
3. Commit a `stellar-guard.toml` (`stellar-guard init`) with any project-specific
   `auth-functions` or rule options.
4. Switch CI to `--fail-on warning` (or start with `--fail-on error`).
