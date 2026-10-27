# Report formats and exit codes

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no finding at or above `--fail-on` |
| `1` | Scan completed; at least one finding at or above `--fail-on` |
| `2` | Error: bad arguments or config, unknown rule, path not found, no Rust files found, write failure |

Files that fail to parse do **not** change the exit code; they are listed in the report
(`parse_failures`) and as warnings in text output.

## Severity and confidence

* **Severity** (`info` < `warning` < `error`) is how bad the issue would be if real. Set per rule via
  config or `--severity`; some rules lower it for specific findings (SG-003 reports `info` when
  `overflow-checks = true`) unless you set an explicit override.
* **Confidence** (`low` < `medium` < `high`) is how likely the finding is a true positive. Filter
  with `--min-confidence`.

## JSON (`--format json`)

Schema version `1.0`, described by the JSON Schema [`report.schema.json`](report.schema.json)
(`$id`: `https://raw.githubusercontent.com/petermuazu/Soroban-Security-Rules-Toolkit/main/docs/report.schema.json`).
Fields are only added in minor versions, so ignore properties you do not know; a breaking change
bumps the major `schema_version`. A test checks every report against the schema.

```json
{
  "schema_version": "1.0",
  "disclaimer": "stellar-guard reports potential issues … does not prove a contract is secure.",
  "tool": { "name": "stellar-guard", "version": "0.1.0" },
  "summary": {
    "files_scanned": 5,
    "errors": 1,
    "warnings": 17,
    "infos": 0,
    "suppressed": 0,
    "parse_failures": 0
  },
  "findings": [
    {
      "rule_id": "SG-001",
      "rule_name": "missing-authorization",
      "severity": "warning",
      "confidence": "high",
      "message": "Exported function `withdraw` transfers tokens out of the contract without an authorization check",
      "help": "Review whether this operation requires `address.require_auth()` …",
      "location": {
        "file": "fixtures/vulnerable-examples/missing-auth/src/lib.rs",
        "start_line": 57,
        "start_column": 16,
        "end_line": 57,
        "end_column": 24
      },
      "snippet": "        client.transfer(&env.current_contract_address(), &user, &amount);",
      "function": "withdraw",
      "fingerprint": "5f0c2d6a9b1e4f37",
      "help_uri": "https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-001.md"
    }
  ],
  "parse_failures": [
    { "file": "src/broken.rs", "line": 3, "column": 1, "message": "expected `;`" }
  ],
  "rules": [
    {
      "id": "SG-001", "name": "missing-authorization", "summary": "…", "description": "…",
      "remediation": "…", "severity": "warning", "tags": ["security"], "help_uri": "…"
    }
  ]
}
```

* Lines and columns are 1-based; columns count Unicode characters.
* `file` is relative to the current working directory when the file is below it, otherwise the
  path as given, always with `/` separators.
* `fingerprint` does not include the line number, so it stays stable when code above moves. It
  changes if the line's content (ignoring whitespace), the function, the file path or the rule
  changes.
* `rules` lists the rules that ran, with their effective severity.
* Findings are sorted by file, line, column, rule. Output is byte-for-byte reproducible.

## SARIF (`--format sarif`)

SARIF 2.1.0, suitable for `github/codeql-action/upload-sarif`:

* `tool.driver.rules[]` carries `shortDescription`, `fullDescription`, `help`, `helpUri`,
  `defaultConfiguration.level` and `properties.security-severity` (error 8.0, warning 5.5, info 2.0)
  so GitHub can rank alerts.
* `results[]` use `level` `error` / `warning` / `note`, `%SRCROOT%`-relative artifact URIs, region
  with snippet, `logicalLocations` (function), `partialFingerprints["stellarGuardFingerprint/v1"]`
  and `properties.confidence`.
* Parse failures are reported as `invocations[0].toolExecutionNotifications`.

Run the scan from the repository root so artifact paths match the repository layout.

## GitHub annotations (`--format github`)

One workflow command per finding:

```
::warning file=src/lib.rs,line=57,col=16,endLine=57,endColumn=24,title=SG-001 missing-authorization::Exported function …
```

## Markdown (`--format markdown`)

A summary table for `$GITHUB_STEP_SUMMARY` or a PR comment.

## Multiple outputs in one run

```sh
stellar-guard scan contracts \
  --format github \
  --report sarif=stellar-guard.sarif \
  --report markdown="$GITHUB_STEP_SUMMARY"
```
