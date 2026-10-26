# Security policy

## Scope

This policy covers vulnerabilities in **stellar-guard itself**, for example a crafted source file
that makes the scanner execute code, write outside the requested output path, or crash in a way that
hides findings.

Missed detections (false negatives) and false positives are **not** security vulnerabilities in
stellar-guard: stellar-guard is a heuristic tool and never guarantees that a contract is secure.
Please report those as regular issues.

## Reporting

Please **do not** open a public issue for a vulnerability. Use GitHub's
[private vulnerability reporting](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/security/advisories/new)
with a description, reproduction steps and the affected version.

You can expect an acknowledgement within 5 working days. We will agree a disclosure timeline with
you and credit you in the advisory unless you prefer otherwise.

## Supported versions

Security fixes are released for the latest minor version.

## Vulnerabilities in your contracts

If stellar-guard flags a real vulnerability in a deployed contract, follow that project's own
disclosure process. Do not post exploit details publicly.
