# Real-world validation

Fixtures prove that rules detect what they claim. To measure **noise**, stellar-guard is also run
on well-reviewed public Soroban code where most findings are expected to be intentional patterns.
This page records the results so precision regressions are visible.

| Repository | Commit | Files | warning | info |
|---|---|---|---|---|
| [stellar/soroban-examples](https://github.com/stellar/soroban-examples) | `03d42aa` (2026-10-06) | 112 | 3 | 37 |
| [OpenZeppelin/stellar-contracts](https://github.com/OpenZeppelin/stellar-contracts) | `ddc327e` (2026-10-20) | 257 | 25 | 28 |

Command: `stellar-guard scan <repo> --no-config` (defaults: tests excluded, all rules).

## soroban-examples, per rule

| Rule | warning | info | Notes |
|---|---|---|---|
| SG-001 | 1 | 9 | warning: `merkle_distribution::claim` sends tokens without `require_auth` (gated by a Merkle proof instead, a typical "review and suppress" case). info: public demo counters such as `increment`. |
| SG-002 | 2 | 0 | `account`: `DataKey::SpendLimit(token)` and `merkle_distribution`: `DataKey::Claimed(index)` written to instance storage; the latter grows with every claim. |
| SG-003 | 0 | 23 | All in crates with `overflow-checks = true`, so they are informational. |
| SG-004 | 0 | 5 | Caller-supplied vectors (proofs, swap lists). |
| SG-005 | 0 | 0 | |

## OpenZeppelin stellar-contracts, per rule

| Rule | warning | info |
|---|---|---|
| SG-001 | 5 | 3 |
| SG-002 | 6 | 0 |
| SG-003 | 0 | 22 |
| SG-004 | 14 | 3 |
| SG-005 | 0 | 0 |

The remaining SG-004 warnings are loops over stored lists where any size cap is not visible by
variable name (see the rule's limitations). SG-001 warnings are permissionless functions in example
contracts (e.g. a Merkle airdrop `claim`, a lazy-upgrade demo).

## Precision fixes driven by this exercise

* Storage-key words come from the key's own name, not from values passed into it.
* Same-named local variables in different `match` arms resolve to the right initializer.
* Submodules of `#[cfg(test)] mod test;` directories are excluded.
* Casts of range-checked values (`if amount > 0 { amount as u128 }`) are not reported.
* Caller-supplied loop sizes and plain public counters are reported as `info`.
* Stored collections capped where they grow are not reported by SG-004.
* `__constructor` writes and parameters are treated as deployer-controlled.

To reproduce, clone the repositories at the listed commits and run the command above.
