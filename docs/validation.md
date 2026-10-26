# Real-world validation

Fixtures prove that rules detect what they claim. To measure **noise**, stellar-guard is also run
on well-reviewed public Soroban code where most findings are expected to be intentional patterns.
This page records the results so precision regressions are visible.

| Repository | Commit | Files | error | warning | info |
|---|---|---|---|---|---|
| [stellar/soroban-examples](https://github.com/stellar/soroban-examples) | `03d42aa` (2026-10-06) | 109 | 0 | 3 | 59 |
| [OpenZeppelin/stellar-contracts](https://github.com/OpenZeppelin/stellar-contracts) | `ddc327e` (2026-10-20) | 257 | 0 | 23 | 35 |

Command: `stellar-guard scan <repo> --no-config` (defaults: tests excluded, all rules).
soroban-examples counts 109 files since `#![cfg(test)]` files and cargo-fuzz targets are excluded
as test code.

## soroban-examples, per rule

| Rule | warning | info | Notes |
|---|---|---|---|
| SG-001 | 1 | 9 | warning: `merkle_distribution::claim` sends tokens without `require_auth` (gated by a Merkle proof instead, a typical "review and suppress" case). info: public demo counters such as `increment`. |
| SG-002 | 2 | 0 | `account`: `DataKey::SpendLimit(token)` and `merkle_distribution`: `DataKey::Claimed(index)` written to instance storage; the latter grows with every claim. |
| SG-003 | 0 | 26 | All in crates with `overflow-checks = true`, so they are informational. Includes arithmetic on locals derived from balances (`liquidity_pool`). |
| SG-004 | 0 | 5 | Caller-supplied vectors (proofs, swap lists). |
| SG-005 | 0 | 0 | |
| SG-006 | 0 | 1 | `account::add_limit` stores a signed limit without a sign check (admin-only, so info). |
| SG-007 | 0 | 18 | Demo contracts that write state from regular functions and never extend TTLs. |
| SG-008 | 0 | 0 | |
| SG-009 | 0 | 0 | All five custom accounts verify signatures or delegate. |

## OpenZeppelin stellar-contracts, per rule

| Rule | warning | info | Notes |
|---|---|---|---|
| SG-001 | 5 | 3 | Permissionless functions in example contracts (e.g. a Merkle airdrop `claim`, a lazy-upgrade demo). |
| SG-002 | 6 | 0 | |
| SG-003 | 0 | 23 | |
| SG-004 | 10 | 3 | Loops over stored lists whose cap is kept in a separate counter or not visible (see the rule's limitations). |
| SG-005 | 0 | 0 | |
| SG-006 | 0 | 2 | Admin-only minting-limit setters (`sac-admin-generic`). |
| SG-007 | 0 | 4 | Example contracts (`ownable`, `pausable`, …) that never extend instance TTL. |
| SG-008 | 2 | 0 | `smart_account` deliberately ignores `try_uninstall` of an untrusted policy; a "review and suppress" case. |
| SG-009 | 0 | 0 | |

## Recall on seeded bugs

[`scripts/seeded_bugs.py`](../scripts/seeded_bugs.py) edits one line at a time in copies of
soroban-examples crates (removing an auth check, an allowance spend, a sign check or a signature
verification; making auth conditional; moving balances to temporary storage) and counts a bug as
detected when the edited copy has a finding the original does not.

| Case | 0.1.0 | now |
|---|---|---|
| token: `transfer_from` without `spend_allowance` | missed | SG-001 |
| token: `transfer` without `from.require_auth()` | SG-001 | SG-001 |
| token: `mint` without `check_nonnegative_amount` | missed | SG-006 |
| token: `transfer` auth only when `amount > 0` | missed | SG-001 |
| token: `transfer` auth inside an unused closure | missed | SG-001 |
| token: `set_admin` without `admin.require_auth()` | SG-001 | SG-001 |
| token: balances in temporary storage | SG-002 | SG-002 |
| simple_account: `__check_auth` without `ed25519_verify` | missed | SG-009 |
| liquidity_pool: `withdraw` without `to.require_auth()` | SG-001 | SG-001 |
| single_offer: `withdraw` without seller auth | SG-001 | SG-001 |
| timelock: `claim` without claimant auth | SG-001 | SG-001 |
| upgradeable_contract: `upgrade` without admin auth (`update_current_contract`) | missed | SG-001 |
| **Detected** | **6 / 12** | **12 / 12** |

```sh
python3 scripts/seeded_bugs.py <soroban-examples checkout at 03d42aa> target/release/stellar-guard
```

## Precision fixes driven by this exercise

* Storage-key words come from the key's own name, not from values passed into it.
* Same-named local variables in different `match` arms resolve to the right initializer.
* Submodules of `#[cfg(test)] mod test;` directories are excluded.
* Casts of range-checked values (`if amount > 0 { amount as u128 }`) are not reported.
* Caller-supplied loop sizes and plain public counters are reported as `info`.
* Stored collections capped where they grow are not reported by SG-004.
* `__constructor` writes and parameters are treated as deployer-controlled.
* Stored-collection caps are matched by storage key, not variable name (−4 SG-004 warnings on
  OpenZeppelin).
* SG-001's right-address check treats allowance spending (`transfer_from`, `burn_from`) and
  stored-admin authorization (clawback) as authorized.
* SG-001 does not report `require_auth_for_args` that signs a deliberate subset of arguments
  (atomic swap).
* SG-006 does not report amounts that are also passed to a token call, including values derived
  from them, since token contracts reject negative amounts.
* SG-007 ignores data written only by `__constructor` / initializers.
* SG-009 accepts accounts that delegate authorization (`delegate_auth`, `require_auth`) without
  reading the payload.
* `#![cfg(test)]` files and cargo-fuzz `fuzz_targets/` are excluded as test code.

To reproduce, clone the repositories at the listed commits and run the command above.
