# Real-world validation

Fixtures prove that rules detect what they claim. To measure **noise**, stellar-guard is also run
on well-reviewed public Soroban code where most findings are expected to be intentional patterns.
This page records the results so precision regressions are visible.

| Repository | Commit | Files | error | warning | info |
|---|---|---|---|---|---|
| [stellar/soroban-examples](https://github.com/stellar/soroban-examples) | `03d42aa` (2026-10-06) | 106 | 0 | 3 | 59 |
| [OpenZeppelin/stellar-contracts](https://github.com/OpenZeppelin/stellar-contracts) | `ddc327e` (2026-10-20) | 257 | 0 | 16 | 38 |
| [code-423n4/2025-02-blend](https://github.com/code-423n4/2025-02-blend) (Blend v2, audited code) | `f23b326` (2025-02-24) | 67 | 0 | 11 | 60 |
| [code-423n4/2025-10-reflector](https://github.com/code-423n4/2025-10-reflector) (Reflector V3, audited code) | `21676f3` | 15 | 0 | 1 | 4 |

Command: `stellar-guard scan <repo> --no-config` (defaults: tests excluded, all rules).
Test code is excluded: `#![cfg(test)]` files, cargo-fuzz targets, and test-support crates (a regular
dependency enables `testutils`, e.g. Blend's `test-suites` and mock contracts).

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
| SG-004 | 3 | 3 | `ClaimsByTopic` claim ids (no cap) and `ClaimTopicIssuers` (bounded only indirectly by `MAX_ISSUERS`). Previously 10: caps checked with `==`, lists mapped from capped or caller-supplied inputs, and lists returned by cross-contract calls are now recognised. |
| SG-005 | 0 | 0 | |
| SG-006 | 0 | 2 | Admin-only minting-limit setters (`sac-admin-generic`). |
| SG-007 | 0 | 7 | Example contracts (`ownable`, `pausable`, …) that never extend instance TTL; the lazy-upgrade demo never extends `Score` / `ScoreVersion` while extending other keys. |
| SG-008 | 2 | 0 | `smart_account` deliberately ignores `try_uninstall` of an untrusted policy; a "review and suppress" case. |
| SG-009 | 0 | 0 | |

## Recall on independently reported bugs

[`scripts/real_bugs.py`](../scripts/real_bugs.py) checks out public Soroban repositories at the
commit a GitHub issue was filed against and checks whether the reported bug is flagged by the
expected rule, in the reported file and function. The issues were written by other people (project
maintainers, contributors and auditors), not seeded by us. These are smaller projects than the ones
above; the cases are bugs in the classes stellar-guard targets.

| Set | Cases | Before tuning | After |
|---|---|---|---|
| Development: rules were improved while looking at these | 18 | 14 / 18 | **18 / 18** |
| Held out: collected afterwards, scored before any change | 21 | **11 / 21** | 17 / 21 after one general fix |

The held-out "before" number is the honest estimate for unseen bugs. The one fix made after scoring
it (initializers that authorize only a caller-supplied `admin` are front-runnable) addressed a
pattern four independent reports describe, and changed no finding on the four codebases above.

Per class (held out, before → after): missing authorization 3/3 → 3/3, front-runnable initializers
5/10 → 10/10, TTL 2/3 → 2/3, unbounded iteration 1/5 → 2/5.

Still missed, by design or as known limits:

* `soroban-ajo#856`: instance TTL is extended, but only in two functions; the rule does not judge
  how often a function runs.
* `sorostream#727`: a loop over a range computed from timestamps, not from storage or arguments.
* `Receipta#47`: no loop; a getter returns a whole stored vector.
* `txwatch#209`: a loop bounded by `min(offset + limit, ids.len())`; the bound is visible, the
  missing `MAX_BATCH_SIZE` check is not.

`Navin-xmr/navin-contracts#987` was excluded: the loop it reports does not exist anywhere in the
file's history.

```sh
python3 scripts/real_bugs.py <cache dir> target/release/stellar-guard            # development set
python3 scripts/real_bugs.py <cache dir> target/release/stellar-guard --heldout  # held-out set
```

## Blend v2 against its public audit

[Blend v2](https://github.com/code-423n4/2025-02-blend) was audited in a
[Code4rena contest](https://code4rena.com/reports/2025-02-blend-v2-audit-certora-formal-verification)
(3 high, 18 medium findings). Scanning the contest commit shows what a pattern-based tool can and
cannot be expected to find.

| Rule | warning | info | Notes |
|---|---|---|---|
| SG-001 | 8 | 1 | Permissionless by design (`gulp`, `bad_debt`, `new_auction`, reward-zone updates, `set_reserve` after an admin-queued timelock). Several act on another user's positions, so they are worth a reviewer's look and a suppression with the reason. `update_status` and `gulp_emissions` are reported because the pool's other setters all authorize (`gulp_emissions` is the entry point of M-12, though the fix there was a minimum delay, not authorization). |
| SG-003 | 3 | 58 | warning: `request.amount as u64` (an `i128` fill percentage truncated to `u64`; a value above `u64::MAX` wraps). info: arithmetic in a crate with `overflow-checks = true`. |
| SG-006 | 0 | 1 | Admin-only `min_collateral`. |

**Audit findings detected: 0 / 21.** All of them are protocol-economics bugs: stale reserve state after
a flash loan (H-01), emissions accounting (H-02, M-05 – M-08, M-12, M-16), utilization limits
(H-03, M-02, M-14), auction pricing and lifecycle (M-03, M-04, M-09, M-17, M-18), fixed-point
rounding to zero (M-10), fee and interest ordering (M-11, M-13, M-15), and a missing
`require_action_allowed` on flash loans (M-01). None is a missing `require_auth`, a storage-tier,
TTL, initialization or `__check_auth` mistake, which is what the rules target. stellar-guard does
not replace an audit of a protocol's economic logic.

Running Blend through the scanner removed 24 false-positive warnings (33 → 9): constant
`Symbol::new(e, KEY)` storage keys were treated as per-user keys (SG-002), enum discriminant casts
(`RequestType::Supply as u32`) as token amounts (SG-003), and `test-suites` / mock crates as
contract code.

## Reflector V3 against its public audit

Reflector V3 was audited in a Code4rena contest in October 2025. One high-severity finding is an
access-control gap: `set_invocation_costs_config` in `beam-contract` is documented as
"Requires admin authorization" but never checks it, so anyone can change invocation costs. Every
sibling setter (`set_cache_size`, `set_fee_config`, `add_assets`, …) calls `panic_if_not_admin`.

| Version | Result |
|---|---|
| before this change | `info` (low confidence): a plain storage write without an `Address` parameter |
| now | **`warning`, high confidence**: "… without an authorization check; its comment says it requires authorization" |

The scan reports nothing else as a warning. The pattern is covered by the
[`forgotten-admin-check`](../fixtures/vulnerable-examples/forgotten-admin-check) fixture.

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
* Crates that enable `testutils` in regular dependencies are excluded as test code (Blend).
* SG-007 checks persistent TTL extensions per key family (Heliobond, identity-credentials-sdk).
* SG-005 reports front-runnable initializers (5 of 10 held-out reports before the fix, 10 of 10 after).
* Keys built only from constants (`Symbol::new(e, ADMIN_KEY)`) are single keys (−14 SG-002 on Blend).
* Enum variants cast to integers are not token amounts (−9 SG-003 on Blend).
* SG-004 traces where a collection's length comes from (−7 on OpenZeppelin).

To reproduce, clone the repositories at the listed commits and run the command above.
