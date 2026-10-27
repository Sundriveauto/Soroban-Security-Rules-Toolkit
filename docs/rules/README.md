# Rules

| ID | Name | Default severity | Detects |
|---|---|---|---|
| [SG-001](SG-001.md) | `missing-authorization` | warning | Exported functions that write state, move funds out or upgrade the contract without `require_auth` |
| [SG-002](SG-002.md) | `storage-tier-misuse` | warning | Long-lived state in temporary storage; per-user data in instance storage |
| [SG-003](SG-003.md) | `unchecked-arithmetic` | warning | Plain `+ - *` and lossy `as` casts on token amounts |
| [SG-004](SG-004.md) | `unbounded-iteration` | warning | Loops over storage-backed or caller-supplied collections without a bound |
| [SG-005](SG-005.md) | `unprotected-initializer` | error | `initialize`-style functions that can be called more than once |
| [SG-006](SG-006.md) | `negative-amount` | warning | `i128` amounts written to storage without rejecting negative values |
| [SG-007](SG-007.md) | `missing-ttl-extension` | info | Persistent / instance data written by regular functions whose TTL is never extended |
| [SG-008](SG-008.md) | `ignored-try-call` | warning | Discarded results of `client.try_*` cross-contract calls |
| [SG-009](SG-009.md) | `weak-check-auth` | error | Custom-account `__check_auth` that verifies no signature, or one not bound to the payload |
| [SG-010](SG-010.md) | `missing-admin-events` | info | Privileged writes and upgrades without a Soroban event |

Every rule is a **source-level heuristic**. Each page lists what the rule detects, why it matters,
an example and fix, known false positives / false negatives, and its options.

Run `stellar-guard explain <ID>` for the same information in the terminal.

## Rule ID policy

* IDs are permanent. A removed rule's ID is never reused.
* Changing what a rule detects in a way that adds findings is noted in the changelog.
* New rules take the next free number; see [CONTRIBUTING.md](../../CONTRIBUTING.md#adding-a-rule).
