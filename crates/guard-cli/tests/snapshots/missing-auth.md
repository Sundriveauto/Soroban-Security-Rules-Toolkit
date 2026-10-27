## stellar-guard results

**1** files scanned · **0** errors · **10** warnings · **4** infos · 0 suppressed

| Severity | Rule | Location | Message | Confidence |
|---|---|---|---|---|
| 🔵 info | [SG-007](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-007.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:33` | This contract writes persistent storage but never extends its TTL; entries will be archived when their TTL expires | medium |
| 🟠 warning | [SG-001](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-001.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:62` | Exported function `withdraw` transfers tokens out of the contract without an authorization check | high |
| 🟠 warning | [SG-001](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-001.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:67` | Exported function `set_admin` modifies privileged configuration without an authorization check | high |
| 🔵 info | [SG-007](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-007.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:67` | This contract writes instance storage but never extends its TTL; entries will be archived when their TTL expires | medium |
| 🔵 info | [SG-010](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-010.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:67` | Exported function `set_admin` modifies privileged configuration without publishing a Soroban event | high |
| 🟠 warning | [SG-001](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-001.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:72` | Exported function `upgrade` upgrades the contract WASM without an authorization check | high |
| 🔵 info | [SG-010](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-010.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:72` | Exported function `upgrade` upgrades the contract without publishing a Soroban event | high |
| 🟠 warning | [SG-001](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-001.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:77` | Exported function `credit` writes contract storage (via `write_balance`) without an authorization check | medium |
| 🟠 warning | [SG-006](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-006.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:77` | `credit` stores or accounts `amount: i128` without rejecting negative values | medium |
| 🟠 warning | [SG-001](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-001.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:83` | Exported function `set_token` writes contract storage without an authorization check | medium |
| 🟠 warning | [SG-001](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-001.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:92` | Exported function `withdraw_to` transfers tokens out of the contract, but authorizes only on some code paths (inside a branch, loop or closure) | medium |
| 🟠 warning | [SG-001](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-001.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:102` | Exported function `move_balance` decreases a value keyed by `from`, but only `caller` authorizes | medium |
| 🟠 warning | [SG-006](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-006.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:102` | `move_balance` stores or accounts `amount: i128` without rejecting negative values | medium |
| 🟠 warning | [SG-001](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-001.md) | `fixtures/vulnerable-examples/missing-auth/src/lib.rs:109` | Exported function `withdraw_signed` calls `require_auth_for_args` without `to`, `amount` in the signed arguments | medium |

> stellar-guard reports potential issues found by source-level heuristics. Findings are not proof of a vulnerability, and a clean scan does not prove a contract is secure.
