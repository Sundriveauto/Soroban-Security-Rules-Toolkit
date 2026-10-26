//! SG-001: exported contract functions that change state, move funds or
//! upgrade the contract without any authorization check.

use guard_engine::{Confidence, Diagnostic, Rule, RuleContext, RuleMeta, RuleOption, Severity};
use guard_parser::{AuthStatus, FnFacts, Span, Witness};

use crate::sg005_unprotected_init::is_initializer_name;
use crate::util::{has_word, word_set};

pub struct MissingAuthorization;

static META: RuleMeta = RuleMeta {
    id: "SG-001",
    name: "missing-authorization",
    summary: "Potential missing authorization check",
    description: "An exported contract function writes to storage, transfers tokens out of the contract, or \
upgrades the contract WASM, but neither it nor any helper it calls invokes `require_auth()` / \
`require_auth_for_args()` (or a recognised access-control helper or attribute). Anyone can call such a \
function with arbitrary arguments.",
    remediation: "Review whether this operation requires `address.require_auth()` (on the affected user or the stored \
admin). If the function is intentionally permissionless, add `// stellar-guard-ignore SG-001 -- <reason>`.",
    default_severity: Severity::Warning,
    tags: &["security", "authorization", "access-control"],
    options: &[
        RuleOption {
            name: "ignore-functions",
            description: "Exported function names that are intentionally permissionless.",
            default: "[]",
        },
        RuleOption {
            name: "privileged-keys",
            description: "Extra storage-key words treated as privileged (in addition to admin, owner, …).",
            default: "[]",
        },
    ],
};

/// Storage-key words that indicate privileged configuration.
const PRIVILEGED_WORDS: &[&str] = &[
    "admin",
    "administrator",
    "owner",
    "operator",
    "minter",
    "manager",
    "governance",
    "governor",
    "upgrader",
    "pauser",
    "guardian",
    "authority",
    "treasury",
    "signer",
    "signers",
    "wasm",
];

/// Functions with protocol-defined semantics.
const SKIPPED: &[&str] = &["__constructor", "__check_auth"];

#[derive(Clone, Copy)]
enum Sensitive {
    Upgrade,
    Outflow,
    PrivilegedWrite,
    Write,
}

impl Rule for MissingAuthorization {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>) {
        let ignored = cx.options.string_list("ignore-functions");
        let privileged = word_set(PRIVILEGED_WORDS, cx.options.string_list("privileged-keys"));
        let model = cx.model;

        for (id, f) in model.fns_in_file(cx.file_idx) {
            if !f.is_contract_export()
                || SKIPPED.contains(&f.name.as_str())
                || ignored.contains(&f.name)
                || is_initializer_name(&f.name, &[])
            {
                continue;
            }
            let auth = model.auth_status(id);
            if auth == AuthStatus::Always {
                continue;
            }

            let privileged_write = |_: &guard_parser::FnDef<'_>, facts: &FnFacts| -> Option<Span> {
                facts
                    .state_writes
                    .iter()
                    .find(|w| w.key_idents.last().is_some_and(|i| has_word(i, &privileged)))
                    .map(|w| w.span)
            };
            let found: Option<(Sensitive, Witness)> = model
                .witness(id, &|_, facts| facts.upgrades.first().copied())
                .map(|w| (Sensitive::Upgrade, w))
                .or_else(|| {
                    model.witness(id, &|_, facts| facts.outflows.first().copied()).map(|w| (Sensitive::Outflow, w))
                })
                .or_else(|| model.witness(id, &privileged_write).map(|w| (Sensitive::PrivilegedWrite, w)))
                .or_else(|| {
                    model
                        .witness(id, &|_, facts| facts.state_writes.first().map(|w| w.span))
                        .map(|w| (Sensitive::Write, w))
                });
            let Some((kind, witness)) = found else { continue };

            let (what, mut confidence) = match kind {
                Sensitive::Upgrade => ("upgrades the contract WASM", Confidence::High),
                Sensitive::Outflow => ("transfers tokens out of the contract", Confidence::High),
                Sensitive::PrivilegedWrite => ("modifies privileged configuration", Confidence::High),
                Sensitive::Write if f.takes_address() => ("writes contract storage", Confidence::Medium),
                Sensitive::Write => ("writes contract storage", Confidence::Low),
            };
            let partial = auth == AuthStatus::Sometimes;
            if partial {
                // A plain write behind conditional auth is usually a deliberate
                // "authorize only when needed" pattern; don't report it.
                if matches!(kind, Sensitive::Write) {
                    continue;
                }
                confidence = Confidence::Medium;
            }
            let via = if witness.via.is_empty() {
                String::new()
            } else {
                format!(" (via `{}`)", witness.via.join("` → `"))
            };
            let message = if partial {
                format!(
                    "Exported function `{}` {what}{via}, but authorizes only on some code paths (inside a branch, loop or closure)",
                    f.name
                )
            } else {
                format!("Exported function `{}` {what}{via} without an authorization check", f.name)
            };
            let mut d = Diagnostic::new(witness.span, message, confidence).in_function(&f.name);
            if confidence == Confidence::Low {
                // A plain storage write with no address involved (e.g. a public counter) is
                // often intentional; report it without failing CI by default.
                d = d.with_severity(Severity::Info);
            }
            out.push(d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use guard_engine::Settings;

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(MissingAuthorization), src)
    }

    // ---- true positives -------------------------------------------------

    #[test]
    fn flags_withdraw_without_auth() {
        let f = check(
            r#"
#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &read_token(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
"#,
        );
        assert_eq!(lines(&f), vec![6]);
        assert_eq!(f[0].confidence, Confidence::High);
        assert!(f[0].message.contains("transfers tokens out"), "{}", f[0].message);
        assert_eq!(f[0].function.as_deref(), Some("withdraw"));
    }

    #[test]
    fn flags_set_admin_and_upgrade() {
        let f = check(
            r#"
#[contractimpl]
impl C {
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &new_admin);
    }
    pub fn upgrade(env: Env, hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(hash);
    }
}
"#,
        );
        assert_eq!(lines(&f), vec![5, 8]);
        assert!(f.iter().all(|x| x.confidence == Confidence::High));
    }

    #[test]
    fn flags_write_through_helper_and_reports_call_site() {
        let f = check(
            r#"
fn write_balance(e: &Env, who: &Address, v: i128) {
    e.storage().persistent().set(&DataKey::Balance(who.clone()), &v);
}
#[contractimpl]
impl Token {
    pub fn mint(e: Env, to: Address, amount: i128) {
        write_balance(&e, &to, amount);
    }
}
"#,
        );
        assert_eq!(lines(&f), vec![8]);
        assert_eq!(f[0].confidence, Confidence::Medium);
        assert!(f[0].message.contains("via `write_balance`"));
    }

    #[test]
    fn trait_impl_functions_are_exported() {
        let f = check(
            r#"
#[contractimpl]
impl TokenInterface for Token {
    fn burn(e: Env, from: Address, amount: i128) {
        e.storage().persistent().remove(&DataKey::Balance(from));
    }
}
"#,
        );
        assert_eq!(f.len(), 1);
    }

    // ---- false positives that must NOT be reported ----------------------

    #[test]
    fn direct_and_helper_auth_are_recognised() {
        let f = check(
            r#"
fn require_admin(e: &Env) {
    let admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap();
    admin.require_auth();
}
#[contractimpl]
impl C {
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        e.storage().persistent().set(&DataKey::Balance(to), &amount);
    }
    pub fn set_admin(e: Env, a: Address) {
        require_admin(&e);
        e.storage().instance().set(&DataKey::Admin, &a);
    }
    pub fn vote(e: Env, voter: Address, args: Vec<Val>) {
        voter.require_auth_for_args(args);
        e.storage().persistent().set(&DataKey::Vote(voter), &true);
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn read_only_ttl_and_internal_fns_are_ignored() {
        let f = check(
            r#"
#[contractimpl]
impl C {
    pub fn balance(e: Env, id: Address) -> i128 {
        e.storage().persistent().get(&DataKey::Balance(id)).unwrap_or(0)
    }
    pub fn bump(e: Env) {
        e.storage().instance().extend_ttl(100, 200);
    }
    fn internal(e: Env) {
        e.storage().instance().set(&DataKey::X, &1);
    }
    pub fn __constructor(e: Env, admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &admin);
    }
}
impl NotAContract {
    pub fn set(e: Env) { e.storage().instance().set(&DataKey::X, &1); }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn deposit_from_user_is_not_an_outflow() {
        let f = check(
            r#"
#[contractimpl]
impl Vault {
    pub fn deposit(e: Env, from: Address, amount: i128) {
        from.require_auth();
        token::Client::new(&e, &t).transfer(&from, &e.current_contract_address(), &amount);
    }
}
"#,
        );
        assert!(f.is_empty());
    }

    #[test]
    fn access_control_attributes_and_custom_helpers() {
        let src = r#"
#[contractimpl]
impl C {
    #[only_owner]
    pub fn pause(e: Env) { e.storage().instance().set(&DataKey::Paused, &true); }
    pub fn unpause(e: Env) { gate(&e); e.storage().instance().set(&DataKey::Paused, &false); }
}
"#;
        let f = check(src);
        assert_eq!(f.len(), 1, "only `unpause` without configured helper");
        assert_eq!((f[0].confidence, f[0].severity), (Confidence::Low, Severity::Info));
        let settings = Settings { auth_functions: vec!["gate".into()], ..Default::default() };
        let f = run_with(Box::new(MissingAuthorization), src, soroban_crate(Some(true)), &settings);
        assert!(f.is_empty());
    }

    #[test]
    fn privileged_keys_use_the_variant_name() {
        let f = check(
            r#"
#[contractimpl]
impl Gov {
    pub fn queue(e: Env, id: u32, op: BytesN<32>) {
        e.storage().persistent().set(&GovernorKey::OperationId(id), &op);
    }
}
"#,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, Confidence::Low, "not a privileged write: {}", f[0].message);
    }

    #[test]
    fn ignore_functions_option() {
        let mut settings = Settings::default();
        settings
            .rule_mut("SG-001")
            .options
            .insert("ignore-functions".into(), toml::Value::Array(vec![toml::Value::String("increment".into())]));
        let f = run_with(
            Box::new(MissingAuthorization),
            "#[contractimpl] impl C { pub fn increment(e: Env) { e.storage().instance().set(&K::C, &1); } }",
            soroban_crate(Some(true)),
            &settings,
        );
        assert!(f.is_empty());
    }

    #[test]
    fn initializers_are_left_to_sg005() {
        let f = check(
            "#[contractimpl] impl C { pub fn initialize(e: Env, a: Address) { e.storage().instance().set(&K::Admin, &a); } }",
        );
        assert!(f.is_empty());
    }
}
