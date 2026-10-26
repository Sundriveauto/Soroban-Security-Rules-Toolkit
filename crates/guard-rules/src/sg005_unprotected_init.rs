//! SG-005: initializer functions that can be called more than once.

use guard_engine::{Confidence, Diagnostic, Rule, RuleContext, RuleMeta, RuleOption, Severity};

pub struct UnprotectedInitializer;

static META: RuleMeta = RuleMeta {
    id: "SG-005",
    name: "unprotected-initializer",
    summary: "Initializer can be called more than once",
    description: "An exported function named like an initializer (`initialize`, `init`, …) writes contract \
state but never checks whether the contract has already been initialized. Because exported functions are \
callable by anyone, an attacker can call it again after deployment to replace the admin, token address or other \
configuration, or front-run the legitimate first call.",
    remediation: "Move initialization into `__constructor` (runs once at deployment), or fail when already \
initialized, e.g. `if env.storage().instance().has(&DataKey::Admin) { panic_with_error!(..) }`.",
    default_severity: Severity::Error,
    tags: &["security", "initialization", "access-control"],
    options: &[RuleOption {
        name: "initializer-names",
        description: "Extra function names treated as initializers.",
        default: "[]",
    }],
};

const INIT_NAMES: &[&str] = &["init", "initialize", "initialise"];
const INIT_PREFIXES: &[&str] = &["init_", "initialize_", "initialise_"];

/// `true` if `name` looks like a one-time initializer.
pub fn is_initializer_name(name: &str, extra: &[String]) -> bool {
    let lower = name.to_ascii_lowercase();
    INIT_NAMES.contains(&lower.as_str())
        || INIT_PREFIXES.iter().any(|p| lower.starts_with(p))
        || extra.iter().any(|e| e == name)
}

impl Rule for UnprotectedInitializer {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>) {
        let extra = cx.options.string_list("initializer-names");
        let model = cx.model;
        for (id, f) in model.fns_in_file(cx.file_idx) {
            if !f.is_contract_export() || !is_initializer_name(&f.name, &extra) {
                continue;
            }
            let writes = model.witness(id, &|_, facts| facts.state_writes.first().map(|w| w.span)).is_some();
            if !writes || model.has_init_guard(id) {
                continue;
            }
            out.push(
                Diagnostic::new(
                    f.name_span,
                    format!(
                        "`{}` writes contract state without checking whether the contract is already initialized",
                        f.name
                    ),
                    Confidence::High,
                )
                .in_function(&f.name),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(UnprotectedInitializer), src)
    }

    #[test]
    fn flags_unguarded_initialize() {
        let f = check(
            r#"
#[contractimpl]
impl Token {
    pub fn initialize(e: Env, admin: Address, decimal: u32) {
        write_administrator(&e, &admin);
        e.storage().instance().set(&DataKey::Decimals, &decimal);
    }
}
fn write_administrator(e: &Env, a: &Address) { e.storage().instance().set(&DataKey::Admin, a); }
"#,
        );
        assert_eq!(lines(&f), vec![4]);
        assert_eq!(f[0].severity, Severity::Error);
    }

    #[test]
    fn flags_init_prefix_names() {
        let f = check("#[contractimpl] impl C { pub fn init_pool(e: Env) { e.storage().instance().set(&K::A, &1); } }");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn guards_are_recognised() {
        let f = check(
            r#"
fn has_administrator(e: &Env) -> bool { e.storage().instance().has(&DataKey::Admin) }
#[contractimpl]
impl A {
    pub fn initialize(e: Env, admin: Address) {
        if has_administrator(&e) { panic!("already initialized") }
        e.storage().instance().set(&DataKey::Admin, &admin);
    }
}
#[contractimpl]
impl B {
    pub fn init(e: Env, admin: Address) {
        assert!(!e.storage().instance().has(&DataKey::Admin), "already initialized");
        e.storage().instance().set(&DataKey::Admin, &admin);
    }
}
#[contractimpl]
impl C {
    pub fn initialize(e: Env, admin: Address) -> Result<(), Error> {
        if e.storage().instance().get::<_, bool>(&DataKey::Initialized).unwrap_or(false) {
            return Err(Error::AlreadyInitialized);
        }
        e.storage().instance().set(&DataKey::Initialized, &true);
        Ok(())
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn constructor_and_read_only_init_are_fine() {
        let f = check(
            r#"
#[contractimpl]
impl C {
    pub fn __constructor(e: Env, admin: Address) { e.storage().instance().set(&DataKey::Admin, &admin); }
    pub fn initialized(e: Env) -> bool { e.storage().instance().has(&DataKey::Admin) }
    pub fn init_status(e: Env) -> u32 { 1 }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }
}
