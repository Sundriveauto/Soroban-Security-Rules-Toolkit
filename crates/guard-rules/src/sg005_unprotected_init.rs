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
            if !writes {
                continue;
            }
            if model.has_init_guard(id) {
                if let Some(d) = guard_never_set(model, id, f) {
                    out.push(d);
                } else if model.auth_status(id) == guard_parser::AuthStatus::Never {
                    out.push(front_runnable(f, None));
                } else {
                    // `admin.require_auth()` on a caller-supplied `admin` proves nothing: a
                    // front-runner passes and signs for their own address.
                    let auth = model.subject_auth(id);
                    if !auth.other && !auth.params.is_empty() {
                        let params = f.params();
                        let names: Vec<String> =
                            auth.params.iter().filter_map(|&i| params.get(i)).map(|(n, _)| format!("`{n}`")).collect();
                        out.push(front_runnable(f, Some(names.join(", "))));
                    }
                }
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

/// A guarded initializer that authorizes nobody runs as a separate transaction
/// after deployment, so whoever calls it first chooses the admin and configuration.
fn front_runnable(f: &guard_parser::FnDef<'_>, authorized_params: Option<String>) -> Diagnostic {
    let why = match authorized_params {
        None => "authorizes nobody".to_string(),
        Some(p) => format!("only authorizes the caller-supplied {p}, which a front-runner sets to their own address"),
    };
    Diagnostic::new(
        f.name_span,
        format!(
            "`{}` can be front-run: it runs after deployment and {why}, so the first caller sets the \
contract's configuration",
            f.name
        ),
        Confidence::Medium,
    )
    .with_severity(Severity::Warning)
    .in_function(&f.name)
    .with_help(
        "Initialize in `__constructor`, which runs atomically with deployment, or require authorization from \
an address fixed at build time (e.g. the deployer).",
    )
}

/// The initializer checks a key (`has(&DataKey::Initialized)`) that it never
/// writes, so the check passes on every call.
fn guard_never_set(model: &guard_parser::CrateModel<'_>, id: usize, f: &guard_parser::FnDef<'_>) -> Option<Diagnostic> {
    let guard_keys = model.init_guard_keys(id)?;
    if guard_keys.is_empty() {
        return None;
    }
    let written = model.written_keys(id);
    if guard_keys.iter().any(|k| written.contains(k)) {
        return None;
    }
    let set_elsewhere = (0..model.fns.len()).any(|other| {
        other != id
            && model.facts[other]
                .state_writes
                .iter()
                .any(|w| w.key_idents.last().is_some_and(|k| guard_keys.contains(k)))
    });
    let keys: Vec<String> = guard_keys.iter().map(|k| format!("`{k}`")).collect();
    let (confidence, note) = if set_elsewhere {
        (Confidence::Medium, " (it is only set by another function)")
    } else {
        (Confidence::High, "")
    };
    Some(
        Diagnostic::new(
            f.name_span,
            format!(
                "`{}` checks {} to prevent re-initialization but never sets it{note}, so the check always passes",
                f.name,
                keys.join(", ")
            ),
            confidence,
        )
        .in_function(&f.name)
        .with_help(format!(
            "Set {} in `{}` (or check a key it does write, such as the admin).",
            keys.join(", "),
            f.name
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    #[test]
    fn guarded_initializer_without_auth_can_be_front_run() {
        let f = run(
            Box::new(UnprotectedInitializer),
            r#"
#[contractimpl]
impl C {
    pub fn initialize(e: Env, admin: Address) {
        if e.storage().instance().has(&DataKey::Admin) { panic!("already initialised") }
        e.storage().instance().set(&DataKey::Admin, &admin);
    }
}
#[contractimpl]
impl D {
    pub fn init(e: Env, admin: Address) {
        if e.storage().instance().has(&DataKey::Admin) { panic!("already initialised") }
        admin.require_auth();
        e.storage().instance().set(&DataKey::Admin, &admin);
    }
}
"#,
        );
        assert_eq!(f.len(), 2, "{f:#?}");
        assert!(f.iter().all(|x| x.message.contains("front-run") && x.severity == Severity::Warning));
        assert!(f[0].message.contains("authorizes nobody"), "{}", f[0].message);
        assert!(f[1].message.contains("caller-supplied `admin`"), "{}", f[1].message);
    }

    #[test]
    fn initializer_authorized_by_a_stored_or_fixed_address_is_not_front_runnable() {
        let f = run(
            Box::new(UnprotectedInitializer),
            r#"
#[contractimpl]
impl C {
    pub fn initialize(e: Env, token: Address) {
        if e.storage().instance().has(&DataKey::Token) { panic!("already initialised") }
        let deployer: Address = e.storage().instance().get(&DataKey::Deployer).unwrap();
        deployer.require_auth();
        e.storage().instance().set(&DataKey::Token, &token);
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(UnprotectedInitializer), src)
    }

    #[test]
    fn flags_guard_on_key_never_written() {
        let f = check(
            r#"
#[contractimpl]
impl C {
    pub fn initialize(e: Env, admin: Address) {
        if e.storage().instance().has(&K::Init) { panic!("already") }
        e.storage().instance().set(&K::Admin, &admin);
    }
    pub fn init_ok(e: Env, admin: Address) {
        if e.storage().instance().has(&K::Admin) { panic!("already") }
        e.storage().instance().set(&K::Admin, &admin);
    }
    pub fn init_flag(e: Env, admin: Address) {
        if is_init(&e) { panic!("already") }
        e.storage().instance().set(&K::Initialized, &true);
        e.storage().instance().set(&K::Admin, &admin);
    }
}
fn is_init(e: &Env) -> bool { e.storage().instance().get(&K::Initialized).unwrap_or(false) }
"#,
        );
        // `init_ok` and `init_flag` are also front-runnable (no auth); that is a separate finding.
        let f: Vec<_> = f.into_iter().filter(|x| !x.message.contains("front-run")).collect();
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].message.contains("checks `Init`"), "{}", f[0].message);
        assert_eq!(f[0].confidence, Confidence::High);
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
        // Every guard is recognised; what remains is only the front-running warning (no auth).
        assert!(f.iter().all(|x| x.message.contains("front-run") && x.severity == Severity::Warning), "{f:#?}");
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
