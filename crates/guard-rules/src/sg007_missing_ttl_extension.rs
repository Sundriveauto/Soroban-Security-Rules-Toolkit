//! SG-007: persistent or instance data written by a contract that never extends its TTL.

use guard_engine::{Confidence, Diagnostic, Rule, RuleContext, RuleMeta, Severity};
use guard_parser::{FnKind, StorageTier};

pub struct MissingTtlExtension;

static META: RuleMeta = RuleMeta {
    id: "SG-007",
    name: "missing-ttl-extension",
    summary: "Stored data never has its TTL extended",
    description: "Persistent and instance entries live only until their time-to-live (TTL) runs out; they are then \
archived and every call that reads them fails until someone restores them. A contract that writes persistent or \
instance storage but never calls `extend_ttl` on that tier (and never extends its instance with the deployer) \
relies on users or operators to extend or restore entries by hand. Archived instance storage makes the whole \
contract unusable until restored. Writes made only by `__constructor` or an initializer are not considered.",
    remediation: "Extend the TTL where entries are written or read, e.g. \
`env.storage().persistent().extend_ttl(&key, THRESHOLD, EXTEND_TO)` and \
`env.storage().instance().extend_ttl(THRESHOLD, EXTEND_TO)` in frequently called functions.",
    default_severity: Severity::Info,
    tags: &["reliability", "storage", "state-archival"],
    options: &[],
};

impl Rule for MissingTtlExtension {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>) {
        if !cx.is_soroban() {
            return;
        }
        let model = cx.model;
        // Only contract crates: library crates usually leave TTL policy to the contract using them.
        let own = || model.fns.iter().zip(&model.facts).filter(|(f, _)| !f.foreign);
        if !own().any(|(f, _)| matches!(f.kind, FnKind::ContractExport { .. })) {
            return;
        }
        let extended = |tier: StorageTier| {
            model.facts.iter().any(|x| x.ttl_extends.iter().any(|t| *t == Some(tier) || t.is_none()))
        };
        let regular: std::collections::HashSet<usize> = own()
            .enumerate()
            .filter(|(_, (f, _))| matches!(f.kind, FnKind::ContractExport { .. }) && !is_setup(&f.name))
            .flat_map(|(i, _)| model.reachable(i))
            .collect();
        for tier in [StorageTier::Persistent, StorageTier::Instance] {
            if extended(tier) {
                continue;
            }
            // Report once per crate, at the first write of this tier (in model order) that a
            // regular exported function can reach. Writes reachable only from the constructor or
            // an initializer set one-time configuration, whose TTL is usually extended
            // off-chain; data written by regular functions keeps changing.
            let first = own().enumerate().filter(|(i, _)| regular.contains(i)).find_map(|(_, (f, x))| {
                x.state_writes
                    .iter()
                    .find(|w| w.tier == Some(tier) && w.kind != guard_parser::StorageOpKind::Remove)
                    .map(|w| (f, w))
            });
            let Some((f, w)) = first else { continue };
            if f.file != cx.file_idx {
                continue;
            }
            out.push(
                Diagnostic::new(
                    w.span,
                    format!(
                        "This contract writes {} storage but never extends its TTL; entries will be archived when \
their TTL expires",
                        tier.as_str()
                    ),
                    Confidence::Medium,
                )
                .in_function(&f.name),
            );
        }
        unextended_persistent_keys(cx, &regular, out);
    }
}

/// Persistent entries are extended one key at a time. When a crate extends
/// some persistent keys by name, report each other key family that regular
/// functions write but never extend (once per file, at its first write there).
///
/// Any extension whose key is unknown (`extend_ttl(&key, ..)` in a generic
/// helper) may cover every key, so nothing is reported then.
fn unextended_persistent_keys(
    cx: &RuleContext<'_>,
    regular: &std::collections::HashSet<usize>,
    out: &mut Vec<Diagnostic>,
) {
    let model = cx.model;
    let mut extended: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (id, x) in model.facts.iter().enumerate() {
        let extends = x.ttl_extends.iter().zip(&x.ttl_extend_keys).zip(&x.ttl_extend_key_locals);
        for ((tier, key), local) in extends {
            if !matches!(tier, Some(StorageTier::Persistent) | None) {
                continue;
            }
            if let Some(k) = key {
                extended.insert(k.clone());
                continue;
            }
            // `fn store(key, value) { set(key, value); extend_ttl(key, ..) }` covers only the
            // writes it makes itself (skipped below).
            if local.as_ref().is_some_and(|l| x.state_writes.iter().any(|w| &w.key_text == l)) {
                continue;
            }
            // `fn bump(e: &Env, key: &DataKey) { ..extend_ttl(key, ..) }`: the keys are the
            // ones its callers pass. Anything less certain may cover every key.
            match local.as_ref().map(|l| keys_passed_for(model, id, l)) {
                Some(KeysPassed::Known(keys)) => extended.extend(keys),
                Some(KeysPassed::NoCallers) if !model.fns[id].is_contract_export() => {}
                _ => return,
            }
        }
    }
    if extended.is_empty() {
        return; // covered by the "never extends" finding above
    }
    let mut reported = std::collections::HashSet::new();
    for (i, (f, x)) in model.fns.iter().zip(&model.facts).enumerate() {
        if f.foreign || !regular.contains(&i) {
            continue;
        }
        for w in &x.state_writes {
            if w.tier != Some(StorageTier::Persistent) || w.kind == guard_parser::StorageOpKind::Remove {
                continue;
            }
            let Some(key) = guard_parser::model::key_id(&w.key_idents) else { continue };
            // Once per key family and file: crates often hold several contracts, one per module.
            if extended.contains(&key) || f.file != cx.file_idx || !reported.insert(key.clone()) {
                continue;
            }
            out.push(
                Diagnostic::new(
                    w.span,
                    format!(
                        "Persistent entries under `{key}` are written but their TTL is never extended (the contract \
extends other persistent keys); they will be archived when their TTL expires"
                    ),
                    Confidence::Medium,
                )
                .in_function(&f.name),
            );
        }
    }
}

enum KeysPassed {
    Known(Vec<String>),
    NoCallers,
    Unknown,
}

/// Key names that callers of `id` pass for its parameter `param`.
fn keys_passed_for(model: &guard_parser::CrateModel<'_>, id: usize, param: &str) -> KeysPassed {
    let Some(index) = model.param_names(id).iter().position(|p| p == param) else { return KeysPassed::Unknown };
    let mut keys = Vec::new();
    for (caller, x) in model.facts.iter().enumerate() {
        for call in &x.calls {
            if !model.resolve(caller, call).contains(&id) {
                continue;
            }
            match call.args.get(index).and_then(|a| a.key.clone()) {
                Some(k) => keys.push(k),
                None => return KeysPassed::Unknown,
            }
        }
    }
    if keys.is_empty() {
        KeysPassed::NoCallers
    } else {
        KeysPassed::Known(keys)
    }
}

fn is_setup(name: &str) -> bool {
    name == "__constructor" || crate::sg005_unprotected_init::is_initializer_name(name, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(MissingTtlExtension), src)
    }

    #[test]
    fn flags_each_tier_once() {
        let f = check(
            r#"
fn put(e: &Env, a: Address, v: i128) { e.storage().persistent().set(&K::Bal(a), &v); }
#[contractimpl]
impl C {
    pub fn a(e: Env, a: Address) { put(&e, a.clone(), 1); put(&e, a, 2); }
    pub fn b(e: Env) { e.storage().instance().set(&K::Count, &1u32); }
    pub fn t(e: Env) { e.storage().temporary().set(&K::Nonce, &1u32); }
}
"#,
        );
        assert_eq!(lines(&f), vec![2, 6], "{f:#?}");
        assert!(f[0].message.contains("persistent"));
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn extensions_anywhere_in_the_crate_count() {
        let f = check(
            r#"
fn bump(e: &Env, a: Address) { e.storage().persistent().extend_ttl(&K::Bal(a), 100, 1000); }
#[contractimpl]
impl C {
    pub fn a(e: Env, a: Address) { e.storage().persistent().set(&K::Bal(a.clone()), &1i128); bump(&e, a); }
    pub fn b(e: Env) { e.storage().instance().set(&K::Count, &1u32); e.deployer().extend_ttl_for_contract_instance(e.current_contract_address(), 1, 2); }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn constructor_only_writes_are_skipped() {
        let f = check(
            r#"
#[contractimpl]
impl C {
    pub fn __constructor(e: Env, a: Address) { e.storage().instance().set(&K::Admin, &a); }
    pub fn initialize(e: Env, a: Address) { write_owner(&e, &a); }
}
fn write_owner(e: &Env, a: &Address) { e.storage().persistent().set(&K::Owner, a); }
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn reports_persistent_keys_that_are_never_extended_when_others_are() {
        let f = check(
            r#"
fn bump(e: &Env, key: &K) { e.storage().persistent().extend_ttl(key, 100, 1000); }
fn store<V>(e: &Env, key: &K, v: &V) { e.storage().persistent().set(key, v); e.storage().persistent().extend_ttl(key, 1, 2); }
fn bump_all(e: &Env) { for key in [K::Total, K::Count] { e.storage().persistent().extend_ttl(&key, 1, 2); } }
#[contractimpl]
impl C {
    pub fn a(e: Env, a: Address) { e.storage().persistent().set(&K::Bal(a.clone()), &1i128); bump(&e, &K::Bal(a)); }
    pub fn b(e: Env, id: u32) { e.storage().persistent().set(&K::Order(id), &1i128); }
    pub fn c(e: Env) { e.storage().persistent().set(&K::Total, &1i128); e.storage().persistent().set(&K::Count, &1u32); bump_all(&e); }
    pub fn d(e: Env, id: u32) { store(&e, &K::Item(id), &1u32); }
    pub fn g(e: Env, id: u32) { e.storage().persistent().set(&Other::Bal(id), &1i128); }
}
"#,
        );
        assert_eq!(f.len(), 2, "{f:#?}");
        assert!(f[0].message.contains("`K::Order`"), "{}", f[0].message);
        assert!(f[1].message.contains("`Other::Bal`"), "same variant name, different enum: {}", f[1].message);
    }

    #[test]
    fn an_extension_of_an_unknown_key_may_cover_every_key() {
        let f = check(
            r#"
#[contractimpl]
impl C {
    pub fn touch(e: Env, key: Bytes) { e.storage().persistent().extend_ttl(&key, 1, 2); }
    pub fn a(e: Env, a: Address) { e.storage().persistent().set(&K::Bal(a.clone()), &1i128); e.storage().persistent().extend_ttl(&K::Bal(a), 1, 2); }
    pub fn b(e: Env, id: u32) { e.storage().persistent().set(&K::Order(id), &1i128); }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn library_crates_are_skipped() {
        let f = check("pub fn put(e: &Env, v: i128) { e.storage().persistent().set(&K::V, &v); }");
        assert!(f.is_empty());
    }
}
