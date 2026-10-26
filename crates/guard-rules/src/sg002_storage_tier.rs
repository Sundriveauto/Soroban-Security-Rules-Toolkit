//! SG-002: long-lived application state in temporary storage, and per-key
//! (per-user) data in instance storage.

use guard_engine::{Confidence, Diagnostic, Rule, RuleContext, RuleMeta, RuleOption, Severity};
use guard_parser::{StorageOpKind, StorageTier};

use crate::util::word_set;

pub struct StorageTierMisuse;

static META: RuleMeta = RuleMeta {
    id: "SG-002",
    name: "storage-tier-misuse",
    summary: "Suspicious storage type for application state",
    description: "Soroban has three storage tiers. Temporary entries are permanently deleted when their TTL \
expires and cannot be restored, so storing balances, admin addresses, configuration or other long-lived state \
there can silently lose funds or brick the contract. Instance storage is loaded on every invocation and shares \
one size-limited ledger entry, so writing per-user keys (e.g. `DataKey::Balance(addr)`) to it grows the entry \
without bound and raises costs for every caller.",
    remediation: "Keep long-lived state in `persistent()` (per-user data) or `instance()` (small contract-wide \
config) and extend its TTL; reserve `temporary()` for data that may safely disappear.",
    default_severity: Severity::Warning,
    tags: &["security", "storage", "state"],
    options: &[
        RuleOption {
            name: "sensitive-keys",
            description: "Extra key words that indicate long-lived state.",
            default: "[]",
        },
        RuleOption {
            name: "ignore-keys",
            description: "Extra key words that are intentionally temporary.",
            default: "[]",
        },
    ],
};

/// Key words that strongly indicate state which must not expire.
const CRITICAL_WORDS: &[&str] = &["balance", "balances", "admin", "administrator", "owner", "supply"];

/// Key words that indicate long-lived state.
const SENSITIVE_WORDS: &[&str] = &[
    "balance",
    "balances",
    "admin",
    "administrator",
    "owner",
    "supply",
    "config",
    "configuration",
    "settings",
    "initialized",
    "metadata",
    "decimals",
    "paused",
    "role",
    "roles",
    "member",
    "members",
    "vault",
    "position",
    "positions",
    "deposit",
    "deposits",
    "stake",
    "stakes",
    "staked",
    "debt",
    "collateral",
    "treasury",
    "proposal",
    "proposals",
    "vote",
    "votes",
    "whitelist",
    "allowlist",
    "blacklist",
    "blocklist",
    "registry",
    "shares",
    "reserve",
    "reserves",
    "escrow",
    "loan",
    "loans",
    "order",
    "orders",
    "listing",
    "listings",
];

/// Key words that indicate data which is fine to expire.
const EPHEMERAL_WORDS: &[&str] = &[
    "allowance",
    "allowances",
    "nonce",
    "nonces",
    "cache",
    "cached",
    "temp",
    "temporary",
    "session",
    "lock",
    "ttl",
    "expiration",
    "expiry",
    "signature",
    "challenge",
    "cooldown",
    "ratelimit",
    "throttle",
    "pending",
];

impl Rule for StorageTierMisuse {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>) {
        let sensitive = word_set(SENSITIVE_WORDS, cx.options.string_list("sensitive-keys"));
        let ephemeral = word_set(EPHEMERAL_WORDS, cx.options.string_list("ignore-keys"));

        for (id, f) in cx.model.fns_in_file(cx.file_idx) {
            for w in &cx.model.facts[id].state_writes {
                if !matches!(w.kind, StorageOpKind::Set | StorageOpKind::Update) {
                    continue;
                }
                // Ephemeral words anywhere in the key opt out; sensitive words must name the
                // variant itself (`VaultKey::Nonce` is ephemeral, `GovKey::Timer` is not "gov").
                if w.key_words().iter().any(|k| ephemeral.contains(k)) {
                    continue;
                }
                let key_words = w.key_variant_words();
                match w.tier {
                    Some(StorageTier::Temporary) => {
                        let Some(hit) = key_words.iter().find(|k| sensitive.contains(k)) else {
                            continue;
                        };
                        let confidence =
                            if CRITICAL_WORDS.contains(&hit.as_str()) { Confidence::High } else { Confidence::Medium };
                        out.push(
                            Diagnostic::new(
                                w.span,
                                format!(
                                    "`{}` looks like long-lived state but is written to temporary storage, \
which is deleted permanently when its TTL expires",
                                    w.key_text
                                ),
                                confidence,
                            )
                            .in_function(&f.name),
                        );
                    }
                    // Keys written once by the deployer in `__constructor` form a bounded set.
                    Some(StorageTier::Instance) if w.key_is_parameterised && f.name != "__constructor" => {
                        out.push(
                            Diagnostic::new(
                                w.span,
                                format!(
                                    "Per-key data `{}` is written to instance storage, which is loaded on every \
call and grows with each new key; use persistent storage instead",
                                    w.key_text
                                ),
                                Confidence::Medium,
                            )
                            .in_function(&f.name),
                        );
                    }
                    Some(StorageTier::Instance) if !w.key_is_parameterised && f.name != "__constructor" => {
                        if let Some((coll, call)) = growing_collection(f, &cx.model.facts[id], w) {
                            out.push(
                                Diagnostic::new(
                                    w.span,
                                    format!(
                                        "Collection `{coll}` stored under instance key `{}` grows with caller-supplied \
entries (`{coll}.{call}(..)`); the single instance entry is loaded on every call and has a size limit",
                                        w.key_text
                                    ),
                                    Confidence::Medium,
                                )
                                .in_function(&f.name)
                                .with_help(
                                    "Store each entry under its own persistent key (e.g. `DataKey::Member(addr)`) \
instead of one growing `Map`/`Vec` in instance storage, or cap its length.",
                                ),
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// For an instance write whose value is a local collection, the local's name and
/// the growth method when the function adds parameter-derived entries to it
/// (`m.set(user, amount)`, `list.push_back(addr)`) without checking its length.
fn growing_collection(
    f: &guard_parser::FnDef<'_>,
    facts: &guard_parser::FnFacts,
    w: &guard_parser::StateWrite,
) -> Option<(String, String)> {
    use syn::visit::Visit;
    struct G<'p> {
        params: &'p [String],
        targets: &'p [String],
        hit: Option<(String, String)>,
    }
    impl<'ast> Visit<'ast> for G<'_> {
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            let method = m.method.to_string();
            if self.hit.is_none() && matches!(method.as_str(), "set" | "push_back" | "push_front" | "insert" | "append")
            {
                if let Some(recv) = guard_parser::syntax::as_local_ident(&m.receiver) {
                    let from_params =
                        m.args.iter().flat_map(guard_parser::syntax::idents).any(|i| self.params.contains(&i));
                    if self.targets.contains(&recv) && from_params {
                        self.hit = Some((recv, method));
                    }
                }
            }
            syn::visit::visit_expr_method_call(self, m);
        }
        fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
    }
    let targets: Vec<String> = w.value_locals.iter().filter(|v| !facts.len_bounds.contains(v)).cloned().collect();
    if targets.is_empty() {
        return None;
    }
    let params: Vec<String> = f.params().into_iter().map(|(n, _)| n).collect();
    let mut g = G { params: &params, targets: &targets, hit: None };
    g.visit_block(f.block);
    g.hit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use guard_engine::Settings;

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(StorageTierMisuse), src)
    }

    #[test]
    fn flags_balances_and_admin_in_temporary() {
        let f = check(
            r#"
fn write_balance(e: &Env, addr: Address, amount: i128) {
    let key = DataKey::Balance(addr);
    e.storage().temporary().set(&key, &amount);
}
fn set_admin(e: &Env, a: &Address) {
    let tmp = e.storage().temporary();
    tmp.set(&DataKey::Admin, a);
}
fn set_cfg(e: &Env, c: &Config) { e.storage().temporary().set(&DataKey::PoolConfig, c); }
"#,
        );
        assert_eq!(lines(&f), vec![4, 8, 10]);
        assert_eq!(f[0].confidence, Confidence::High);
        assert!(f[0].message.contains("`DataKey::Balance(addr)`"), "{}", f[0].message);
        assert_eq!(f[2].confidence, Confidence::Medium);
    }

    #[test]
    fn flags_growing_collection_in_instance_storage() {
        let f = check(
            r#"
fn register(e: &Env, u: Address, amount: i128) {
    let mut m: Map<Address, i128> = e.storage().instance().get(&K::Users).unwrap_or(Map::new(e));
    m.set(u, amount);
    e.storage().instance().set(&K::Users, &m);
}
fn capped(e: &Env, u: Address) {
    let mut v: Vec<Address> = e.storage().instance().get(&K::List).unwrap();
    if v.len() >= 10 { panic!() }
    v.push_back(u);
    e.storage().instance().set(&K::List, &v);
}
fn config(e: &Env, fee: u32) {
    let mut c: Config = e.storage().instance().get(&K::Cfg).unwrap();
    c.fee = fee;
    e.storage().instance().set(&K::Cfg, &c);
}
"#,
        );
        assert_eq!(lines(&f), vec![5], "{f:#?}");
        assert!(f[0].message.contains("`m.set(..)`"), "{}", f[0].message);
    }

    #[test]
    fn flags_per_user_keys_in_instance_storage() {
        let f = check("fn w(e: &Env, a: Address) { e.storage().instance().set(&DataKey::Balance(a), &1i128); }");
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("instance storage"));
    }

    #[test]
    fn key_arguments_do_not_count_as_key_names() {
        let f = check(
            "fn w(e: &Env, config: Config, m: Address) { \
             e.storage().temporary().set(&StorageKey::MinterStats(config.epoch, m), &1); }",
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn constructor_writes_to_instance_are_bounded() {
        let f = check(
            "#[contractimpl] impl A { pub fn __constructor(e: Env, s: BytesN<32>) { \
             e.storage().instance().set(&DataKey::Signer(s), &()); } }",
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn ignores_intended_temporary_and_correct_tiers() {
        let f = check(
            r#"
fn a(e: &Env, k: AllowanceDataKey, v: AllowanceValue) { e.storage().temporary().set(&DataKey::Allowance(k), &v); }
fn b(e: &Env, n: u64) { e.storage().temporary().set(&DataKey::Nonce(n), &true); }
fn c(e: &Env, a: Address, x: i128) { e.storage().persistent().set(&DataKey::Balance(a), &x); }
fn d(e: &Env, a: Address) { e.storage().instance().set(&DataKey::Admin, &a); }
fn f(e: &Env, x: u32) { e.storage().temporary().set(&DataKey::PriceFeedCache, &x); }
fn g(e: &Env) { e.storage().temporary().remove(&DataKey::Balance(a)); }
fn h(e: &Env) { e.storage().temporary().set(&DataKey::Counter, &1); }
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn options_extend_word_lists() {
        let src = "fn a(e: &Env) { e.storage().temporary().set(&DataKey::Counter, &1); }\n\
                   fn b(e: &Env) { e.storage().temporary().set(&DataKey::Balance(x), &1); }";
        let mut s = Settings::default();
        let opts = &mut s.rule_mut("SG-002").options;
        opts.insert("sensitive-keys".into(), toml::Value::Array(vec!["Counter".into()]));
        opts.insert("ignore-keys".into(), toml::Value::Array(vec!["balance".into()]));
        let f = run_with(Box::new(StorageTierMisuse), src, soroban_crate(Some(true)), &s);
        assert_eq!(lines(&f), vec![1]);
    }
}
