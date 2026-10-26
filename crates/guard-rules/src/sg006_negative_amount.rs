//! SG-006: signed amounts that move funds or update balances without a sign check.

use std::collections::HashSet;

use guard_engine::{Confidence, Diagnostic, Rule, RuleContext, RuleMeta, RuleOption, Severity};
use guard_parser::syntax::{as_local_ident, compact, macro_args, resolved_idents, strip, Bindings};
use guard_parser::{CrateModel, FnId};
use syn::visit::Visit;
use syn::{BinOp, Expr};

pub struct NegativeAmount;

static META: RuleMeta = RuleMeta {
    id: "SG-006",
    name: "negative-amount",
    summary: "Signed amount not checked for negative values",
    description: "Soroban token amounts are `i128`, so they can be negative. An exported function that writes an \
`i128` parameter into contract storage (balances, shares, debts, limits), directly or through helpers, without \
checking its sign lets a caller invert the operation: a negative mint burns, a negative deposit credits less than \
zero, a negative debt repayment borrows. Amounts that are also passed to an external token call are not \
reported, because token contracts reject negative amounts and the whole invocation fails.",
    remediation: "Reject negative (and usually zero) amounts before using them, e.g. \
`if amount <= 0 { panic_with_error!(&env, Error::InvalidAmount) }`, or use an unsigned type.",
    default_severity: Severity::Warning,
    tags: &["security", "input-validation", "arithmetic"],
    options: &[RuleOption {
        name: "ignore-params",
        description: "Parameter names that may legitimately be negative (e.g. signed deltas).",
        default: "[]",
    }],
};

/// Token-client methods that reject negative amounts.
const VALUE_METHODS: &[&str] = &["transfer", "transfer_from", "mint", "burn", "burn_from", "clawback", "approve"];

impl Rule for NegativeAmount {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>) {
        if !cx.is_soroban() {
            return;
        }
        let ignored = cx.options.string_list("ignore-params");
        let model = cx.model;
        for (id, f) in model.fns_in_file(cx.file_idx) {
            if !f.is_contract_export() || matches!(f.name.as_str(), "__constructor" | "__check_auth") {
                continue;
            }
            let mut checked = sign_checked_params(model, id, &mut HashSet::new());
            checked.extend(token_checked_params(model, id, &mut HashSet::new()));
            for (i, (name, ty)) in f.params().into_iter().enumerate() {
                if compact(ty).trim_start_matches('&') != "i128" || ignored.contains(&name) || checked.contains(&i) {
                    continue;
                }
                let Some(use_span) = value_use(model, id, &name) else { continue };
                // Only a stored admin (or other non-parameter address) authorizes: a negative value
                // is a configuration mistake rather than an attack.
                let auth = model.subject_auth(id);
                let admin_only = auth.other && auth.params.is_empty();
                let (confidence, note) =
                    if admin_only { (Confidence::Low, " (admin-only function)") } else { (Confidence::Medium, "") };
                let mut d = Diagnostic::new(
                    use_span,
                    format!("`{}` stores or accounts `{name}: i128` without rejecting negative values{note}", f.name),
                    confidence,
                );
                if admin_only {
                    d = d.with_severity(Severity::Info);
                }
                out.push(d.in_function(&f.name).with_help(format!(
                    "Add `if {name} <= 0 {{ panic_with_error!(..) }}` (or `< 0` if zero is allowed) before using it."
                )));
            }
        }
    }
}

/// Where `name` updates contract storage: written directly, or passed to a crate
/// helper that writes storage.
fn value_use(model: &CrateModel<'_>, id: FnId, name: &str) -> Option<guard_parser::Span> {
    let facts = &model.facts[id];
    if let Some(w) = facts.state_writes.iter().find(|w| w.value_locals.iter().any(|v| v == name)) {
        return Some(w.span);
    }
    for call in &facts.calls {
        if !call.args.iter().any(|a| a.mentions.iter().any(|m| m == name)) {
            continue;
        }
        let writes = model
            .resolve(id, call)
            .into_iter()
            .any(|callee| model.reachable(callee).into_iter().any(|r| !model.facts[r].state_writes.is_empty()));
        if writes {
            return Some(call.span);
        }
    }
    None
}

/// Indices of `id`'s parameters passed as the amount of an external token call
/// (`token.transfer(&from, &to, &amount)`), directly or through helpers. Token
/// contracts reject negative amounts, so the whole invocation fails.
fn token_checked_params(model: &CrateModel<'_>, id: FnId, stack: &mut HashSet<FnId>) -> HashSet<usize> {
    let mut out = HashSet::new();
    if stack.len() > 16 || !stack.insert(id) {
        return out;
    }
    let params = model.param_names(id);
    let bindings = Bindings::collect(model.fns[id].block);
    // Parameters an argument is derived from: the local itself if it is a parameter, plus
    // parameters in its initializer (`let out_a = balance_a * share_amount / total`).
    let all_bindings = bindings.iter();
    let sources = |local: &str| -> Vec<usize> {
        let mut names = vec![local.to_string()];
        for (_, init) in all_bindings.iter().filter(|(n, _)| *n == local) {
            names.extend(resolved_idents(init, &bindings));
        }
        names.iter().filter_map(|n| params.iter().position(|p| p == n)).collect()
    };
    for call in &model.facts[id].calls {
        let callees = model.resolve(id, call);
        if callees.is_empty() && call.is_method && VALUE_METHODS.contains(&call.name.as_str()) {
            out.extend(call.args.iter().filter_map(|a| a.local.as_deref()).flat_map(sources));
            continue;
        }
        for callee in callees {
            for j in token_checked_params(model, callee, stack) {
                if let Some(local) = call.args.get(j).and_then(|a| a.local.as_deref()) {
                    out.extend(sources(local));
                }
            }
        }
    }
    stack.remove(&id);
    out
}

/// Indices of `id`'s parameters compared with zero (`amount < 0`, `assert!(amount > 0)`,
/// `amount.is_negative()`), directly or in a helper they are passed to
/// (`check_nonnegative_amount(amount)`).
fn sign_checked_params(model: &CrateModel<'_>, id: FnId, stack: &mut HashSet<FnId>) -> HashSet<usize> {
    let mut out = HashSet::new();
    if stack.len() > 16 || !stack.insert(id) {
        return out;
    }
    let def = &model.fns[id];
    let params = model.param_names(id);
    let mut v = ZeroChecks::default();
    v.visit_block(def.block);
    for (i, p) in params.iter().enumerate() {
        if v.names.contains(p) {
            out.insert(i);
        }
    }
    for call in &model.facts[id].calls {
        for callee in model.resolve(id, call) {
            for j in sign_checked_params(model, callee, stack) {
                if let Some(i) =
                    call.args.get(j).and_then(|a| a.local.as_deref()).and_then(|n| params.iter().position(|p| p == n))
                {
                    out.insert(i);
                }
            }
        }
    }
    stack.remove(&id);
    out
}

#[derive(Default)]
struct ZeroChecks {
    names: HashSet<String>,
}

/// `0`, `0i128`, `0_i128`.
fn is_zero(e: &Expr) -> bool {
    matches!(strip(e), Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) if i.base10_digits() == "0")
}

impl<'ast> Visit<'ast> for ZeroChecks {
    fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
        if matches!(b.op, BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_)) {
            if is_zero(&b.right) {
                if let Some(n) = as_local_ident(&b.left) {
                    self.names.insert(n);
                }
            }
            if is_zero(&b.left) {
                if let Some(n) = as_local_ident(&b.right) {
                    self.names.insert(n);
                }
            }
        }
        syn::visit::visit_expr_binary(self, b);
    }

    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        if matches!(m.method.to_string().as_str(), "is_negative" | "is_positive" | "signum") {
            if let Some(n) = as_local_ident(&m.receiver) {
                self.names.insert(n);
            }
        }
        syn::visit::visit_expr_method_call(self, m);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        // `assert!(amount > 0)`, `require!(..)` and the like.
        for a in macro_args(mac) {
            self.visit_expr(&a);
        }
    }

    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(NegativeAmount), src)
    }

    #[test]
    fn flags_unchecked_signed_amounts() {
        let f = check(
            r#"
fn write_balance(e: &Env, a: &Address, v: i128) { e.storage().persistent().set(&K::Bal(a.clone()), &v); }
#[contractimpl]
impl Vault {
    pub fn mint(e: Env, to: Address, amount: i128) {
        write_balance(&e, &to, amount);
    }
    pub fn set_debt(e: Env, who: Address, debt: i128) {
        e.storage().persistent().set(&K::Debt(who), &debt);
    }
    pub fn deposit(e: Env, from: Address, amount: i128) {
        from.require_auth();
        token::Client::new(&e, &t).transfer(&from, &e.current_contract_address(), &amount);
        write_balance(&e, &from, amount);
    }
}
"#,
        );
        assert_eq!(lines(&f), vec![6, 9], "{f:#?}");
        assert!(f[0].message.contains("`amount: i128`"));
    }

    #[test]
    fn sign_checks_directly_or_in_helpers() {
        let f = check(
            r#"
fn check_nonnegative_amount(amount: i128) { if amount < 0 { panic!("negative amount is not allowed: {}", amount) } }
#[contractimpl]
impl Token {
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        check_nonnegative_amount(amount);
        spend(&e, from, amount);
    }
    pub fn deposit(e: Env, from: Address, amount: i128) {
        assert!(amount > 0, "amount");
        token::Client::new(&e, &t).transfer(&from, &e.current_contract_address(), &amount);
    }
    pub fn burn(e: Env, from: Address, amount: i128) {
        if amount.is_negative() { panic!() }
        token::Client::new(&e, &t).burn(&from, &amount);
    }
    pub fn delta(e: Env, from: Address, change: i128) {
        spend(&e, from, change);
    }
    pub fn view(e: Env, amount: i128) -> i128 { amount * 2 }
    pub fn count(e: Env, n: u64) { e.storage().instance().set(&K::N, &n); }
}
fn spend(e: &Env, a: Address, v: i128) { e.storage().persistent().set(&K::Bal(a), &v); }
"#,
        );
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].function.as_deref(), Some("delta"));
    }

    #[test]
    fn derived_token_amounts_and_admin_only_functions() {
        let f = check(
            r#"
fn transfer_a(e: &Env, to: Address, amount: i128) { token::Client::new(e, &t).transfer(&e.current_contract_address(), &to, &amount); }
fn burn_shares(e: &Env, from: &Address, amount: i128) { e.storage().persistent().set(&K::Shares(from.clone()), &amount); }
#[contractimpl]
impl Pool {
    pub fn withdraw(e: Env, to: Address, share_amount: i128) {
        to.require_auth();
        let out_a = (get_balance(&e) * share_amount) / total(&e);
        burn_shares(&e, &to, share_amount);
        transfer_a(&e, to, out_a);
    }
    pub fn set_limit(e: Env, limit: i128) {
        let admin: Address = e.storage().instance().get(&K::Admin).unwrap();
        admin.require_auth();
        e.storage().instance().set(&K::Limit, &limit);
    }
}
"#,
        );
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].function.as_deref(), Some("set_limit"));
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn ignore_params_option() {
        let mut s = guard_engine::Settings::default();
        s.rule_mut("SG-006").options.insert("ignore-params".into(), toml::Value::Array(vec!["change".into()]));
        let f = run_with(
            Box::new(NegativeAmount),
            "#[contractimpl] impl C { pub fn d(e: Env, a: Address, change: i128) { e.storage().persistent().set(&K::D(a), &change); } }",
            soroban_crate(Some(false)),
            &s,
        );
        assert!(f.is_empty());
    }
}
