//! SG-004: loops whose length is controlled by storage growth or by the caller.

use std::collections::{BTreeMap, HashSet};

use guard_engine::{Confidence, Diagnostic, Rule, RuleContext, RuleMeta, Severity};
use guard_parser::syntax::{
    as_local_ident, call_name, chain_root, idents, is_assert_macro, is_collection_type, is_integer_type, macro_args,
    macro_name, method_chain, storage_op, strip, Bindings,
};
use guard_parser::{CrateModel, FnDef, Span};
use syn::visit::Visit;
use syn::{BinOp, Expr};

pub struct UnboundedIteration;

static META: RuleMeta = RuleMeta {
    id: "SG-004",
    name: "unbounded-iteration",
    summary: "Potentially unbounded iteration",
    description: "A loop or iterator chain walks a collection that is loaded from contract storage, or a \
collection / count supplied by the caller, without an upper bound check. Soroban transactions have hard CPU, \
memory and ledger-read limits. If a stored collection can grow without limit (for example, anyone can append to a \
list of users), the function will eventually exceed those limits and become permanently uncallable, which can \
lock funds. Caller-supplied sizes let a single caller force expensive work.",
    remediation: "Check `len()` (or the count) against a maximum before looping, paginate with \
`start`/`limit` arguments, or store each entry under its own key instead of one growing `Vec`/`Map`.",
    default_severity: Severity::Warning,
    tags: &["security", "denial-of-service", "resource-limits"],
    options: &[],
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Loaded from contract storage.
    Storage,
    /// A collection parameter of an exported function.
    ParamCollection,
    /// An integer parameter of an exported function used as a loop bound.
    ParamCount,
}

impl Source {
    fn describe(self, name: &str) -> (String, Confidence) {
        match self {
            Source::Storage => (
                format!("Loop iterates over `{name}`, a collection loaded from contract storage, without a size bound"),
                Confidence::High,
            ),
            Source::ParamCollection => (
                format!("Loop iterates over caller-supplied collection `{name}` without a length check"),
                Confidence::Low,
            ),
            Source::ParamCount => (
                format!("Loop bound `{name}` is supplied by the caller and never checked against a maximum"),
                Confidence::Low,
            ),
        }
    }
}

/// Iterator methods that walk every element.
const CONSUMERS: &[&str] = &[
    "for_each",
    "try_for_each",
    "fold",
    "try_fold",
    "map",
    "filter",
    "filter_map",
    "sum",
    "product",
    "count",
    "any",
    "all",
    "find",
    "position",
    "max",
    "min",
    "max_by_key",
    "min_by_key",
    "collect",
    "last",
];
/// Methods that produce an iterator from a collection.
const ITER_SOURCES: &[&str] = &["iter", "into_iter", "keys", "values", "iter_mut"];
/// Methods that bound an iterator.
const LIMITERS: &[&str] = &["take", "step_by", "first", "nth"];

impl Rule for UnboundedIteration {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>) {
        if !cx.is_soroban() {
            return;
        }
        for (_, f) in cx.model.fns_in_file(cx.file_idx) {
            let bindings = Bindings::collect(f.block);
            let sources = collect_sources(f, &bindings, cx.model);
            if sources.is_empty() && !has_direct_storage_iteration(f.block) {
                continue;
            }
            let bounded = collect_bound_checks(f.block);
            let mut v = LoopVisitor {
                sources: &sources,
                bounded: &bounded,
                bindings: &bindings,
                function: &f.name,
                reported_lines: HashSet::new(),
                out: &mut *out,
            };
            v.visit_block(f.block);
        }
    }
}

fn has_direct_storage_iteration(block: &syn::Block) -> bool {
    // Cheap pre-filter: any storage access at all.
    idents(block).iter().any(|i| i == "storage")
}

fn collect_sources(f: &FnDef<'_>, bindings: &Bindings<'_>, model: &CrateModel<'_>) -> BTreeMap<String, Source> {
    let mut sources = BTreeMap::new();
    // Constructor arguments come from the deployer and `__check_auth` contexts are
    // bounded by the transaction itself, so their parameters are not caller-controlled.
    let caller_controlled = f.is_contract_export() && !matches!(f.name.as_str(), "__constructor" | "__check_auth");
    if caller_controlled {
        for (name, ty) in f.params() {
            if is_collection_type(ty) {
                sources.insert(name, Source::ParamCollection);
            } else if is_integer_type(ty) {
                sources.insert(name, Source::ParamCount);
            }
        }
    }
    for (name, init) in bindings.iter() {
        if expr_loads_storage(init, bindings, model) && !capped_where_written(name, model) {
            sources.insert(name.to_string(), Source::Storage);
        }
    }
    sources
}

/// `true` if some storage-writing function in the crate checks `<name>.len()`
/// against a bound, i.e. the collection is capped where it grows
/// (`if modules.len() >= MAX_MODULES { return Err(..) }` before `set`).
fn capped_where_written(name: &str, model: &CrateModel<'_>) -> bool {
    model.facts.iter().any(|f| !f.state_writes.is_empty() && f.len_bounds.iter().any(|n| n == name))
}

/// `true` if `expr` reads from storage directly, or calls a crate helper that
/// returns a collection and (transitively) reads storage.
fn expr_loads_storage(expr: &Expr, bindings: &Bindings<'_>, model: &CrateModel<'_>) -> bool {
    struct V<'x, 'a, 'm> {
        bindings: &'x Bindings<'a>,
        model: &'x CrateModel<'m>,
        hit: bool,
    }
    impl<'ast> Visit<'ast> for V<'_, '_, '_> {
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            if storage_op(m, self.bindings).is_some_and(|op| op.kind == guard_parser::StorageOpKind::Get) {
                self.hit = true;
            }
            syn::visit::visit_expr_method_call(self, m);
        }
        fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
            if let Some(name) = call_name(c) {
                for &id in self.model.by_name(&name) {
                    let def = &self.model.fns[id];
                    let returns_collection = match &def.sig.output {
                        syn::ReturnType::Type(_, ty) => is_collection_type(ty),
                        syn::ReturnType::Default => false,
                    };
                    if returns_collection && self.model.reads_storage(id) {
                        self.hit = true;
                    }
                }
            }
            syn::visit::visit_expr_call(self, c);
        }
    }
    let mut v = V { bindings, model, hit: false };
    v.visit_expr(expr);
    v.hit
}

/// Names compared in `if` conditions or assertion macros (`if items.len() > MAX`).
fn collect_bound_checks(block: &syn::Block) -> HashSet<String> {
    struct C {
        names: HashSet<String>,
        in_cond: usize,
    }
    impl<'ast> Visit<'ast> for C {
        fn visit_expr_if(&mut self, e: &'ast syn::ExprIf) {
            self.in_cond += 1;
            self.visit_expr(&e.cond);
            self.in_cond -= 1;
            self.visit_block(&e.then_branch);
            if let Some((_, els)) = &e.else_branch {
                self.visit_expr(els);
            }
        }
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if let Some((_, g)) = &arm.guard {
                self.in_cond += 1;
                self.visit_expr(g);
                self.in_cond -= 1;
            }
            self.visit_expr(&arm.body);
        }
        fn visit_macro(&mut self, m: &'ast syn::Macro) {
            let assert = is_assert_macro(&macro_name(m));
            if assert {
                self.in_cond += 1;
            }
            for a in macro_args(m) {
                self.visit_expr(&a);
            }
            if assert {
                self.in_cond -= 1;
            }
        }
        fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
            if self.in_cond > 0 && matches!(b.op, BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_)) {
                self.names.extend(idents(&*b.left));
                self.names.extend(idents(&*b.right));
            }
            syn::visit::visit_expr_binary(self, b);
        }
    }
    let mut c = C { names: HashSet::new(), in_cond: 0 };
    c.visit_block(block);
    c.names
}

struct LoopVisitor<'a, 'b> {
    sources: &'a BTreeMap<String, Source>,
    bounded: &'a HashSet<String>,
    bindings: &'a Bindings<'b>,
    function: &'a str,
    reported_lines: HashSet<usize>,
    out: &'a mut Vec<Diagnostic>,
}

impl LoopVisitor<'_, '_> {
    /// Classifies the collection an iterable expression walks.
    fn classify(&self, iterable: &Expr) -> Option<(String, Source)> {
        let e = strip(iterable);
        if let Expr::Range(r) = e {
            let end = r.end.as_deref()?;
            return self.classify_root(end, true);
        }
        let chain = method_chain(e);
        if chain.iter().any(|m| LIMITERS.contains(&m.as_str())) {
            return None;
        }
        self.classify_root(e, false)
    }

    fn classify_root(&self, e: &Expr, is_range_end: bool) -> Option<(String, Source)> {
        // Direct storage read: `for x in env.storage().persistent().get(..).unwrap()`.
        let mut probe = e;
        while let Expr::MethodCall(m) = strip(probe) {
            if storage_op(m, self.bindings).is_some_and(|op| op.kind == guard_parser::StorageOpKind::Get) {
                let key =
                    m.args.first().map(|a| guard_parser::syntax::compact(strip(a))).unwrap_or_else(|| "storage".into());
                return Some((key, Source::Storage));
            }
            probe = &m.receiver;
        }
        let root = chain_root(e);
        let name = as_local_ident(root)?;
        let source = *self.sources.get(&name)?;
        match source {
            Source::ParamCount if !is_range_end => None,
            _ if self.bounded.contains(&name) => None,
            _ => Some((name, source)),
        }
    }

    fn report(&mut self, span: Span, name: &str, source: Source) {
        if !self.reported_lines.insert(span.start.line) {
            return;
        }
        let (msg, confidence) = source.describe(name);
        let mut d = Diagnostic::new(span, msg, confidence).in_function(self.function);
        if source != Source::Storage {
            // The caller pays for their own oversized input: a hardening hint rather than a
            // denial of service against other users.
            d = d.with_severity(Severity::Info);
        }
        self.out.push(d);
    }
}

impl<'ast> Visit<'ast> for LoopVisitor<'_, '_> {
    fn visit_expr_for_loop(&mut self, l: &'ast syn::ExprForLoop) {
        if let Some((name, source)) = self.classify(&l.expr) {
            self.report(Span::of(&l.for_token), &name, source);
        }
        syn::visit::visit_expr_for_loop(self, l);
    }

    fn visit_expr_while(&mut self, w: &'ast syn::ExprWhile) {
        if let Expr::Binary(b) = strip(&w.cond) {
            if matches!(b.op, BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_)) {
                for side in [&b.left, &b.right] {
                    if let Some((name, source)) = self.classify_root(side, true) {
                        self.report(Span::of(&w.while_token), &name, source);
                        break;
                    }
                }
            }
        }
        syn::visit::visit_expr_while(self, w);
    }

    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        let name = m.method.to_string();
        if CONSUMERS.contains(&name.as_str()) {
            let chain = method_chain(&m.receiver);
            let iterates = chain.iter().any(|c| ITER_SOURCES.contains(&c.as_str()));
            if iterates {
                if let Some((n, source)) = self.classify(&m.receiver) {
                    if source != Source::ParamCount {
                        self.report(Span::of(&m.method), &n, source);
                    }
                }
            }
        }
        syn::visit::visit_expr_method_call(self, m);
    }

    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(UnboundedIteration), src)
    }

    #[test]
    fn flags_storage_backed_loops() {
        let f = check(
            r#"
fn read_users(e: &Env) -> Vec<Address> { e.storage().persistent().get(&DataKey::Users).unwrap() }
#[contractimpl]
impl C {
    pub fn distribute(e: Env) {
        let users: Vec<Address> = e.storage().persistent().get(&DataKey::Users).unwrap();
        for u in users.iter() {
            pay(&e, &u);
        }
    }
    pub fn total(e: Env) -> i128 {
        let users = read_users(&e);
        users.iter().map(|u| balance(&e, u)).sum()
    }
    pub fn direct(e: Env) {
        for x in e.storage().instance().get::<_, Vec<u32>>(&DataKey::List).unwrap() { log(x); }
    }
}
"#,
        );
        assert_eq!(lines(&f), vec![7, 13, 16]);
        assert!(f.iter().all(|x| x.confidence == Confidence::High));
        assert!(f[0].message.contains("`users`"));
    }

    #[test]
    fn flags_caller_supplied_sizes() {
        let f = check(
            r#"
#[contractimpl]
impl C {
    pub fn batch(e: Env, recipients: Vec<Address>) {
        for r in recipients.iter() { pay(&e, &r); }
    }
    pub fn spin(e: Env, count: u32) {
        for i in 0..count { work(&e, i); }
    }
    pub fn spin2(e: Env, n: u32) {
        let mut i = 0;
        while i < n { i += 1; }
    }
}
"#,
        );
        assert_eq!(lines(&f), vec![5, 8, 12]);
        assert!(f.iter().all(|x| x.confidence == Confidence::Low && x.severity == Severity::Info));
    }

    #[test]
    fn constructor_and_check_auth_params_are_not_caller_controlled() {
        let f = check(
            r#"
#[contractimpl]
impl Account {
    pub fn __constructor(e: Env, signers: Vec<BytesN<32>>) {
        for s in signers.iter() { e.storage().instance().set(&DataKey::Signer(s), &()); }
    }
    pub fn __check_auth(e: Env, payload: Hash<32>, sig: Sig, auth_context: Vec<Context>) {
        for c in auth_context.iter() { verify(&e, &c); }
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn ignores_bounded_loops() {
        let f = check(
            r#"
const MAX: u32 = 50;
#[contractimpl]
impl C {
    pub fn batch(e: Env, recipients: Vec<Address>) {
        if recipients.len() > MAX { panic!("too many") }
        for r in recipients.iter() { pay(&e, &r); }
    }
    pub fn page(e: Env, start: u32, limit: u32) {
        assert!(limit <= MAX);
        let users: Vec<Address> = e.storage().persistent().get(&DataKey::Users).unwrap();
        for i in start..limit { pay(&e, &users.get(i).unwrap()); }
    }
    pub fn first_few(e: Env) {
        let users: Vec<Address> = e.storage().persistent().get(&DataKey::Users).unwrap();
        for u in users.iter().take(10) { pay(&e, &u); }
    }
    pub fn fixed(e: Env) {
        for i in 0..10 { work(&e, i); }
        let local = vec![&e, 1, 2, 3];
        for x in local.iter() { work(&e, x); }
    }
    pub fn add_member(e: Env, m: Address) {
        let mut members: Vec<Address> = e.storage().persistent().get(&DataKey::Members).unwrap();
        if members.len() >= MAX { panic!("full") }
        members.push_back(m);
        e.storage().persistent().set(&DataKey::Members, &members);
    }
    pub fn pay_members(e: Env) {
        let members: Vec<Address> = e.storage().persistent().get(&DataKey::Members).unwrap();
        for m in members.iter() { pay(&e, &m); }
    }
    pub fn opt(e: Env) -> Option<u32> {
        let v: Option<u32> = e.storage().instance().get(&DataKey::X);
        v.map(|x| x + 1)
    }
}
fn helper(items: Vec<u32>) { for i in items.iter() { work(i); } }
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }
}
