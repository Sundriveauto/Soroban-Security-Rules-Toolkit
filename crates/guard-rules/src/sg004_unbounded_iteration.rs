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
        let mut capped = None;
        for (_, f) in cx.model.fns_in_file(cx.file_idx) {
            let bindings = Bindings::collect(f.block);
            let sources = collect_sources(f, &bindings, cx.model, &mut capped);
            if sources.is_empty() && !has_direct_storage_iteration(f.block) {
                continue;
            }
            let bounded = collect_bound_checks(f.block);
            let capped_keys = capped.get_or_insert_with(|| capped_keys(cx.model));
            let mut v = LoopVisitor {
                sources: &sources,
                bounded: &bounded,
                capped_keys,
                model: cx.model,
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

fn collect_sources(
    f: &FnDef<'_>,
    bindings: &Bindings<'_>,
    model: &CrateModel<'_>,
    capped: &mut Option<HashSet<String>>,
) -> BTreeMap<String, Source> {
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
        if !length_from_storage(init, bindings, model, 0) || capped_where_written(name, model) {
            continue;
        }
        let capped = capped.get_or_insert_with(|| capped_keys(model));
        let keys = loaded_keys(init, bindings, model);
        if !keys.is_empty() && keys.iter().all(|k| capped.contains(k)) {
            continue;
        }
        sources.insert(name.to_string(), Source::Storage);
    }
    sources
}

/// Locals whose length a function checks, directly (`if v.len() >= MAX`) or by
/// passing them to a helper that checks its parameter.
fn bounded_locals(model: &CrateModel<'_>, id: usize) -> HashSet<String> {
    let f = &model.facts[id];
    let mut out: HashSet<String> = f.len_bounds.iter().cloned().collect();
    for call in &f.calls {
        for (j, arg) in call.args.iter().enumerate() {
            let Some(local) = &arg.local else { continue };
            let checked = model.resolve(id, call).into_iter().any(|callee| {
                model.param_names(callee).get(j).is_some_and(|p| model.facts[callee].len_bounds.contains(p))
            });
            if checked {
                out.insert(local.clone());
            }
        }
    }
    out
}

/// Storage keys (most specific name) whose stored collection is length-checked
/// where it is written: the written value is built from a bounded local.
fn capped_keys(model: &CrateModel<'_>) -> HashSet<String> {
    let mut out = HashSet::new();
    for (id, f) in model.facts.iter().enumerate() {
        if f.state_writes.is_empty() {
            continue;
        }
        let bounded = bounded_locals(model, id);
        if bounded.is_empty() {
            continue;
        }
        for w in &f.state_writes {
            if w.value_locals.iter().any(|v| bounded.contains(v)) {
                if let Some(k) = w.key_idents.last() {
                    out.insert(k.clone());
                }
            }
        }
    }
    out
}

/// Storage keys read by `expr`, directly or through crate helpers it calls.
fn loaded_keys<'a>(expr: &'a Expr, bindings: &Bindings<'a>, model: &CrateModel<'_>) -> Vec<String> {
    struct V<'x, 'a, 'm> {
        bindings: &'x Bindings<'a>,
        model: &'x CrateModel<'m>,
        keys: Vec<String>,
        /// Locals followed so far (a collection derived from another local inherits its keys).
        followed: usize,
    }
    impl<'ast> Visit<'ast> for V<'_, 'ast, '_> {
        fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
            let e = Expr::Path(p.clone());
            if self.followed < 8 {
                if let Some(init) = self.bindings.resolve(&e) {
                    self.followed += 1;
                    self.visit_expr(init);
                }
            }
        }
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            if let Some(op) = storage_op(m, self.bindings) {
                if op.kind == guard_parser::StorageOpKind::Get {
                    if let Some(k) = op.key().and_then(|k| {
                        guard_parser::model::resolve_const_key(
                            guard_parser::syntax::key_names(k, self.bindings),
                            &self.model.consts,
                        )
                        .pop()
                    }) {
                        self.keys.push(k);
                    }
                }
            }
            syn::visit::visit_expr_method_call(self, m);
        }
        fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
            if let Some(name) = call_name(c) {
                for &id in self.model.by_name(&name) {
                    // One level of helpers plus whatever they read directly or via witness.
                    let mut stack = vec![id];
                    let mut seen = HashSet::new();
                    while let Some(f) = stack.pop() {
                        if !seen.insert(f) || seen.len() > 32 {
                            continue;
                        }
                        self.keys.extend(self.model.facts[f].read_keys.iter().cloned());
                        for call in &self.model.facts[f].calls {
                            stack.extend(self.model.resolve(f, call));
                        }
                    }
                }
            }
            syn::visit::visit_expr_call(self, c);
        }
    }
    let mut v = V { bindings, model, keys: Vec::new(), followed: 0 };
    v.visit_expr(expr);
    v.keys.sort();
    v.keys.dedup();
    v.keys
}

/// `true` if some storage-writing function in the crate checks `<name>.len()`
/// against a bound, i.e. the collection is capped where it grows
/// (`if modules.len() >= MAX_MODULES { return Err(..) }` before `set`).
///
/// The check may also live in a helper the collection is passed to
/// (`assert_cap(&list)` where `assert_cap` compares `v.len()` to a maximum).
fn capped_where_written(name: &str, model: &CrateModel<'_>) -> bool {
    model.facts.iter().enumerate().any(|(id, f)| {
        if f.state_writes.is_empty() {
            return false;
        }
        if f.len_bounds.iter().any(|n| n == name) {
            return true;
        }
        f.calls.iter().any(|call| {
            call.args.iter().enumerate().any(|(j, arg)| {
                arg.local.as_deref() == Some(name)
                    && model.resolve(id, call).into_iter().any(|callee| {
                        model.param_names(callee).get(j).is_some_and(|p| model.facts[callee].len_bounds.contains(p))
                    })
            })
        })
    })
}

/// Methods whose result has (at most) the length of their receiver.
const LENGTH_PRESERVING: &[&str] = &[
    "iter",
    "into_iter",
    "iter_mut",
    "keys",
    "values",
    "map",
    "filter",
    "filter_map",
    "cloned",
    "copied",
    "enumerate",
    "rev",
    "skip",
    "inspect",
    "collect",
    "to_vec",
    "clone",
    "into",
    "unwrap",
    "unwrap_or",
    "unwrap_or_else",
    "unwrap_or_default",
    "expect",
    "ok",
    "ok_or",
    "ok_or_else",
    "as_ref",
];

/// `true` if the length of the collection `expr` evaluates to is controlled by
/// contract storage: a stored collection, or one built element-wise from it.
///
/// A collection mapped from a parameter (`Vec::from_iter(e, ids.iter().map(|id| load(id)))`)
/// or returned by a cross-contract call has the length of that input, even when
/// its elements are read from storage.
fn length_from_storage(expr: &Expr, bindings: &Bindings<'_>, model: &CrateModel<'_>, depth: usize) -> bool {
    if depth > 6 {
        return false;
    }
    let e = strip(expr);
    match e {
        Expr::MethodCall(m) => {
            if let Some(op) = storage_op(m, bindings) {
                return op.kind == guard_parser::StorageOpKind::Get;
            }
            LENGTH_PRESERVING.contains(&m.method.to_string().as_str())
                && length_from_storage(&m.receiver, bindings, model, depth)
        }
        Expr::Call(c) => {
            let Some(name) = call_name(c) else { return false };
            if name == "from_iter" {
                return c.args.last().is_some_and(|a| length_from_storage(a, bindings, model, depth));
            }
            model.by_name(&name).iter().any(|&id| returns_stored_collection(id, model, depth + 1))
        }
        Expr::Path(_) => bindings
            .resolve(e)
            .is_some_and(|init| !std::ptr::eq(strip(init), e) && length_from_storage(init, bindings, model, depth + 1)),
        Expr::Block(b) => block_tail(&b.block).is_some_and(|t| length_from_storage(t, bindings, model, depth)),
        Expr::If(i) => {
            let then = block_tail(&i.then_branch);
            // `if let Some(v) = storage.get(..) { v } else { .. }`
            let from_pattern = match (strip(&i.cond), then.and_then(as_local_ident)) {
                (Expr::Let(l), Some(name)) => {
                    pat_binds(&l.pat, &name) && length_from_storage(&l.expr, bindings, model, depth + 1)
                }
                _ => false,
            };
            from_pattern
                || then.is_some_and(|t| length_from_storage(t, bindings, model, depth))
                || i.else_branch.as_ref().is_some_and(|(_, els)| length_from_storage(els, bindings, model, depth))
        }
        // `match storage.get(..) { Some(v) => v, None => .. }`
        Expr::Match(m) => m.arms.iter().any(|a| {
            let bound = as_local_ident(&a.body).is_some_and(|name| pat_binds(&a.pat, &name));
            if bound {
                length_from_storage(&m.expr, bindings, model, depth + 1)
            } else {
                length_from_storage(&a.body, bindings, model, depth)
            }
        }),
        _ => false,
    }
}

/// `true` if pattern `pat` binds `name` (`Some(name)`, `Ok(mut name)`, …).
fn pat_binds(pat: &syn::Pat, name: &str) -> bool {
    struct P<'n> {
        name: &'n str,
        hit: bool,
    }
    impl<'ast> Visit<'ast> for P<'_> {
        fn visit_pat_ident(&mut self, p: &'ast syn::PatIdent) {
            if p.ident == self.name {
                self.hit = true;
            }
            syn::visit::visit_pat_ident(self, p);
        }
    }
    let mut p = P { name, hit: false };
    p.visit_pat(pat);
    p.hit
}

fn block_tail(b: &syn::Block) -> Option<&Expr> {
    match b.stmts.last()? {
        syn::Stmt::Expr(e, None) => Some(e),
        _ => None,
    }
}

/// `true` if crate function `id` returns a collection whose length comes from storage.
fn returns_stored_collection(id: usize, model: &CrateModel<'_>, depth: usize) -> bool {
    let def = &model.fns[id];
    let returns_collection = match &def.sig.output {
        syn::ReturnType::Type(_, ty) => is_collection_type(ty),
        syn::ReturnType::Default => false,
    };
    if !returns_collection || !model.reads_storage(id) {
        return false;
    }
    struct Returns<'a> {
        out: Vec<&'a Expr>,
    }
    impl<'a> Visit<'a> for Returns<'a> {
        fn visit_expr_return(&mut self, r: &'a syn::ExprReturn) {
            if let Some(e) = &r.expr {
                self.out.push(e);
            }
        }
        fn visit_expr_closure(&mut self, _: &'a syn::ExprClosure) {}
        fn visit_item_fn(&mut self, _: &'a syn::ItemFn) {}
    }
    let mut r = Returns { out: block_tail(def.block).into_iter().collect() };
    r.visit_block(def.block);
    let bindings = Bindings::collect(def.block);
    r.out.iter().any(|e| length_from_storage(e, &bindings, model, depth))
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
            if self.in_cond > 0 {
                if matches!(b.op, BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_)) {
                    self.names.extend(idents(&*b.left));
                    self.names.extend(idents(&*b.right));
                } else if matches!(b.op, BinOp::Eq(_) | BinOp::Ne(_)) {
                    // Equality bounds only a `.len()` operand (`if v.len() == MAX`).
                    for side in [&*b.left, &*b.right] {
                        if let Expr::MethodCall(m) = strip(side) {
                            if m.method == "len" {
                                self.names.extend(idents(&*m.receiver));
                            }
                        }
                    }
                }
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
    /// Storage keys whose collection is length-checked where it is written.
    capped_keys: &'a HashSet<String>,
    model: &'a CrateModel<'b>,
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
            if let Some(op) = storage_op(m, self.bindings).filter(|op| op.kind == guard_parser::StorageOpKind::Get) {
                let capped = op.key().and_then(|k| {
                    guard_parser::model::resolve_const_key(
                        guard_parser::syntax::key_names(k, self.bindings),
                        &self.model.consts,
                    )
                    .pop()
                });
                if capped.is_some_and(|k| self.capped_keys.contains(&k)) {
                    return None;
                }
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
    #[test]
    fn cap_checked_where_key_is_written_bounds_reads_under_another_name() {
        let f = check(
            r#"
const MAX: u32 = 10;
fn topics(e: &Env) -> Vec<u32> { e.storage().persistent().get(&K::Topics).unwrap() }
#[contractimpl]
impl C {
    pub fn add(e: Env, t: u32) {
        let mut claim_topics = topics(&e);
        if claim_topics.len() >= MAX { panic!() }
        claim_topics.push_back(t);
        e.storage().persistent().set(&K::Topics, &claim_topics);
    }
    pub fn sum(e: Env) -> u32 {
        let issuer_topics = topics(&e);
        let mut n = 0;
        for t in issuer_topics.iter() { n += t; }
        n
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn equality_cap_where_written_bounds_reads() {
        let f = check(
            r#"
const MAX_ROLES: u32 = 256;
fn roles(e: &Env) -> Vec<Symbol> { e.storage().persistent().get(&K::Roles).unwrap_or_else(|| Vec::new(e)) }
#[contractimpl]
impl C {
    pub fn add(e: Env, r: Symbol) {
        let mut existing_roles = roles(&e);
        if existing_roles.len() == MAX_ROLES { panic!() }
        existing_roles.push_back(r);
        e.storage().persistent().set(&K::Roles, &existing_roles);
    }
    pub fn remove(e: Env, r: Symbol) {
        let mut existing_roles = roles(&e);
        if let Some(i) = existing_roles.iter().position(|x| x == r) { existing_roles.remove(i as u32); }
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn length_follows_the_input_not_the_element_loads() {
        let f = check(
            r#"
fn load_all(e: &Env, ids: &Vec<u32>) -> Vec<Address> {
    Vec::from_iter(e, ids.iter().map(|id| e.storage().persistent().get(&K::Item(id)).unwrap()))
}
fn remote_entries(e: &Env, who: &Address) -> Vec<u32> {
    let registry: Address = e.storage().instance().get(&K::Registry).unwrap();
    RegistryClient::new(e, &registry).entries(who)
}
#[contractimpl]
impl C {
    pub fn a(e: Env) {
        let entry: Entry = e.storage().persistent().get(&K::Entry).unwrap();
        let items = load_all(&e, &entry.ids);
        for i in items.iter() { use_it(&i); }
    }
    pub fn b(e: Env, who: Address) {
        let entries = remote_entries(&e, &who);
        for x in entries.iter() { use_it(&x); }
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn direct_read_of_a_capped_key_is_bounded() {
        let f = check(
            r#"
const MAX: u32 = 20;
#[contractimpl]
impl C {
    pub fn add(e: Env, k: BytesN<32>, a: Address) {
        let key = K::Pairs(k);
        let mut pairs: Vec<Address> = e.storage().persistent().get(&key).unwrap_or_else(|| Vec::new(&e));
        if pairs.len() >= MAX { panic!() }
        pairs.push_back(a);
        e.storage().persistent().set(&key, &pairs);
    }
    pub fn list(e: Env, k: BytesN<32>) -> Vec<Address> {
        let key = K::Pairs(k);
        let it = e.storage().persistent().get::<_, Vec<Address>>(&key).unwrap().iter().map(|a| a);
        Vec::from_iter(&e, it)
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn getter_returning_through_if_let_is_storage_backed() {
        let f = check(
            r#"
fn issuers(e: &Env, t: u32) -> Vec<Address> {
    if let Some(v) = e.storage().persistent().get::<_, Vec<Address>>(&K::Issuers(t)) { v } else { panic!() }
}
fn holders(e: &Env) -> Vec<Address> {
    match e.storage().persistent().get(&K::Holders) { Some(h) => h, None => Vec::new(e) }
}
#[contractimpl]
impl C {
    pub fn a(e: Env, t: u32) { let is = issuers(&e, t); for i in is.iter() { use_it(&i); } }
    pub fn b(e: Env) { let hs = holders(&e); for h in hs.iter() { use_it(&h); } }
}
"#,
        );
        assert_eq!(lines(&f), vec![10, 11], "{f:#?}");
    }

    #[test]
    fn flags_stored_map_iteration() {
        let f = check(
            r#"
#[contractimpl]
impl C {
    pub fn total(e: Env) -> i128 {
        let m: Map<Address, i128> = e.storage().persistent().get(&K::M).unwrap();
        m.values().iter().sum()
    }
    pub fn count(e: Env) -> u32 {
        let m: Map<Address, i128> = e.storage().persistent().get(&K::M).unwrap();
        let mut c = 0;
        for (_k, _v) in m.iter() { c += 1; }
        c
    }
}
"#,
        );
        assert_eq!(f.len(), 2, "{f:#?}");
    }

    #[test]
    fn cap_in_helper_counts_as_bound() {
        let f = check(
            r#"
const MAX: u32 = 10;
fn assert_cap(v: &Vec<Address>) { if v.len() >= MAX { panic!() } }
#[contractimpl]
impl C {
    pub fn add(e: Env, a: Address) {
        let mut list: Vec<Address> = e.storage().persistent().get(&K::List).unwrap();
        assert_cap(&list);
        list.push_back(a);
        e.storage().persistent().set(&K::List, &list);
    }
    pub fn count(e: Env) -> u32 {
        let list: Vec<Address> = e.storage().persistent().get(&K::List).unwrap();
        let mut n = 0;
        for _x in list.iter() { n += 1; }
        n
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

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
