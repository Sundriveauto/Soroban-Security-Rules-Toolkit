//! A per-crate model of functions and the security-relevant facts about them.
//!
//! Rules use the model to answer questions such as "does this exported
//! contract function, or anything it calls, perform `require_auth`?" without
//! each rule re-implementing call-graph traversal.

use std::collections::{HashMap, HashSet};

use syn::visit::Visit;
use syn::{Attribute, Block, Expr, Signature};

use crate::project::Project;
use crate::syntax::{
    attr_is, call_name, idents, is_assert_macro, macro_args, macro_name, resolved_idents, storage_op, words, Bindings,
    Span, StorageOpKind, StorageTier,
};

/// Index of a function in [`CrateModel::fns`].
pub type FnId = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FnKind {
    /// A function exported by a `#[contractimpl]` block (callable on-chain).
    ContractExport { contract: String, via_trait: Option<String> },
    /// A method in an ordinary `impl` block (or a non-exported contractimpl fn).
    Method { self_ty: String, has_self: bool },
    /// A free function.
    Free,
}

/// A function definition anywhere in the crate.
#[derive(Debug)]
pub struct FnDef<'a> {
    pub name: String,
    pub kind: FnKind,
    /// Index into [`Project::files`].
    pub file: usize,
    pub sig: &'a Signature,
    pub block: &'a Block,
    pub attrs: &'a [Attribute],
    /// Span of the function name.
    pub name_span: Span,
}

impl FnDef<'_> {
    pub fn is_contract_export(&self) -> bool {
        matches!(self.kind, FnKind::ContractExport { .. })
    }

    /// Typed parameters as `(name, type)` pairs, excluding `self`.
    pub fn params(&self) -> Vec<(String, &syn::Type)> {
        self.sig
            .inputs
            .iter()
            .filter_map(|arg| match arg {
                syn::FnArg::Typed(pt) => crate::syntax::pat_ident(&pt.pat).map(|n| (n, &*pt.ty)),
                syn::FnArg::Receiver(_) => None,
            })
            .collect()
    }

    /// `true` if any parameter's type mentions `Address`.
    pub fn takes_address(&self) -> bool {
        self.params().iter().any(|(_, ty)| idents(*ty).iter().any(|i| i == "Address"))
    }
}

/// A storage write (`set`, `remove`, `update`).
#[derive(Debug, Clone)]
pub struct StateWrite {
    pub span: Span,
    pub kind: StorageOpKind,
    pub tier: Option<StorageTier>,
    /// Identifiers naming the key (enum/struct path, symbol literal), excluding
    /// argument values. See [`crate::syntax::key_names`].
    pub key_idents: Vec<String>,
    /// `true` when the key is constructed with arguments, e.g. `DataKey::Balance(addr)`.
    pub key_is_parameterised: bool,
    /// The key expression as written (after resolving a local variable once).
    pub key_text: String,
}

impl StateWrite {
    /// Lowercase words of all key names (`DataKey::TotalSupply` → `data key total supply`).
    pub fn key_words(&self) -> Vec<String> {
        self.key_idents.iter().flat_map(|i| words(i)).collect()
    }

    /// Lowercase words of the most specific key name: the enum variant, struct
    /// name or symbol (`GovernorKey::OperationId(..)` → `operation id`).
    pub fn key_variant_words(&self) -> Vec<String> {
        self.key_idents.last().map(|i| words(i)).unwrap_or_default()
    }
}

/// A call to another function.
#[derive(Debug, Clone)]
pub struct CallSite {
    pub name: String,
    pub span: Span,
    /// Method-call syntax (`x.f()`) rather than path syntax (`f()`, `Self::f()`).
    pub is_method: bool,
    /// Call appears inside a condition (`if`, `match`, `assert!` …).
    pub in_condition: bool,
    /// Call runs on only some paths: inside an `if` / `match` arm or a `for` / `while` body.
    pub in_branch: bool,
    /// The callee's name looks like an authorization helper (`require_admin`, `check_owner_auth`).
    /// Trusted only when the crate does not define the helper; otherwise its body is checked.
    pub auth_named: bool,
}

/// How reliably a function performs an authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthStatus {
    /// No authorization on any path.
    Never,
    /// Authorization happens on some paths only (e.g. inside an `if`).
    Sometimes,
    /// Authorization happens on every path that reaches the end of the function.
    Always,
}

/// Security-relevant facts collected directly from one function body.
#[derive(Debug, Clone, Default)]
pub struct FnFacts {
    /// Authorization checks that run on every path: `require_auth` /
    /// `require_auth_for_args`, configured `auth-functions` and auth macros.
    pub auth: Vec<Span>,
    /// Authorization checks that run on some paths only (inside a branch or loop body).
    pub cond_auth: Vec<Span>,
    /// The function carries an access-control attribute such as `#[only_owner]`.
    pub auth_attr: bool,
    pub state_writes: Vec<StateWrite>,
    pub storage_reads: Vec<Span>,
    /// Token transfers whose source is the contract itself.
    pub outflows: Vec<Span>,
    /// `update_current_contract_wasm` calls.
    pub upgrades: Vec<Span>,
    /// Checks for existing state (`has`, or a `get` used in a condition).
    pub init_guards: Vec<Span>,
    pub calls: Vec<CallSite>,
    /// Local names whose `.len()` is compared in a condition (`if items.len() >= MAX`).
    pub len_bounds: Vec<String>,
}

/// Options influencing fact collection.
#[derive(Debug, Clone, Default)]
pub struct ModelOptions {
    /// Additional function or macro names that should count as an authorization check.
    pub auth_functions: Vec<String>,
}

/// Attribute macros that enforce access control (OpenZeppelin Stellar and similar).
const AUTH_ATTRIBUTES: &[&str] = &["only_owner", "only_admin", "only_role", "has_role", "has_any_role", "only_roles"];

fn is_auth_attr(attr: &Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .map(|s| {
            let n = s.ident.to_string();
            AUTH_ATTRIBUTES.contains(&n.as_str()) || n.starts_with("only_")
        })
        .unwrap_or(false)
}

/// Heuristic: does a function name look like an authorization helper?
/// Matches e.g. `require_admin_auth`, `enforce_owner_auth`, `ensure_role`, `check_auth`.
pub fn is_auth_helper_name(name: &str, extra: &[String]) -> bool {
    if extra.iter().any(|e| e == name) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    if lower == "__check_auth" {
        return false;
    }
    let prefixes = ["require", "enforce", "ensure", "assert", "check", "verify", "only"];
    let has_prefix = prefixes.iter().any(|p| lower.starts_with(p));
    has_prefix
        && (lower.contains("auth") || lower.contains("role") || lower.contains("owner") || lower.contains("admin"))
}

/// Function model for one crate.
#[derive(Debug)]
pub struct CrateModel<'a> {
    pub crate_id: usize,
    pub fns: Vec<FnDef<'a>>,
    pub facts: Vec<FnFacts>,
    by_name: HashMap<String, Vec<FnId>>,
}

/// The place where a transitive property was found, seen from the queried function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    /// Span inside the queried function: the operation itself, or the call that leads to it.
    pub span: Span,
    /// Names of helper functions traversed, outermost first. Empty for a direct hit.
    pub via: Vec<String>,
}

impl<'a> CrateModel<'a> {
    /// Builds models for every crate in the project.
    pub fn build_all(project: &'a Project, opts: &ModelOptions) -> Vec<CrateModel<'a>> {
        (0..project.crates.len().max(1)).map(|id| CrateModel::build(project, id, opts)).collect()
    }

    pub fn build(project: &'a Project, crate_id: usize, opts: &ModelOptions) -> Self {
        let mut fns = Vec::new();
        for (file_idx, file) in project.files.iter().enumerate() {
            if file.crate_id != crate_id {
                continue;
            }
            collect_items(&file.ast.items, file_idx, &mut fns);
        }
        let facts = fns.iter().map(|f| collect_facts(f, opts)).collect();
        let mut by_name: HashMap<String, Vec<FnId>> = HashMap::new();
        for (i, f) in fns.iter().enumerate() {
            by_name.entry(f.name.clone()).or_default().push(i);
        }
        CrateModel { crate_id, fns, facts, by_name }
    }

    /// Functions defined in a given file.
    pub fn fns_in_file(&self, file: usize) -> impl Iterator<Item = (FnId, &FnDef<'a>)> {
        self.fns.iter().enumerate().filter(move |(_, f)| f.file == file)
    }

    /// Functions with the given name.
    pub fn by_name(&self, name: &str) -> &[FnId] {
        self.by_name.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Crate functions a call site may refer to (name-based, conservative).
    pub fn resolve(&self, call: &CallSite) -> Vec<FnId> {
        self.by_name(&call.name)
            .iter()
            .copied()
            .filter(|&id| {
                if call.is_method {
                    matches!(self.fns[id].kind, FnKind::Method { has_self: true, .. })
                } else {
                    true
                }
            })
            .collect()
    }

    /// Finds where `pred` holds, either directly in `id` or in any function it
    /// (transitively) calls. `pred` returns the first matching span in a body.
    pub fn witness(&self, id: FnId, pred: &dyn Fn(&FnDef<'_>, &FnFacts) -> Option<Span>) -> Option<Witness> {
        let mut visited = HashSet::new();
        self.witness_inner(id, pred, &mut visited)
    }

    fn witness_inner(
        &self,
        id: FnId,
        pred: &dyn Fn(&FnDef<'_>, &FnFacts) -> Option<Span>,
        visited: &mut HashSet<FnId>,
    ) -> Option<Witness> {
        if !visited.insert(id) {
            return None;
        }
        if let Some(span) = pred(&self.fns[id], &self.facts[id]) {
            return Some(Witness { span, via: vec![] });
        }
        for call in &self.facts[id].calls {
            for callee in self.resolve(call) {
                if let Some(w) = self.witness_inner(callee, pred, visited) {
                    let mut via = vec![self.fns[callee].name.clone()];
                    via.extend(w.via);
                    return Some(Witness { span: call.span, via });
                }
            }
        }
        None
    }

    /// `true` if `id` or anything it calls performs an authorization check on at least one path.
    pub fn performs_auth(&self, id: FnId) -> bool {
        self.auth_status(id) != AuthStatus::Never
    }

    /// Whether `id`, directly or through the helpers it calls, authorizes on
    /// every path, on some paths, or never.
    ///
    /// Helpers whose names look like auth checks are followed into their bodies
    /// when the crate defines them, so an empty `fn check_admin() {}` does not count.
    pub fn auth_status(&self, id: FnId) -> AuthStatus {
        let mut visited = HashSet::new();
        self.auth_status_inner(id, &mut visited)
    }

    fn auth_status_inner(&self, id: FnId, visited: &mut HashSet<FnId>) -> AuthStatus {
        if !visited.insert(id) {
            return AuthStatus::Never;
        }
        let def = &self.fns[id];
        let facts = &self.facts[id];
        if facts.auth_attr || def.attrs.iter().any(is_auth_attr) || !facts.auth.is_empty() {
            return AuthStatus::Always;
        }
        let mut best = if facts.cond_auth.is_empty() { AuthStatus::Never } else { AuthStatus::Sometimes };
        for call in &facts.calls {
            let callees = self.resolve(call);
            let status = if callees.is_empty() {
                if call.auth_named {
                    AuthStatus::Always
                } else {
                    AuthStatus::Never
                }
            } else {
                callees.iter().map(|&c| self.auth_status_inner(c, visited)).max().unwrap_or(AuthStatus::Never)
            };
            let status = if call.in_branch { status.min(AuthStatus::Sometimes) } else { status };
            if status == AuthStatus::Always {
                return AuthStatus::Always;
            }
            best = best.max(status);
        }
        best
    }

    /// `true` if `id` or anything it calls reads contract storage.
    pub fn reads_storage(&self, id: FnId) -> bool {
        self.witness(id, &|_, f| f.storage_reads.first().copied()).is_some()
    }

    /// `true` if `id` has an "already initialized" style guard, directly, in a
    /// helper it calls, or by calling a storage-reading helper inside a condition.
    pub fn has_init_guard(&self, id: FnId) -> bool {
        if self.witness(id, &|_, f| f.init_guards.first().copied()).is_some() {
            return true;
        }
        self.facts[id]
            .calls
            .iter()
            .filter(|c| c.in_condition)
            .any(|c| self.resolve(c).into_iter().any(|callee| self.reads_storage(callee)))
    }
}

fn collect_items<'a>(items: &'a [syn::Item], file: usize, out: &mut Vec<FnDef<'a>>) {
    for item in items {
        match item {
            syn::Item::Fn(f) => out.push(FnDef {
                name: f.sig.ident.to_string(),
                kind: FnKind::Free,
                file,
                sig: &f.sig,
                block: &f.block,
                attrs: &f.attrs,
                name_span: Span::of(&f.sig.ident),
            }),
            syn::Item::Impl(imp) => {
                let is_contract = imp.attrs.iter().any(|a| attr_is(a, "contractimpl"));
                let self_ty = match &*imp.self_ty {
                    syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default(),
                    _ => String::new(),
                };
                let trait_name =
                    imp.trait_.as_ref().and_then(|(_, p, _)| p.segments.last().map(|s| s.ident.to_string()));
                for it in &imp.items {
                    let syn::ImplItem::Fn(f) = it else { continue };
                    let is_pub = matches!(f.vis, syn::Visibility::Public(_));
                    let has_self = f.sig.receiver().is_some();
                    let kind = if is_contract && (is_pub || trait_name.is_some()) && !has_self {
                        FnKind::ContractExport { contract: self_ty.clone(), via_trait: trait_name.clone() }
                    } else {
                        FnKind::Method { self_ty: self_ty.clone(), has_self }
                    };
                    out.push(FnDef {
                        name: f.sig.ident.to_string(),
                        kind,
                        file,
                        sig: &f.sig,
                        block: &f.block,
                        attrs: &f.attrs,
                        name_span: Span::of(&f.sig.ident),
                    });
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    collect_items(items, file, out);
                }
            }
            _ => {}
        }
    }
}

/// `true` if an expression always leaves the function: `panic!`, `return`, a
/// `panic_with_error!` call, or a block ending in one of those.
fn diverges(expr: &Expr) -> bool {
    match crate::syntax::strip(expr) {
        Expr::Return(_) => true,
        Expr::Macro(m) => {
            let n = macro_name(&m.mac);
            matches!(n.as_str(), "panic" | "panic_with_error" | "unreachable" | "unimplemented" | "todo")
        }
        Expr::Block(b) => b.block.stmts.last().is_some_and(|s| match s {
            syn::Stmt::Expr(e, _) => diverges(e),
            syn::Stmt::Macro(m) => {
                let n = macro_name(&m.mac);
                matches!(n.as_str(), "panic" | "panic_with_error" | "unreachable" | "unimplemented" | "todo")
            }
            _ => false,
        }),
        _ => false,
    }
}

fn collect_facts(def: &FnDef<'_>, opts: &ModelOptions) -> FnFacts {
    let bindings = Bindings::collect(def.block);
    let mut v = FactsVisitor {
        bindings: &bindings,
        opts,
        facts: FnFacts { auth_attr: def.attrs.iter().any(is_auth_attr), ..Default::default() },
        cond_depth: 0,
        branch_depth: 0,
    };
    v.visit_block(def.block);
    v.facts
}

struct FactsVisitor<'b, 'a> {
    bindings: &'b Bindings<'a>,
    opts: &'b ModelOptions,
    facts: FnFacts,
    cond_depth: usize,
    /// > 0 inside code that runs on some paths only.
    branch_depth: usize,
}

impl FactsVisitor<'_, '_> {
    fn condition<F: FnOnce(&mut Self)>(&mut self, f: F) {
        self.cond_depth += 1;
        f(self);
        self.cond_depth -= 1;
    }

    fn branch<F: FnOnce(&mut Self)>(&mut self, f: F) {
        self.branch_depth += 1;
        f(self);
        self.branch_depth -= 1;
    }

    /// Records a direct authorization check, conditional or not.
    fn push_auth(&mut self, span: Span) {
        if self.branch_depth > 0 {
            self.facts.cond_auth.push(span);
        } else {
            self.facts.auth.push(span);
        }
    }

    fn push_call(&mut self, name: String, span: Span, is_method: bool) {
        let auth_named = is_auth_helper_name(&name, &[]);
        self.facts.calls.push(CallSite {
            name,
            span,
            is_method,
            in_condition: self.cond_depth > 0,
            in_branch: self.branch_depth > 0,
            auth_named,
        });
    }

    /// When every alternative of an `if`/`else` or `match` performs a direct
    /// auth check, the check runs on every path.
    fn promote_if_exhaustive(&mut self, all_branches_auth: bool, first: Option<Span>) {
        if all_branches_auth && self.branch_depth == 0 {
            if let Some(span) = first {
                self.facts.auth.push(span);
            }
        }
    }

    fn expr_reads_storage(&self, expr: &Expr) -> bool {
        struct R<'x, 'a> {
            b: &'x Bindings<'a>,
            hit: bool,
        }
        impl<'ast> Visit<'ast> for R<'_, '_> {
            fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
                if storage_op(m, self.b).is_some_and(|op| op.kind.is_read()) {
                    self.hit = true;
                }
                syn::visit::visit_expr_method_call(self, m);
            }
        }
        let mut r = R { b: self.bindings, hit: false };
        r.visit_expr(expr);
        r.hit
    }
}

impl<'ast> Visit<'ast> for FactsVisitor<'_, '_> {
    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        let name = m.method.to_string();
        let span = Span::of(&m.method);
        match name.as_str() {
            "require_auth" | "require_auth_for_args" => self.push_auth(span),
            "update_current_contract_wasm" => self.facts.upgrades.push(span),
            "transfer" | "transfer_from" => {
                let from_contract = m
                    .args
                    .first()
                    .is_some_and(|a| resolved_idents(a, self.bindings).iter().any(|i| i == "current_contract_address"));
                if from_contract {
                    self.facts.outflows.push(span);
                }
            }
            _ => {}
        }
        if let Some(op) = storage_op(m, self.bindings) {
            if op.kind.is_write() {
                let key_text = op
                    .key()
                    .map(|k| {
                        let resolved = self.bindings.resolve(k).unwrap_or(k);
                        crate::syntax::compact(crate::syntax::strip(resolved))
                    })
                    .unwrap_or_default();
                let (key_idents, key_is_parameterised) = match op.key() {
                    Some(k) => {
                        let parameterised = match crate::syntax::strip(k) {
                            Expr::Call(c) => !c.args.is_empty(),
                            Expr::Path(_) => self.bindings.resolve(k).is_some_and(
                                |init| matches!(crate::syntax::strip(init), Expr::Call(c) if !c.args.is_empty()),
                            ),
                            _ => false,
                        };
                        (crate::syntax::key_names(k, self.bindings), parameterised)
                    }
                    None => (vec![], false),
                };
                self.facts.state_writes.push(StateWrite {
                    span,
                    kind: op.kind,
                    tier: op.tier,
                    key_idents,
                    key_is_parameterised,
                    key_text,
                });
            } else if op.kind.is_read() {
                self.facts.storage_reads.push(span);
                if op.kind == StorageOpKind::Has || self.cond_depth > 0 {
                    self.facts.init_guards.push(span);
                }
            }
        } else if self.opts.auth_functions.contains(&name) {
            self.push_auth(span);
        } else if !matches!(name.as_str(), "require_auth" | "require_auth_for_args") {
            self.push_call(name, span, true);
        }
        syn::visit::visit_expr_method_call(self, m);
    }

    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        if let Some(name) = call_name(c) {
            let span = Span::of(&c.func);
            if self.opts.auth_functions.contains(&name) {
                self.push_auth(span);
            } else {
                self.push_call(name, span, false);
            }
        }
        syn::visit::visit_expr_call(self, c);
    }

    fn visit_expr_if(&mut self, e: &'ast syn::ExprIf) {
        self.condition(|s| s.visit_expr(&e.cond));
        let before = self.facts.cond_auth.len();
        self.branch(|s| s.visit_block(&e.then_branch));
        let after_then = self.facts.cond_auth.len();
        let mut all = after_then > before;
        if let Some((_, els)) = &e.else_branch {
            self.branch(|s| s.visit_expr(els));
            all &= self.facts.cond_auth.len() > after_then;
        } else {
            all = false;
        }
        let first = self.facts.cond_auth.get(before).copied();
        self.promote_if_exhaustive(all, first);
    }

    fn visit_expr_match(&mut self, e: &'ast syn::ExprMatch) {
        self.condition(|s| s.visit_expr(&e.expr));
        let before = self.facts.cond_auth.len();
        let mut all = !e.arms.is_empty();
        for arm in &e.arms {
            if let Some((_, g)) = &arm.guard {
                self.condition(|s| s.visit_expr(g));
            }
            let n = self.facts.cond_auth.len();
            self.branch(|s| s.visit_expr(&arm.body));
            // An arm that diverges (`panic!`, `return`) need not authorize.
            all &= self.facts.cond_auth.len() > n || diverges(&arm.body);
        }
        let first = self.facts.cond_auth.get(before).copied();
        self.promote_if_exhaustive(all, first);
    }

    fn visit_expr_while(&mut self, e: &'ast syn::ExprWhile) {
        self.condition(|s| s.visit_expr(&e.cond));
        self.branch(|s| s.visit_block(&e.body));
    }

    fn visit_expr_for_loop(&mut self, e: &'ast syn::ExprForLoop) {
        self.visit_expr(&e.expr);
        // The body may run zero times.
        self.branch(|s| s.visit_block(&e.body));
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init {
            if let Some((_, diverge)) = &init.diverge {
                // `let Some(x) = storage.get(..) else { panic!() };`
                self.condition(|s| s.visit_expr(&init.expr));
                self.visit_expr(diverge);
                return;
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
        if self.cond_depth > 0 && p.path.segments.len() == 1 {
            let name = p.path.segments[0].ident.to_string();
            if let Some(init) = self.bindings.get(&name, Span::of(p).start) {
                if self.expr_reads_storage(init) {
                    self.facts.init_guards.push(Span::of(p));
                }
            }
        }
        syn::visit::visit_expr_path(self, p);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let name = macro_name(mac);
        // Macros are not expanded, so an auth-like macro name is trusted.
        if is_auth_helper_name(&name, &self.opts.auth_functions) {
            self.push_auth(Span::of(&mac.path));
        }
        let args = macro_args(mac);
        if is_assert_macro(&name) {
            self.condition(|s| args.iter().for_each(|a| s.visit_expr(a)));
        } else {
            args.iter().for_each(|a| self.visit_expr(a));
        }
    }

    fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
        use syn::BinOp::*;
        if self.cond_depth > 0 && matches!(b.op, Lt(_) | Le(_) | Gt(_) | Ge(_)) {
            for side in [&*b.left, &*b.right] {
                if let Expr::MethodCall(m) = crate::syntax::strip(side) {
                    if m.method == "len" {
                        if let Some(name) = crate::syntax::as_local_ident(&m.receiver) {
                            self.facts.len_bounds.push(name);
                        }
                    }
                }
            }
        }
        syn::visit::visit_expr_binary(self, b);
    }

    // Nested function items are modelled separately.
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cargo::CrateInfo;

    fn project(src: &str) -> Project {
        Project::from_sources([("lib.rs", src)], CrateInfo::default(), false)
    }

    #[test]
    fn classifies_exports() {
        let p = project(
            r#"
            #[contractimpl]
            impl C { pub fn a(e: Env) {} fn b(e: Env) {} }
            #[contractimpl]
            impl Tr for C { fn c(e: Env) {} }
            impl C { pub fn d(&self) {} }
            fn e() {}
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        let exports: Vec<_> = m.fns.iter().filter(|f| f.is_contract_export()).map(|f| f.name.as_str()).collect();
        assert_eq!(exports, vec!["a", "c"]);
        assert_eq!(m.fns.len(), 5);
    }

    #[test]
    fn transitive_auth_and_writes() {
        let p = project(
            r#"
            fn check(e: &Env) { let a: Address = e.storage().instance().get(&K::Admin).unwrap(); a.require_auth(); }
            fn write(e: &Env, v: i128) { e.storage().persistent().set(&K::V, &v); }
            #[contractimpl]
            impl C {
                pub fn guarded(e: Env, v: i128) { check(&e); write(&e, v); }
                pub fn open(e: Env, v: i128) { write(&e, v); }
            }
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        let id = |n: &str| m.by_name(n)[0];
        assert!(m.performs_auth(id("guarded")));
        assert!(!m.performs_auth(id("open")));
        let w = m.witness(id("open"), &|_, f| f.state_writes.first().map(|w| w.span)).unwrap();
        assert_eq!(w.via, vec!["write".to_string()]);
    }

    #[test]
    fn init_guards() {
        let p = project(
            r#"
            fn is_init(e: &Env) -> bool { e.storage().instance().has(&K::Admin) }
            #[contractimpl]
            impl C {
                pub fn a(e: Env) { if is_init(&e) { panic!() } e.storage().instance().set(&K::Admin, &1); }
                pub fn b(e: Env) { assert!(e.storage().instance().get::<_, bool>(&K::Init).is_none()); }
                pub fn c(e: Env) { e.storage().instance().set(&K::Admin, &1); }
                pub fn d(e: Env) { let cur = e.storage().instance().get::<_, u32>(&K::A); if cur.is_some() { panic!() } }
            }
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        let id = |n: &str| m.by_name(n)[0];
        assert!(m.has_init_guard(id("a")));
        assert!(m.has_init_guard(id("b")));
        assert!(!m.has_init_guard(id("c")));
        assert!(m.has_init_guard(id("d")));
    }

    #[test]
    fn auth_status_tracks_branches_and_helper_bodies() {
        let p = project(
            r#"
            fn require_admin(e: &Env) {}
            fn require_owner(e: &Env) { let o: Address = e.storage().instance().get(&K::Owner).unwrap(); o.require_auth(); }
            #[contractimpl]
            impl C {
                pub fn fake(e: Env) { require_admin(&e); }
                pub fn real(e: Env) { require_owner(&e); }
                pub fn external(e: Env) { require_operator_auth(&e); }
                pub fn half(e: Env, a: Address, f: bool) { if f { a.require_auth(); } }
                pub fn both(e: Env, a: Address, b: Address, f: bool) { if f { a.require_auth(); } else { b.require_auth(); } }
                pub fn arms(e: Env, a: Address, k: u32) { match k { 0 => a.require_auth(), _ => panic!("no") } }
                pub fn looped(e: Env, xs: Vec<Address>) { for x in xs.iter() { x.require_auth(); } }
                pub fn helper_in_branch(e: Env, f: bool) { if f { require_owner(&e); } }
            }
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        let st = |n: &str| m.auth_status(m.by_name(n)[0]);
        assert_eq!(st("fake"), AuthStatus::Never);
        assert_eq!(st("real"), AuthStatus::Always);
        assert_eq!(st("external"), AuthStatus::Always, "undefined auth-named helpers are trusted");
        assert_eq!(st("half"), AuthStatus::Sometimes);
        assert_eq!(st("both"), AuthStatus::Always);
        assert_eq!(st("arms"), AuthStatus::Always);
        assert_eq!(st("looped"), AuthStatus::Sometimes);
        assert_eq!(st("helper_in_branch"), AuthStatus::Sometimes);
    }

    #[test]
    fn configured_auth_functions_are_trusted() {
        let p = project("#[contractimpl] impl C { pub fn a(e: Env) { gate(&e); } }");
        let opts = ModelOptions { auth_functions: vec!["gate".into()] };
        let m = CrateModel::build(&p, 0, &opts);
        assert_eq!(m.auth_status(0), AuthStatus::Always);
    }

    #[test]
    fn auth_helper_names() {
        assert!(is_auth_helper_name("require_admin_auth", &[]));
        assert!(is_auth_helper_name("enforce_owner_auth", &[]));
        assert!(is_auth_helper_name("ensure_role", &[]));
        assert!(!is_auth_helper_name("transfer", &[]));
        assert!(!is_auth_helper_name("__check_auth", &[]));
        assert!(is_auth_helper_name("gate", &["gate".into()]));
    }

    #[test]
    fn outflows_detected_through_bindings() {
        let p = project(
            r#"
            #[contractimpl]
            impl C {
                pub fn w(e: Env, to: Address, amt: i128) {
                    let me = e.current_contract_address();
                    token::Client::new(&e, &t).transfer(&me, &to, &amt);
                }
                pub fn d(e: Env, from: Address, amt: i128) {
                    token::Client::new(&e, &t).transfer(&from, &e.current_contract_address(), &amt);
                }
            }
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        assert_eq!(m.facts[m.by_name("w")[0]].outflows.len(), 1);
        assert_eq!(m.facts[m.by_name("d")[0]].outflows.len(), 0);
    }
}
