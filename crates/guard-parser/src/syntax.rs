//! Reusable helpers for inspecting `syn` syntax trees.

use std::collections::HashMap;

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use serde::Serialize;
use syn::spanned::Spanned;
use syn::{Expr, ExprMethodCall, Pat};

/// A 1-based line and column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct LineCol {
    pub line: usize,
    pub column: usize,
}

/// A source range, both ends inclusive-start / exclusive-end, 1-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Span {
    pub start: LineCol,
    pub end: LineCol,
}

impl Span {
    pub fn of<T: Spanned + ?Sized>(node: &T) -> Self {
        Self::from_proc(node.span())
    }

    pub fn from_proc(span: proc_macro2::Span) -> Self {
        let s = span.start();
        let e = span.end();
        let start = LineCol { line: s.line.max(1), column: s.column + 1 };
        let mut end = LineCol { line: e.line.max(1), column: e.column + 1 };
        if end < start {
            end = start;
        }
        Span { start, end }
    }
}

/// Which Soroban storage tier a call targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageTier {
    Persistent,
    Temporary,
    Instance,
}

impl StorageTier {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageTier::Persistent => "persistent",
            StorageTier::Temporary => "temporary",
            StorageTier::Instance => "instance",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageOpKind {
    Get,
    Has,
    Set,
    Remove,
    Update,
    ExtendTtl,
}

impl StorageOpKind {
    pub fn is_write(self) -> bool {
        matches!(self, StorageOpKind::Set | StorageOpKind::Remove | StorageOpKind::Update)
    }
    pub fn is_read(self) -> bool {
        matches!(self, StorageOpKind::Get | StorageOpKind::Has)
    }
}

/// A recognised `env.storage().<tier>().<op>(..)` call.
#[derive(Debug, Clone)]
pub struct StorageOp<'a> {
    pub kind: StorageOpKind,
    /// `None` when the tier could not be determined (e.g. a storage handle passed
    /// in as a parameter).
    pub tier: Option<StorageTier>,
    pub call: &'a ExprMethodCall,
}

impl<'a> StorageOp<'a> {
    /// The key argument (first argument) of the call, if any.
    pub fn key(&self) -> Option<&'a Expr> {
        self.call.args.first()
    }
}

/// Map from local variable name to the expressions it was initialised with.
///
/// Lookups are position-aware: a use resolves to the closest `let` that ends
/// before it, so shadowing and same-named variables in different `match` arms
/// resolve correctly in the common case.
#[derive(Debug, Default, Clone)]
pub struct Bindings<'a> {
    map: HashMap<String, Vec<(LineCol, &'a Expr)>>,
}

impl<'a> Bindings<'a> {
    /// Collects every `let name = expr;` in `block` (including nested blocks).
    pub fn collect(block: &'a syn::Block) -> Self {
        struct V<'a> {
            map: HashMap<String, Vec<(LineCol, &'a Expr)>>,
        }
        impl<'a> syn::visit::Visit<'a> for V<'a> {
            fn visit_local(&mut self, local: &'a syn::Local) {
                if let (Some(name), Some(init)) = (pat_ident(&local.pat), local.init.as_ref()) {
                    let end = Span::of(&local.semi_token).start;
                    self.map.entry(name).or_default().push((end, &init.expr));
                }
                syn::visit::visit_local(self, local);
            }
            fn visit_item_fn(&mut self, _: &'a syn::ItemFn) {}
        }
        let mut v = V { map: HashMap::new() };
        syn::visit::Visit::visit_block(&mut v, block);
        for list in v.map.values_mut() {
            list.sort_by_key(|(pos, _)| *pos);
        }
        Bindings { map: v.map }
    }

    /// The initializer of `name` as seen from source position `at`.
    pub fn get(&self, name: &str, at: LineCol) -> Option<&'a Expr> {
        self.map.get(name)?.iter().rev().find(|(end, _)| *end < at).map(|(_, e)| *e)
    }

    /// The initializer of a local-variable expression, resolved at its own position.
    pub fn resolve(&self, expr: &Expr) -> Option<&'a Expr> {
        let name = as_local_ident(expr)?;
        self.get(&name, Span::of(strip(expr)).start)
    }

    /// All bindings, sorted by name then position, for determinism.
    pub fn iter(&self) -> Vec<(&str, &'a Expr)> {
        let mut v: Vec<_> =
            self.map.iter().flat_map(|(k, list)| list.iter().map(move |(pos, e)| (k.as_str(), *pos, *e))).collect();
        v.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        v.into_iter().map(|(k, _, e)| (k, e)).collect()
    }
}

/// Renders a syntax node as compact source text (`& DataKey :: Admin` → `&DataKey::Admin`).
pub fn compact<T: ToTokens>(node: &T) -> String {
    let raw = node.to_token_stream().to_string();
    let mut s = raw;
    for (from, to) in [
        (" :: ", "::"),
        (":: ", "::"),
        (" ::", "::"),
        ("& ", "&"),
        (" (", "("),
        ("( ", "("),
        (" )", ")"),
        (" . ", "."),
        (" ,", ","),
        ("< ", "<"),
        (" <", "<"),
        (" >", ">"),
        ("! (", "!("),
    ] {
        while s.contains(from) {
            s = s.replace(from, to);
        }
    }
    s
}

/// Returns the bound identifier of a simple pattern (`x`, `mut x`, `x: T`).
pub fn pat_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(p) => Some(p.ident.to_string()),
        Pat::Type(t) => pat_ident(&t.pat),
        _ => None,
    }
}

/// Removes references, parentheses, `?`, groups and dereferences.
pub fn strip(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(r) => strip(&r.expr),
        Expr::Paren(p) => strip(&p.expr),
        Expr::Group(g) => strip(&g.expr),
        Expr::Try(t) => strip(&t.expr),
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => strip(&u.expr),
        other => other,
    }
}

/// The method names along a call chain, outermost last. `a.b().c(x)` → `["b", "c"]`.
pub fn method_chain(expr: &Expr) -> Vec<String> {
    let mut names = Vec::new();
    let mut cur = strip(expr);
    loop {
        match cur {
            Expr::MethodCall(m) => {
                names.push(m.method.to_string());
                cur = strip(&m.receiver);
            }
            Expr::Field(f) => cur = strip(&f.base),
            _ => break,
        }
    }
    names.reverse();
    names
}

/// The innermost receiver of a method chain. `a.b().c()` → `a`.
pub fn chain_root(expr: &Expr) -> &Expr {
    let mut cur = strip(expr);
    loop {
        match cur {
            Expr::MethodCall(m) => cur = strip(&m.receiver),
            Expr::Field(f) => cur = strip(&f.base),
            _ => return cur,
        }
    }
}

/// If `expr` is a single-segment path (a local variable), its name.
pub fn as_local_ident(expr: &Expr) -> Option<String> {
    match strip(expr) {
        Expr::Path(p) if p.qself.is_none() && p.path.segments.len() == 1 => Some(p.path.segments[0].ident.to_string()),
        _ => None,
    }
}

/// Method chain, following local variables back to their initialisers.
pub fn resolved_method_chain(expr: &Expr, bindings: &Bindings<'_>) -> Vec<String> {
    let mut chain = method_chain(expr);
    let mut root = chain_root(expr);
    for _ in 0..8 {
        let Some(init) = bindings.resolve(root) else { break };
        if std::ptr::eq(strip(init), root) {
            break;
        }
        let mut prefix = method_chain(init);
        prefix.extend(chain);
        chain = prefix;
        root = chain_root(init);
    }
    chain
}

/// Recognises Soroban storage calls such as `env.storage().persistent().set(..)`,
/// including when the storage handle was stored in a local variable first.
pub fn storage_op<'a>(call: &'a ExprMethodCall, bindings: &Bindings<'_>) -> Option<StorageOp<'a>> {
    let kind = match call.method.to_string().as_str() {
        "get" => StorageOpKind::Get,
        "has" => StorageOpKind::Has,
        "set" => StorageOpKind::Set,
        "remove" => StorageOpKind::Remove,
        "update" | "try_update" => StorageOpKind::Update,
        "extend_ttl" | "bump" => StorageOpKind::ExtendTtl,
        _ => return None,
    };
    let chain = resolved_method_chain(&call.receiver, bindings);
    let storage_pos = chain.iter().rposition(|m| m == "storage")?;
    let tier = chain[storage_pos + 1..].iter().find_map(|m| match m.as_str() {
        "persistent" => Some(StorageTier::Persistent),
        "temporary" => Some(StorageTier::Temporary),
        "instance" => Some(StorageTier::Instance),
        _ => None,
    });
    // `env.storage().max_ttl()` and friends are not data operations.
    if tier.is_none() && chain.len() > storage_pos + 1 {
        return None;
    }
    Some(StorageOp { kind, tier, call })
}

/// All identifier names appearing in a token stream, in order.
pub fn idents_in_tokens(tokens: TokenStream, out: &mut Vec<String>) {
    for tt in tokens {
        match tt {
            TokenTree::Ident(i) => out.push(i.to_string()),
            TokenTree::Group(g) => idents_in_tokens(g.stream(), out),
            _ => {}
        }
    }
}

/// All identifiers mentioned by a syntax node.
pub fn idents<T: ToTokens>(node: &T) -> Vec<String> {
    let mut out = Vec::new();
    idents_in_tokens(node.to_token_stream(), &mut out);
    out
}

/// Identifiers mentioned by `expr`, also expanding local variables to the
/// identifiers of their initialisers (bounded depth).
pub fn resolved_idents(expr: &Expr, bindings: &Bindings<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![(expr, 0usize)];
    let mut seen = std::collections::HashSet::new();
    while let Some((e, depth)) = stack.pop() {
        let at = Span::of(e).start;
        for id in idents(e) {
            if depth < 4 && seen.insert(id.clone()) {
                if let Some(init) = bindings.get(&id, at) {
                    stack.push((init, depth + 1));
                }
            }
            out.push(id);
        }
    }
    out
}

/// Identifiers that *name* a storage key, ignoring values passed into it.
///
/// `DataKey::Balance(config.owner)` → `["DataKey", "Balance"]`,
/// `symbol_short!("ADMIN")` → `["ADMIN"]`, and a local `key` is followed to
/// its initializer.
pub fn key_names(expr: &Expr, bindings: &Bindings<'_>) -> Vec<String> {
    fn lit_strings(tokens: TokenStream, out: &mut Vec<String>) {
        for tt in tokens {
            match tt {
                TokenTree::Literal(l) => {
                    let s = l.to_string();
                    if let Some(inner) = s.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                        out.push(inner.to_string());
                    }
                }
                TokenTree::Group(g) => lit_strings(g.stream(), out),
                _ => {}
            }
        }
    }
    fn go(e: &Expr, b: &Bindings<'_>, depth: usize, out: &mut Vec<String>) {
        if depth > 6 {
            return;
        }
        match strip(e) {
            Expr::Path(p) => {
                if p.qself.is_none() && p.path.segments.len() == 1 {
                    let name = p.path.segments[0].ident.to_string();
                    if let Some(init) = b.get(&name, Span::of(p).start) {
                        if !std::ptr::eq(strip(init), strip(e)) {
                            go(init, b, depth + 1, out);
                        }
                        return;
                    }
                    // Unbound lowercase names are parameters/values, not key names.
                    if name.starts_with(|c: char| c.is_lowercase()) {
                        return;
                    }
                }
                out.extend(p.path.segments.iter().map(|s| s.ident.to_string()));
            }
            Expr::Call(c) => go(&c.func, b, depth + 1, out),
            Expr::Struct(st) => out.extend(st.path.segments.iter().map(|s| s.ident.to_string())),
            Expr::MethodCall(m) => go(&m.receiver, b, depth + 1, out),
            Expr::Tuple(t) => t.elems.iter().for_each(|el| go(el, b, depth + 1, out)),
            Expr::Macro(m) => lit_strings(m.mac.tokens.clone(), out),
            Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => out.push(s.value()),
            _ => {}
        }
    }
    let mut out = Vec::new();
    go(expr, bindings, 0, &mut out);
    out
}

/// Splits an identifier into lowercase words on `_` and camel-case boundaries.
/// `TotalSupply` → `["total", "supply"]`, `new_balance` → `["new", "balance"]`.
pub fn words(ident: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in ident.split('_').filter(|p| !p.is_empty()) {
        let chars: Vec<char> = part.chars().collect();
        let mut cur = String::new();
        for (i, &c) in chars.iter().enumerate() {
            let boundary = i > 0
                && c.is_uppercase()
                && (chars[i - 1].is_lowercase()
                    || chars[i - 1].is_ascii_digit()
                    || chars.get(i + 1).is_some_and(|n| n.is_lowercase()));
            if boundary && !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            cur.extend(c.to_lowercase());
        }
        if !cur.is_empty() {
            out.push(cur);
        }
    }
    out
}

/// `true` if an attribute's path ends with `name` (`#[soroban_sdk::contractimpl]`).
pub fn attr_is(attr: &syn::Attribute, name: &str) -> bool {
    attr.path().segments.last().is_some_and(|s| s.ident == name)
}

/// `true` for `#[cfg(test)]` and `#[test]`-style attributes.
pub fn is_test_attr(attr: &syn::Attribute) -> bool {
    if attr_is(attr, "test") {
        return true;
    }
    if attr.path().is_ident("cfg") {
        if let syn::Meta::List(list) = &attr.meta {
            return list.tokens.to_string().trim() == "test";
        }
    }
    false
}

/// Best-effort parse of macro arguments as comma-separated expressions
/// (works for `assert!`, `require!`, `panic_with_error!`, `log!` …).
pub fn macro_args(mac: &syn::Macro) -> Vec<Expr> {
    use syn::parse::Parser;
    use syn::punctuated::Punctuated;
    Punctuated::<Expr, syn::Token![,]>::parse_terminated
        .parse2(mac.tokens.clone())
        .map(|p| p.into_iter().collect())
        .unwrap_or_default()
}

/// The last identifier of a macro path (`soroban_sdk::panic_with_error!` → `panic_with_error`).
pub fn macro_name(mac: &syn::Macro) -> String {
    mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default()
}

/// `true` for assertion-like macros whose arguments are conditions.
pub fn is_assert_macro(name: &str) -> bool {
    name.starts_with("assert")
        || name.starts_with("debug_assert")
        || name.starts_with("require")
        || name.starts_with("ensure")
}

/// Name of the function being called in a call expression (`a::b::c(..)` → `c`).
pub fn call_name(call: &syn::ExprCall) -> Option<String> {
    match strip(&call.func) {
        Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

/// `true` if `ty` mentions a collection type (`Vec`, `Map`, `Bytes`).
pub fn is_collection_type(ty: &syn::Type) -> bool {
    idents(ty).iter().any(|i| matches!(i.as_str(), "Vec" | "Map" | "Bytes" | "VecDeque" | "HashMap" | "BTreeMap"))
}

/// `true` if `ty` is a plain integer type (possibly behind a reference).
pub fn is_integer_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Reference(r) => is_integer_type(&r.elem),
        syn::Type::Path(p) => p.path.get_ident().is_some_and(|i| {
            matches!(
                i.to_string().as_str(),
                "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128" | "isize"
            )
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_words() {
        assert_eq!(words("TotalSupply"), vec!["total", "supply"]);
        assert_eq!(words("new_balance"), vec!["new", "balance"]);
        assert_eq!(words("HTTPServer"), vec!["http", "server"]);
        assert_eq!(words("amount"), vec!["amount"]);
        assert_eq!(words("__constructor"), vec!["constructor"]);
    }

    fn first_method_call(src: &str) -> syn::ExprMethodCall {
        match syn::parse_str::<Expr>(src).unwrap() {
            Expr::MethodCall(m) => m,
            _ => panic!("not a method call"),
        }
    }

    #[test]
    fn recognises_storage_ops() {
        let empty = syn::parse_str::<syn::Block>("{}").unwrap();
        let b = Bindings::collect(&empty);
        let c = first_method_call("env.storage().temporary().set(&DataKey::Balance(a), &x)");
        let op = storage_op(&c, &b).unwrap();
        assert_eq!(op.kind, StorageOpKind::Set);
        assert_eq!(op.tier, Some(StorageTier::Temporary));

        let c = first_method_call("map.set(k, v)");
        assert!(storage_op(&c, &b).is_none());

        let c = first_method_call("env.storage().max_ttl()");
        assert!(storage_op(&c, &b).is_none());
    }

    #[test]
    fn follows_bindings() {
        let block: syn::Block = syn::parse_str("{ let s = env.storage().persistent(); s.set(&k, &v); }").unwrap();
        let b = Bindings::collect(&block);
        let syn::Stmt::Expr(Expr::MethodCall(c), _) = &block.stmts[1] else { panic!() };
        let op = storage_op(c, &b).unwrap();
        assert_eq!(op.tier, Some(StorageTier::Persistent));
    }

    #[test]
    fn bindings_are_position_aware() {
        let block: syn::Block = syn::parse_str(
            "{ match t { A => { let k = Key::Total; use_(k); } B => { let k = Key::Account(a); use_(k); } } }",
        )
        .unwrap();
        let b = Bindings::collect(&block);
        let mut uses = Vec::new();
        struct U<'u>(&'u mut Vec<Expr>);
        impl<'ast> syn::visit::Visit<'ast> for U<'_> {
            fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
                if call_name(c).as_deref() == Some("use_") {
                    self.0.push(c.args[0].clone());
                }
            }
        }
        syn::visit::Visit::visit_block(&mut U(&mut uses), &block);
        assert_eq!(key_names(&uses[0], &b), vec!["Key", "Total"]);
        assert_eq!(key_names(&uses[1], &b), vec!["Key", "Account"]);
    }

    #[test]
    fn key_names_ignore_arguments() {
        let block: syn::Block = syn::parse_str(
            "{ let key = StorageKey::MinterStats(config.epoch, minter); let k2 = symbol_short!(\"ADMIN\"); &key; &k2; }",
        )
        .unwrap();
        let b = Bindings::collect(&block);
        let use_at = |i: usize| match &block.stmts[i] {
            syn::Stmt::Expr(e, _) => e.clone(),
            _ => panic!(),
        };
        assert_eq!(key_names(&use_at(2), &b), vec!["StorageKey", "MinterStats"]);
        assert_eq!(key_names(&use_at(3), &b), vec!["ADMIN"]);
        let e: Expr = syn::parse_str("&DataKey::Allowance(AllowanceDataKey { from, spender })").unwrap();
        assert_eq!(key_names(&e, &b), vec!["DataKey", "Allowance"]);
        let e: Expr = syn::parse_str("&(DataKey::Vote, voter)").unwrap();
        assert_eq!(key_names(&e, &b), vec!["DataKey", "Vote"]);
        let e: Expr = syn::parse_str("&ADMIN_KEY").unwrap();
        assert_eq!(key_names(&e, &b), vec!["ADMIN_KEY"]);
    }

    #[test]
    fn compacts_tokens() {
        let e: Expr = syn::parse_str("&DataKey::Balance(addr.clone())").unwrap();
        assert_eq!(compact(&e), "&DataKey::Balance(addr.clone())");
    }

    #[test]
    fn test_attr_detection() {
        let f: syn::ItemFn = syn::parse_str("#[cfg(test)] fn x() {}").unwrap();
        assert!(is_test_attr(&f.attrs[0]));
        let f: syn::ItemFn = syn::parse_str("#[cfg(not(test))] fn x() {}").unwrap();
        assert!(!is_test_attr(&f.attrs[0]));
    }
}
