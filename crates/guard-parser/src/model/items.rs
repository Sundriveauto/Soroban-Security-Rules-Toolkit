//! Collecting functions and constants from parsed files.

use super::*;

/// Module path of a source file inside its crate: `src/lib.rs` → `[]`,
/// `src/a.rs` and `src/a/mod.rs` → `["a"]`, `src/a/b.rs` → `["a", "b"]`.
pub(super) fn file_module_path(path: &std::path::Path) -> Vec<String> {
    let comps: Vec<String> = path.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    let start = comps.iter().rposition(|c| c == "src").map(|i| i + 1).unwrap_or(comps.len().saturating_sub(1));
    let mut module: Vec<String> = comps[start..].to_vec();
    if let Some(last) = module.pop() {
        let stem = last.strip_suffix(".rs").unwrap_or(&last).to_string();
        if !matches!(stem.as_str(), "lib" | "main" | "mod") {
            module.push(stem);
        }
    }
    module
}

pub(super) fn collect_items<'a>(items: &'a [syn::Item], file: usize, module: &[String], out: &mut Vec<FnDef<'a>>) {
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
                module: module.to_vec(),
                self_ty: None,
                trait_name: None,
                foreign: false,
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
                        module: module.to_vec(),
                        self_ty: Some(self_ty.clone()),
                        trait_name: trait_name.clone(),
                        foreign: false,
                    });
                }
            }
            syn::Item::Trait(t) => {
                // Default method bodies are callable through every implementor.
                for it in &t.items {
                    let syn::TraitItem::Fn(f) = it else { continue };
                    let Some(block) = &f.default else { continue };
                    out.push(FnDef {
                        name: f.sig.ident.to_string(),
                        kind: FnKind::Method { self_ty: String::new(), has_self: f.sig.receiver().is_some() },
                        file,
                        sig: &f.sig,
                        block,
                        attrs: &f.attrs,
                        name_span: Span::of(&f.sig.ident),
                        module: module.to_vec(),
                        self_ty: None,
                        trait_name: Some(t.ident.to_string()),
                        foreign: false,
                    });
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    let mut inner = module.to_vec();
                    inner.push(m.ident.to_string());
                    collect_items(items, file, &inner, out);
                }
            }
            _ => {}
        }
    }
}

/// One crate's own functions with their facts, computed once per scan.
pub(super) struct OwnFns<'a> {
    pub(super) fns: Vec<FnDef<'a>>,
    pub(super) facts: Vec<FnFacts>,
    pub(super) consts: HashMap<String, Vec<String>>,
}

impl<'a> OwnFns<'a> {
    pub(super) fn collect(project: &'a Project, crate_id: usize, opts: &ModelOptions) -> Self {
        let mut fns = Vec::new();
        let mut consts = HashMap::new();
        for (file_idx, file) in project.files.iter().enumerate() {
            if file.crate_id != crate_id {
                continue;
            }
            let module = file_module_path(&file.path);
            collect_items(&file.ast.items, file_idx, &module, &mut fns);
            collect_consts(&file.ast.items, &mut consts);
        }
        let facts = fns.iter().map(|f| collect_facts(f, opts, &consts)).collect();
        OwnFns { fns, facts, consts }
    }
}

/// Key names of `const` / `static` items, including those in inline modules.
pub(super) fn collect_consts(items: &[syn::Item], out: &mut HashMap<String, Vec<String>>) {
    let empty = Bindings::default();
    for item in items {
        let (name, expr) = match item {
            syn::Item::Const(c) => (c.ident.to_string(), &*c.expr),
            syn::Item::Static(s) => (s.ident.to_string(), &*s.expr),
            syn::Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    collect_consts(items, out);
                }
                continue;
            }
            _ => continue,
        };
        let names = crate::syntax::key_names(expr, &empty);
        if !names.is_empty() {
            out.insert(name, names);
        }
    }
}

/// Key names with a constant (`&ADMIN_KEY`, `&keys::ADMIN_KEY`) replaced by its value's names,
/// keeping the constant's own name first so both contribute words.
pub fn resolve_const_key(names: Vec<String>, consts: &HashMap<String, Vec<String>>) -> Vec<String> {
    // `KEY` or `keys::KEY` (module path segments are lowercase).
    let Some((last, prefix)) = names.split_last() else { return names };
    if !prefix.iter().all(|p| p.starts_with(|c: char| c.is_lowercase())) {
        return names;
    }
    match consts.get(last) {
        Some(value) => {
            let mut out = vec![last.clone()];
            out.extend(value.iter().filter(|v| *v != last).cloned());
            out
        }
        None => names,
    }
}
