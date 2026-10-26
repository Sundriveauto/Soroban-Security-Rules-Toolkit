//! SG-008: results of fallible cross-contract calls (`client.try_*`) that are discarded.

use guard_engine::{Confidence, Diagnostic, Rule, RuleContext, RuleMeta, Severity};
use guard_parser::syntax::{resolved_idents, strip, Bindings};
use guard_parser::Span;
use syn::visit::Visit;
use syn::{Expr, Stmt};

pub struct IgnoredTryCall;

static META: RuleMeta = RuleMeta {
    id: "SG-008",
    name: "ignored-try-call",
    summary: "Result of a fallible cross-contract call is ignored",
    description: "Generated contract clients offer `try_*` variants (`client.try_transfer(..)`) that return a \
`Result` instead of aborting when the callee fails. Dropping that result (`client.try_transfer(..);` or \
`let _ = client.try_transfer(..);`) lets execution continue as if the call succeeded: tokens were not moved, a \
hook did not run, state was not updated, yet the caller records success.",
    remediation: "Use the non-`try_` method so a failure aborts the invocation, or handle the `Result` \
explicitly (`match client.try_transfer(..) { Ok(Ok(())) => .., _ => panic_with_error!(..) }`).",
    default_severity: Severity::Warning,
    tags: &["security", "error-handling", "cross-contract"],
    options: &[],
};

/// `try_` methods on Soroban collections and std types, which are not cross-contract calls.
const NOT_CALLS: &[&str] = &[
    "try_from",
    "try_into",
    "try_from_val",
    "try_into_val",
    "try_update",
    "try_for_each",
    "try_fold",
    "try_get",
    "try_get_unchecked",
    "try_first",
    "try_last",
    "try_pop_front",
    "try_pop_back",
    "try_remove",
    "try_insert",
    "try_set",
    "try_push_back",
    "try_push_front",
];

impl Rule for IgnoredTryCall {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>) {
        if !cx.is_soroban() {
            return;
        }
        for (_, f) in cx.model.fns_in_file(cx.file_idx) {
            let bindings = Bindings::collect(f.block);
            let mut v = V { bindings: &bindings, hits: Vec::new() };
            v.visit_block(f.block);
            for (span, method, discarded_with_let) in v.hits {
                let how = if discarded_with_let { "assigned to `_`" } else { "discarded" };
                out.push(
                    Diagnostic::new(
                        span,
                        format!("Result of cross-contract call `{method}` is {how}, so a failed call goes unnoticed"),
                        if discarded_with_let { Confidence::Medium } else { Confidence::High },
                    )
                    .in_function(&f.name),
                );
            }
        }
    }
}

struct V<'b, 'a> {
    bindings: &'b Bindings<'a>,
    hits: Vec<(Span, String, bool)>,
}

impl V<'_, '_> {
    /// `client.try_x(..)` where the receiver is a contract client
    /// (`FooClient::new(..)`, `token::Client::new(..)`, or a local holding one).
    fn try_client_call<'e>(&self, e: &'e Expr) -> Option<&'e syn::ExprMethodCall> {
        let Expr::MethodCall(m) = strip(e) else { return None };
        let name = m.method.to_string();
        if !name.starts_with("try_") || NOT_CALLS.contains(&name.as_str()) {
            return None;
        }
        let is_client = resolved_idents(&m.receiver, self.bindings)
            .iter()
            .any(|i| i.ends_with("Client") || i.ends_with("client") || i == "invoke_contract");
        is_client.then_some(m)
    }
}

impl<'ast> Visit<'ast> for V<'_, '_> {
    fn visit_stmt(&mut self, s: &'ast Stmt) {
        match s {
            Stmt::Expr(e, Some(_)) => {
                if let Some(m) = self.try_client_call(e) {
                    self.hits.push((Span::of(&m.method), m.method.to_string(), false));
                }
            }
            Stmt::Local(l) if matches!(l.pat, syn::Pat::Wild(_)) => {
                if let Some(init) = &l.init {
                    if let Some(m) = self.try_client_call(&init.expr) {
                        self.hits.push((Span::of(&m.method), m.method.to_string(), true));
                    }
                }
            }
            _ => {}
        }
        syn::visit::visit_stmt(self, s);
    }

    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(IgnoredTryCall), src)
    }

    #[test]
    fn flags_discarded_try_calls() {
        let f = check(
            r#"
fn a(e: &Env, t: Address, to: Address) {
    token::Client::new(e, &t).try_transfer(&e.current_contract_address(), &to, &1);
    let hook = HookClient::new(e, &t);
    let _ = hook.try_on_receive(&to);
}
"#,
        );
        assert_eq!(lines(&f), vec![3, 5], "{f:#?}");
        assert_eq!(f[0].confidence, Confidence::High);
        assert_eq!(f[1].confidence, Confidence::Medium);
    }

    #[test]
    fn handled_results_and_non_calls_are_fine() {
        let f = check(
            r#"
fn a(e: &Env, t: Address, v: Vec<u32>) -> Result<(), Error> {
    let r = token::Client::new(e, &t).try_balance(&t);
    if token::Client::new(e, &t).try_decimals().is_err() { panic!() }
    match HookClient::new(e, &t).try_ping() { Ok(_) => {}, Err(_) => panic!() }
    let _x = u64::try_from(5i128);
    let _ = v.try_get(0);
    e.storage().instance().try_update(&K::A, |x: Option<u32>| Ok::<u32, Error>(1));
    Ok(())
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }
}
