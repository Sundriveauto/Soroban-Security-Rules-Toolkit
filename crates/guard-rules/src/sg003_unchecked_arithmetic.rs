//! SG-003: plain arithmetic and lossy casts on token amounts.

use std::collections::HashSet;

use guard_engine::{Confidence, Diagnostic, Rule, RuleContext, RuleMeta, RuleOption, Severity};
use guard_parser::syntax::{is_assert_macro, macro_args, macro_name};
use guard_parser::Span;
use syn::visit::Visit;
use syn::{BinOp, Expr};

use crate::util::{has_word, is_constant_name, is_literal, operand_name, word_set, AMOUNT_WORDS};

pub struct UncheckedArithmetic;

static META: RuleMeta = RuleMeta {
    id: "SG-003",
    name: "unchecked-arithmetic",
    summary: "Unchecked arithmetic on token amounts",
    description: "Plain `+`, `-`, `*` (and their assignment forms) on values that look like token amounts or \
balances, and `as` casts of such values to a narrower integer type. In release builds without \
`overflow-checks = true`, integer overflow wraps silently, which can mint balances or bypass limits. `as` casts \
never check: `amount as u64` truncates and `amount as u128` turns negative amounts into huge positive ones.",
    remediation: "Use `checked_add` / `checked_sub` / `checked_mul` and handle `None`, set \
`overflow-checks = true` in `[profile.release]`, and replace `as` casts with `try_from`.",
    default_severity: Severity::Warning,
    tags: &["security", "arithmetic", "overflow"],
    options: &[RuleOption {
        name: "amount-identifiers",
        description: "Extra identifier words treated as token amounts.",
        default: "[]",
    }],
};

impl Rule for UncheckedArithmetic {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>) {
        if !cx.is_soroban() {
            return;
        }
        let amount_words = word_set(AMOUNT_WORDS, cx.options.string_list("amount-identifiers"));
        let overflow_checks = cx.crate_info.overflow_checks;
        for (_, f) in cx.model.fns_in_file(cx.file_idx) {
            let mut v = ArithVisitor {
                amount_words: &amount_words,
                derived: derived_amounts(f, &amount_words),
                wide_params: wide_int_params(f),
                overflow_checks,
                function: &f.name,
                guarded_pairs: collect_comparisons(f.block),
                suppress: 0,
                out: &mut *out,
            };
            v.visit_block(f.block);
        }
    }
}

/// Pairs of operand names compared in conditions (`if balance < amount`), used
/// to skip subtractions guarded by an explicit underflow check. Every compared
/// name is also recorded as `(name, "")` (range-checked, e.g. `amount > 0`).
fn collect_comparisons(block: &syn::Block) -> HashSet<(String, String)> {
    struct C {
        pairs: HashSet<(String, String)>,
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
                let (l, r) = (operand_name(&b.left), operand_name(&b.right));
                for n in [&l, &r].into_iter().flatten() {
                    self.pairs.insert((n.clone(), String::new()));
                }
                if let (Some(l), Some(r)) = (l, r) {
                    self.pairs.insert((l.clone(), r.clone()));
                    self.pairs.insert((r, l));
                }
            }
            syn::visit::visit_expr_binary(self, b);
        }
    }
    let mut c = C { pairs: HashSet::new(), in_cond: 0 };
    c.visit_block(block);
    c.pairs
}

/// Parameters typed `i128` / `u128`, Soroban's token-amount types.
fn wide_int_params(f: &guard_parser::FnDef<'_>) -> HashSet<String> {
    f.params()
        .into_iter()
        .filter(|(_, ty)| matches!(guard_parser::syntax::compact(*ty).trim_start_matches('&'), "i128" | "u128"))
        .map(|(n, _)| n)
        .collect()
}

/// Locals whose initializer is an amount: an amount-named value or call
/// (`read_balance(&e)`), an `i128`/`u128` parameter, another such local, or
/// arithmetic on one (`let x = a * 2`). Computed to a fixpoint.
fn derived_amounts(f: &guard_parser::FnDef<'_>, amount_words: &[String]) -> HashSet<String> {
    fn is_amount(e: &Expr, words: &[String], known: &HashSet<String>) -> bool {
        match guard_parser::syntax::strip(e) {
            Expr::Binary(b) if op_info(&b.op).is_some() || matches!(b.op, BinOp::Div(_)) => {
                is_amount(&b.left, words, known) || is_amount(&b.right, words, known)
            }
            Expr::MethodCall(m)
                if m.method.to_string().starts_with("checked_") || m.method.to_string().starts_with("saturating_") =>
            {
                is_amount(&m.receiver, words, known)
            }
            Expr::MethodCall(m)
                if matches!(m.method.to_string().as_str(), "unwrap" | "expect" | "unwrap_or" | "unwrap_or_default") =>
            {
                is_amount(&m.receiver, words, known)
            }
            other => {
                if is_literal(other) {
                    return false;
                }
                operand_name(other)
                    .is_some_and(|n| !is_constant_name(&n) && (has_word(&n, words) || known.contains(&n)))
            }
        }
    }
    let bindings = guard_parser::syntax::Bindings::collect(f.block);
    let mut known = wide_int_params(f);
    let params = known.clone();
    let mut derived = HashSet::new();
    for _ in 0..6 {
        let mut changed = false;
        for (name, init) in bindings.iter() {
            if !known.contains(name) && is_amount(init, amount_words, &known) {
                known.insert(name.to_string());
                derived.insert(name.to_string());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    derived.retain(|n| !params.contains(n));
    derived
}

struct ArithVisitor<'a> {
    amount_words: &'a [String],
    /// Locals derived from amounts (see [`derived_amounts`]); inferred, so medium confidence at most.
    derived: HashSet<String>,
    /// `i128`/`u128` parameters: treated as amounts even without an amount-like name.
    wide_params: HashSet<String>,
    overflow_checks: Option<bool>,
    function: &'a str,
    guarded_pairs: HashSet<(String, String)>,
    /// > 0 while inside an already-reported expression.
    suppress: usize,
    out: &'a mut Vec<Diagnostic>,
}

impl ArithVisitor<'_> {
    /// The operand's name if it looks like a token amount, and whether that is
    /// only inferred (from an `i128`/`u128` parameter type or a local's initializer).
    fn amount_operand(&self, e: &Expr) -> Option<(String, bool)> {
        if is_literal(e) {
            return None;
        }
        let name = operand_name(e)?;
        if is_constant_name(&name) {
            return None;
        }
        if has_word(&name, self.amount_words) {
            return Some((name, false));
        }
        let is_local = matches!(guard_parser::syntax::strip(e), Expr::Path(p) if p.path.segments.len() == 1);
        (is_local && (self.wide_params.contains(&name) || self.derived.contains(&name))).then_some((name, true))
    }
}

fn op_info(op: &BinOp) -> Option<(&'static str, &'static str)> {
    Some(match op {
        BinOp::Add(_) => ("+", "checked_add"),
        BinOp::AddAssign(_) => ("+=", "checked_add"),
        BinOp::Sub(_) => ("-", "checked_sub"),
        BinOp::SubAssign(_) => ("-=", "checked_sub"),
        BinOp::Mul(_) => ("*", "checked_mul"),
        BinOp::MulAssign(_) => ("*=", "checked_mul"),
        _ => return None,
    })
}

impl<'ast> Visit<'ast> for ArithVisitor<'_> {
    fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
        let mut reported = false;
        if self.suppress == 0 {
            if let Some((sym, checked)) = op_info(&b.op) {
                let left = self.amount_operand(&b.left);
                let right = self.amount_operand(&b.right);
                let is_sub = matches!(b.op, BinOp::Sub(_) | BinOp::SubAssign(_));
                let guarded = is_sub
                    && match (operand_name(&b.left), operand_name(&b.right)) {
                        (Some(l), Some(r)) => self.guarded_pairs.contains(&(l, r)),
                        _ => false,
                    };
                // Constants on both sides cannot overflow at runtime in a meaningful way.
                let both_const = [&b.left, &b.right]
                    .iter()
                    .all(|e| is_literal(e) || operand_name(e).is_some_and(|n| is_constant_name(&n)));
                // Prefer a named amount over one inferred from its type.
                let pick = match (left, right) {
                    (Some(l), Some(r)) => Some(if l.1 && !r.1 { r } else { l }),
                    (l, r) => l.or(r),
                };
                if let Some((name, by_type)) = pick {
                    if !guarded && !both_const {
                        let (mut confidence, severity, note) = match self.overflow_checks {
                            Some(true) => (
                                Confidence::Low,
                                Some(Severity::Info),
                                "; `overflow-checks` is on, so overflow panics instead of wrapping",
                            ),
                            Some(false) => (
                                Confidence::High,
                                None,
                                "; `overflow-checks` is off for release builds, so overflow wraps silently",
                            ),
                            None => (Confidence::Medium, None, ""),
                        };
                        if by_type && confidence == Confidence::High {
                            confidence = Confidence::Medium;
                        }
                        let mut d = Diagnostic::new(
                            Span::of(&b.op),
                            format!("Unchecked `{sym}` on token amount `{name}`{note}"),
                            confidence,
                        )
                        .in_function(self.function)
                        .with_help(format!(
                            "Use `{checked}` and handle the `None` case, and enable `overflow-checks = true` \
in `[profile.release]`."
                        ));
                        if let Some(s) = severity {
                            d = d.with_severity(s);
                        }
                        self.out.push(d);
                        reported = true;
                    }
                }
            }
        }
        if reported {
            self.suppress += 1;
        }
        syn::visit::visit_expr_binary(self, b);
        if reported {
            self.suppress -= 1;
        }
    }

    fn visit_expr_cast(&mut self, c: &'ast syn::ExprCast) {
        if self.suppress == 0 {
            let target = guard_parser::syntax::compact(&*c.ty);
            let narrowing = matches!(
                target.as_str(),
                "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "isize"
            );
            if narrowing {
                let range_checked = |n: &String| self.guarded_pairs.contains(&(n.clone(), String::new()));
                if let Some((name, _)) = self.amount_operand(&c.expr).filter(|(n, _)| !range_checked(n)) {
                    self.out.push(
                        Diagnostic::new(
                            Span::of(c),
                            format!("Lossy `as {target}` cast of token amount `{name}`; `as` never checks for truncation or sign loss"),
                            Confidence::Medium,
                        )
                        .in_function(self.function)
                        .with_help(format!(
                            "Use `{target}::try_from({name})` and handle the error instead of `as {target}`."
                        )),
                    );
                }
            }
        }
        syn::visit::visit_expr_cast(self, c);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        for a in macro_args(m) {
            self.visit_expr(&a);
        }
    }

    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use guard_parser::CrateInfo;

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(UncheckedArithmetic), src)
    }

    #[test]
    fn flags_plain_arithmetic_on_amounts() {
        let f = check(
            r#"
fn receive(e: &Env, addr: Address, amount: i128) {
    let balance = read_balance(e, addr.clone());
    write_balance(e, addr, balance + amount);
}
fn fee(amount: i128, fee_bps: i128) -> i128 { amount * fee_bps / 10_000 }
fn total(s: &mut State, amount: i128) { s.total_supply += amount; }
"#,
        );
        assert_eq!(lines(&f), vec![4, 6, 7]);
        assert!(f.iter().all(|x| x.confidence == Confidence::High));
        assert!(f[0].message.contains("`+`"));
        assert!(f[0].help.contains("checked_add"));
    }

    #[test]
    fn reports_each_expression_once() {
        let f = check("fn x(balance: i128, amount: i128, fee: i128) -> i128 { balance + amount - fee }");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn flags_lossy_casts() {
        let f = check("fn x(amount: i128) -> u64 { let a = amount as u64; let b = amount as i128; a }");
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("as u64"));
    }

    #[test]
    fn overflow_checks_downgrades_to_info() {
        let f = run_with(
            Box::new(UncheckedArithmetic),
            "fn x(balance: i128, amount: i128) -> i128 { balance + amount }",
            soroban_crate(Some(true)),
            &Default::default(),
        );
        assert_eq!(f[0].severity, Severity::Info);
        assert_eq!(f[0].confidence, Confidence::Low);
    }

    #[test]
    fn ignores_safe_patterns() {
        let f = check(
            r#"
fn a(balance: i128, amount: i128) -> i128 { balance.checked_add(amount).unwrap() }
fn b(balance: i128, amount: i128) -> i128 {
    if balance < amount { panic!("insufficient balance"); }
    balance - amount
}
fn c(i: u32, len: u32) -> u32 { i + 1 + len }
fn d() -> i128 { MAX_FEE * 2 }
fn e(amount: i128) -> i128 { amount.saturating_mul(2) }
fn f(x: u32) -> u64 { x as u64 }
fn g(balance: i128, amount: i128) { assert!(amount <= balance); let _ = balance - amount; }
fn h(amount: i128) -> u128 { if amount > 0 { amount as u128 } else { 0 } }
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn flags_i128_params_without_amount_names() {
        let f = check("fn add(a: i128, b: i128) -> i128 { a + b }\nfn idx(i: u32, n: u32) -> u32 { i + n }");
        assert_eq!(lines(&f), vec![1]);
        assert_eq!(f[0].confidence, Confidence::Medium);
        assert!(f[0].message.contains("`a`"), "{}", f[0].message);
    }

    #[test]
    fn tracks_amounts_through_locals() {
        let f = check(
            r#"
fn a(e: &Env) -> i128 { let x = read_balance(e); let y = x * 3; y + 1 }
fn b(items: Vec<u32>) -> u32 { let n = items.len(); n + 1 }
fn c(e: &Env) -> i128 { let x = read_balance(e).checked_add(1).unwrap(); x - 2 }
"#,
        );
        assert_eq!(lines(&f), vec![2, 2, 4], "{f:#?}");
        assert!(f.iter().all(|x| x.confidence == Confidence::Medium));
    }

    #[test]
    fn named_amount_keeps_high_confidence_next_to_typed_param() {
        let f = check("fn x(n: i128, amount: i128) -> i128 { n * amount }");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, Confidence::High);
        assert!(f[0].message.contains("`amount`"), "{}", f[0].message);
    }

    #[test]
    fn non_soroban_code_is_skipped() {
        let f = run_with(
            Box::new(UncheckedArithmetic),
            "fn x(balance: i128, amount: i128) -> i128 { balance + amount }",
            CrateInfo::default(),
            &Default::default(),
        );
        assert!(f.is_empty());
    }

    #[test]
    fn custom_amount_identifiers() {
        let mut s = guard_engine::Settings::default();
        s.rule_mut("SG-003").options.insert("amount-identifiers".into(), toml::Value::Array(vec!["qty".into()]));
        let f = run_with(
            Box::new(UncheckedArithmetic),
            "fn x(qty: i128, n: i128) -> i128 { qty * n }",
            soroban_crate(Some(false)),
            &s,
        );
        assert_eq!(f.len(), 1);
    }
}
