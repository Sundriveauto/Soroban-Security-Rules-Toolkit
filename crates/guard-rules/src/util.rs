//! Helpers shared by several rules.

use guard_parser::syntax::{call_name, strip, words};
use syn::Expr;

/// Words that suggest a value is a token amount or balance.
pub const AMOUNT_WORDS: &[&str] = &[
    "amount",
    "amounts",
    "balance",
    "balances",
    "supply",
    "fee",
    "fees",
    "price",
    "allowance",
    "reward",
    "rewards",
    "stake",
    "staked",
    "debt",
    "collateral",
    "share",
    "shares",
    "liquidity",
    "reserve",
    "reserves",
    "deposit",
    "deposits",
    "withdrawal",
    "principal",
    "interest",
    "payout",
    "tokens",
    "lp",
];

/// Lowercase configured words, merged with defaults.
pub fn word_set(defaults: &[&str], extra: Vec<String>) -> Vec<String> {
    let mut v: Vec<String> = defaults.iter().map(|s| s.to_string()).collect();
    v.extend(extra.into_iter().flat_map(|e| words(&e)));
    v.sort();
    v.dedup();
    v
}

/// `true` if any word of `ident` is in `set`.
pub fn has_word(ident: &str, set: &[String]) -> bool {
    words(ident).iter().any(|w| set.iter().any(|s| s == w))
}

/// `true` for `SCREAMING_CASE` identifiers (constants).
pub fn is_constant_name(name: &str) -> bool {
    name.chars().any(|c| c.is_ascii_alphabetic()) && name.chars().all(|c| !c.is_ascii_lowercase())
}

/// The "name" of an operand: variable, field, called function or method.
/// `self.total_supply` → `total_supply`, `read_balance(&e)` → `read_balance`,
/// `x.amount.clone()` → `amount`. Literals have no name.
pub fn operand_name(expr: &Expr) -> Option<String> {
    match strip(expr) {
        Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        Expr::Field(f) => match &f.member {
            syn::Member::Named(i) => Some(i.to_string()),
            syn::Member::Unnamed(_) => operand_name(&f.base),
        },
        Expr::MethodCall(m) => {
            let name = m.method.to_string();
            if matches!(
                name.as_str(),
                "unwrap"
                    | "unwrap_or"
                    | "unwrap_or_default"
                    | "unwrap_or_else"
                    | "expect"
                    | "clone"
                    | "into"
                    | "to_owned"
            ) {
                operand_name(&m.receiver)
            } else {
                Some(name)
            }
        }
        Expr::Call(c) => call_name(c),
        Expr::Index(i) => operand_name(&i.expr),
        Expr::Cast(c) => operand_name(&c.expr),
        _ => None,
    }
}

/// `true` if the expression is a numeric literal (possibly negated).
pub fn is_literal(expr: &Expr) -> bool {
    match strip(expr) {
        Expr::Lit(_) => true,
        Expr::Unary(u) => is_literal(&u.expr),
        _ => false,
    }
}
