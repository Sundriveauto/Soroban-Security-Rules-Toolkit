//! Built-in stellar-guard detection rules.
//!
//! | ID     | Name                      | Looks for |
//! |--------|---------------------------|-----------|
//! | SG-001 | `missing-authorization`   | Exported functions that change state or move funds without `require_auth` |
//! | SG-002 | `storage-tier-misuse`     | Long-lived state in temporary storage; per-user data in instance storage |
//! | SG-003 | `unchecked-arithmetic`    | Plain `+ - *` and lossy `as` casts on token amounts |
//! | SG-004 | `unbounded-iteration`     | Loops over storage-backed or caller-supplied collections without a bound |
//! | SG-005 | `unprotected-initializer` | `initialize` functions that can be called more than once |
//! | SG-006 | `negative-amount`         | `i128` amounts written to storage without a sign check |
//! | SG-007 | `missing-ttl-extension`   | Persistent / instance data whose TTL is never extended |
//! | SG-008 | `ignored-try-call`        | Discarded results of `client.try_*` cross-contract calls |
//!
//! Every rule is a heuristic over source code. See `docs/rules/` for the
//! detection logic, known false positives and false negatives of each rule.

use guard_engine::Rule;

mod sg001_missing_auth;
mod sg002_storage_tier;
mod sg003_unchecked_arithmetic;
mod sg004_unbounded_iteration;
mod sg005_unprotected_init;
mod sg006_negative_amount;
mod sg007_missing_ttl_extension;
mod sg008_ignored_try_call;
mod util;

#[cfg(test)]
mod test_util;

pub use sg001_missing_auth::MissingAuthorization;
pub use sg002_storage_tier::StorageTierMisuse;
pub use sg003_unchecked_arithmetic::UncheckedArithmetic;
pub use sg004_unbounded_iteration::UnboundedIteration;
pub use sg005_unprotected_init::UnprotectedInitializer;
pub use sg006_negative_amount::NegativeAmount;
pub use sg007_missing_ttl_extension::MissingTtlExtension;
pub use sg008_ignored_try_call::IgnoredTryCall;

/// All built-in rules, ordered by ID.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(MissingAuthorization),
        Box::new(StorageTierMisuse),
        Box::new(UncheckedArithmetic),
        Box::new(UnboundedIteration),
        Box::new(UnprotectedInitializer),
        Box::new(NegativeAmount),
        Box::new(MissingTtlExtension),
        Box::new(IgnoredTryCall),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn ids_are_unique_and_sorted() {
        let ids: Vec<_> = super::all().iter().map(|r| r.meta().id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn metadata_is_complete() {
        for r in super::all() {
            let m = r.meta();
            assert!(m.id.starts_with("SG-") && m.id.len() == 6, "{}", m.id);
            assert!(!m.name.is_empty() && !m.summary.is_empty());
            assert!(m.description.len() > 40, "{} description too short", m.id);
            assert!(m.remediation.len() > 20, "{} remediation too short", m.id);
        }
    }
}
