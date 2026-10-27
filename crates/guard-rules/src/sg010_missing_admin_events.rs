//! SG-010: exported privileged changes that do not publish a Soroban event.

use guard_engine::{Confidence, Diagnostic, Rule, RuleContext, RuleMeta, Severity};
use guard_parser::{FnFacts, Span};

use crate::sg001_missing_auth::PRIVILEGED_WORDS;
use crate::util::{has_word, word_set};

pub struct MissingAdminEvents;

static META: RuleMeta = RuleMeta {
    id: "SG-010",
    name: "missing-admin-events",
    summary: "Privileged changes do not publish an event",
    description: "An exported contract function upgrades the contract or writes a privileged \
storage key without publishing a Soroban event itself or through a helper it calls. Events make \
these changes easier for indexers and operators to monitor off-chain.",
    remediation: "Publish a descriptive event with `env.events().publish(..)` when the privileged \
change occurs, directly or through a helper.",
    default_severity: Severity::Info,
    tags: &["operations", "events", "access-control"],
    options: &[],
};

const SKIPPED: &[&str] = &["__constructor", "__check_auth"];

impl Rule for MissingAdminEvents {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>) {
        let privileged = word_set(PRIVILEGED_WORDS, vec!["pause".into(), "paused".into()]);
        let model = cx.model;

        for (id, f) in model.fns_in_file(cx.file_idx) {
            if !f.is_contract_export() || SKIPPED.contains(&f.name.as_str()) {
                continue;
            }

            let publishes = model.witness(id, &|_, facts| facts.event_publishes.first().copied()).is_some();
            if publishes {
                continue;
            }

            if let Some(w) = model.witness(id, &|_, facts| facts.upgrades.first().copied()) {
                out.push(missing_event(&f.name, w.span, "upgrades the contract"));
            }
            if let Some(w) = model.witness(id, &|_, facts| privileged_write(facts, &privileged)) {
                out.push(missing_event(&f.name, w.span, "modifies privileged configuration"));
            }
        }
    }
}

fn privileged_write(facts: &FnFacts, privileged: &[String]) -> Option<Span> {
    facts.state_writes.iter().find(|w| w.key_idents.last().is_some_and(|key| has_word(key, privileged))).map(|w| w.span)
}

fn missing_event(function: &str, span: Span, operation: &str) -> Diagnostic {
    Diagnostic::new(
        span,
        format!("Exported function `{function}` {operation} without publishing a Soroban event"),
        Confidence::High,
    )
    .with_help("Publish an event with `env.events().publish(..)` so off-chain consumers can monitor this change.")
    .in_function(function)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(MissingAdminEvents), src)
    }

    #[test]
    fn reports_unlogged_upgrades_and_privileged_writes_through_helpers() {
        let findings = check(
            r#"
fn upgrade(e: &Env, wasm: &Bytes) { e.deployer().update_current_contract_wasm(wasm); }
fn set_admin(e: &Env, admin: &Address) { e.storage().instance().set(&DataKey::Admin, admin); }
#[contractimpl]
impl C {
    pub fn upgrade_without_event(e: Env, wasm: Bytes) { upgrade(&e, &wasm); }
    pub fn admin_without_event(e: Env, admin: Address) { set_admin(&e, &admin); }
}
"#,
        );
        assert_eq!(findings.len(), 2, "{findings:#?}");
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("upgrades the contract"));
        assert!(findings[1].message.contains("modifies privileged configuration"));
    }

    #[test]
    fn direct_and_helper_events_suppress_findings_but_other_publish_methods_do_not() {
        let findings = check(
            r#"
fn set_admin(e: &Env, admin: &Address) { e.storage().instance().set(&DataKey::Admin, admin); }
fn emit(e: &Env) { e.events().publish((symbol_short!("admin"),), 1); }
#[contractimpl]
impl C {
    pub fn direct_event(e: Env, admin: Address) {
        set_admin(&e, &admin);
        e.events().publish((symbol_short!("admin"),), 1);
    }
    pub fn helper_event(e: Env, admin: Address) {
        set_admin(&e, &admin);
        emit(&e);
    }
    pub fn unrelated_publish(e: Env, admin: Address, watcher: Watcher) {
        set_admin(&e, &admin);
        watcher.publish(1);
    }
}
"#,
        );
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert!(findings[0].message.contains("unrelated_publish"));
    }
}
