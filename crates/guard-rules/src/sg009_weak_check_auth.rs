//! SG-009: custom-account `__check_auth` implementations that do not verify anything.

use guard_engine::{Confidence, Diagnostic, Rule, RuleContext, RuleMeta, Severity};
use guard_parser::syntax::idents;
use guard_parser::{CrateModel, FnId};

pub struct WeakCheckAuth;

static META: RuleMeta = RuleMeta {
    id: "SG-009",
    name: "weak-check-auth",
    summary: "Custom account `__check_auth` does not verify the signature",
    description: "A custom account contract authorizes every action taken on its behalf through `__check_auth(env, \
signature_payload, signatures, auth_contexts)`. If the implementation never uses the payload or the signatures, or \
never calls a signature-verification function (`ed25519_verify`, `secp256r1_verify`, `secp256k1_recover`, \
`bls12_381` checks) or delegates to another account's `require_auth`, then any transaction can spend the \
account's funds.",
    remediation: "Verify every signature against `signature_payload` (e.g. \
`env.crypto().ed25519_verify(&public_key, &signature_payload.into(), &signature)`) and check that the signer is \
authorized for each entry of `auth_contexts`.",
    default_severity: Severity::Error,
    tags: &["security", "authorization", "account-abstraction"],
    options: &[],
};

/// Calls that verify a cryptographic signature (over some message).
const CRYPTO: &[&str] = &[
    "ed25519_verify",
    "secp256r1_verify",
    "secp256k1_recover",
    "secp256k1_verify",
    "verify_sig_ecdsa_secp256r1",
    "bls12_381_check_g1_g2_pairing",
    "pairing_check",
];

/// Calls that hand authorization to other addresses (which verify their own signatures).
const DELEGATION: &[&str] = &["require_auth", "require_auth_for_args", "delegate_auth"];

impl Rule for WeakCheckAuth {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>) {
        let model = cx.model;
        for (id, f) in model.fns_in_file(cx.file_idx) {
            if f.name != "__check_auth" {
                continue;
            }
            let params = f.params();
            // (env, signature_payload, signatures, auth_contexts)
            if params.len() < 3 {
                continue;
            }
            let body_idents = idents(f.block);
            let used = |n: &str| body_idents.iter().any(|i| i == n);
            let (payload, signatures) = (params[1].0.as_str(), params[2].0.as_str());
            let (crypto, delegates) = verification(model, id);
            let (problem, confidence) = if !crypto && !delegates {
                let unused: Vec<String> =
                    [payload, signatures].iter().filter(|n| !used(n)).map(|n| format!("`{n}`")).collect();
                let detail =
                    if unused.is_empty() { String::new() } else { format!(" and never uses {}", unused.join(" or ")) };
                (
                    format!("never verifies a signature or delegates authorization{detail}"),
                    if unused.is_empty() { Confidence::Medium } else { Confidence::High },
                )
            } else if crypto && !delegates && !used(payload) {
                (format!("verifies a signature but never uses `{payload}`, so the signature is not bound to this transaction"), Confidence::Medium)
            } else {
                continue;
            };
            out.push(
                Diagnostic::new(
                    f.name_span,
                    format!("`__check_auth` {problem}; it may accept any transaction"),
                    confidence,
                )
                .in_function(&f.name),
            );
        }
    }
}

/// Whether `id` (or a crate helper it calls) verifies a cryptographic signature, and
/// whether it delegates authorization to other addresses.
fn verification(model: &CrateModel<'_>, id: FnId) -> (bool, bool) {
    let mut crypto = false;
    let mut delegates = false;
    for f in model.reachable(id) {
        let facts = &model.facts[f];
        delegates |= !facts.auth.is_empty() || !facts.cond_auth.is_empty();
        for c in &facts.calls {
            crypto |= CRYPTO.contains(&c.name.as_str()) || c.name.contains("verify");
            delegates |= DELEGATION.contains(&c.name.as_str());
        }
    }
    (crypto, delegates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(WeakCheckAuth), src)
    }

    #[test]
    fn flags_accounts_that_verify_nothing() {
        let f = check(
            r#"
#[contractimpl]
impl CustomAccountInterface for A {
    type Signature = BytesN<64>;
    type Error = Error;
    fn __check_auth(env: Env, _signature_payload: Hash<32>, _signature: BytesN<64>, _ctx: Vec<Context>) -> Result<(), Error> {
        Ok(())
    }
}
"#,
        );
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].message.contains("never uses `_signature_payload` or `_signature`"), "{}", f[0].message);
        assert_eq!(f[0].confidence, Confidence::High);
        assert_eq!(f[0].severity, Severity::Error);
    }

    #[test]
    fn flags_used_but_unverified() {
        let f = check(
            r#"
#[contractimpl]
impl CustomAccountInterface for A {
    fn __check_auth(env: Env, payload: Hash<32>, sig: BytesN<64>, ctx: Vec<Context>) -> Result<(), Error> {
        let stored: BytesN<32> = env.storage().instance().get(&K::Hash).unwrap();
        if stored.len() != sig.len() + payload.to_array().len() { return Err(Error::Bad); }
        Ok(())
    }
}
"#,
        );
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].message.contains("never verifies a signature"));
        assert_eq!(f[0].confidence, Confidence::Medium);
    }

    #[test]
    fn flags_signature_not_bound_to_payload() {
        let f = check(
            r#"
#[contractimpl]
impl CustomAccountInterface for A {
    fn __check_auth(env: Env, _payload: Hash<32>, sig: BytesN<64>, ctx: Vec<Context>) -> Result<(), Error> {
        let pk: BytesN<32> = env.storage().instance().get(&K::Pk).unwrap();
        let msg = Bytes::from_array(&env, &[1, 2, 3]);
        env.crypto().ed25519_verify(&pk, &msg, &sig);
        Ok(())
    }
}
"#,
        );
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].message.contains("never uses `_payload`"), "{}", f[0].message);
    }

    #[test]
    fn verifying_accounts_are_fine() {
        let f = check(
            r#"
fn check_sig(env: &Env, pk: &BytesN<32>, payload: &Hash<32>, sig: &BytesN<64>) {
    env.crypto().ed25519_verify(pk, &payload.clone().into(), sig);
}
#[contractimpl]
impl CustomAccountInterface for A {
    fn __check_auth(env: Env, signature_payload: Hash<32>, signatures: Vec<Sig>, ctx: Vec<Context>) -> Result<(), Error> {
        for s in signatures.iter() { check_sig(&env, &s.public_key, &signature_payload, &s.signature); }
        Ok(())
    }
}
#[contractimpl]
impl CustomAccountInterface for D {
    fn __check_auth(env: Env, _payload: Hash<32>, _s: (), _ctx: Vec<Context>) -> Result<(), Error> {
        for d in env.custom_account().get_delegated_signers().iter() { env.custom_account().delegate_auth(&d); }
        Ok(())
    }
}
#[contractimpl]
impl CustomAccountInterface for B {
    fn __check_auth(env: Env, signature_payload: Hash<32>, signer: Address, ctx: Vec<Context>) -> Result<(), Error> {
        let _ = signature_payload;
        signer.require_auth();
        Ok(())
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }
}
