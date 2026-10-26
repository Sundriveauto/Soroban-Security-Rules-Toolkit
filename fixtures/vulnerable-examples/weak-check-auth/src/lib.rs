//! VULNERABLE: a custom account whose `__check_auth` checks that a public key is
//! registered but never verifies the signature, so anyone can spend from it.
#![no_std]
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    BytesN, Env, Vec,
};

#[contract]
pub struct Wallet;

#[contracttype]
#[derive(Clone)]
pub struct Signature {
    pub public_key: BytesN<32>,
    pub signature: BytesN<64>,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Signer(BytesN<32>),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    UnknownSigner = 1,
}

#[contractimpl]
impl Wallet {
    pub fn __constructor(env: Env, signer: BytesN<32>) {
        env.storage().instance().set(&DataKey::Signer(signer), &());
    }
}

#[contractimpl]
impl CustomAccountInterface for Wallet {
    type Signature = Signature;
    type Error = Error;

    fn __check_auth( // expect: SG-009
        env: Env,
        signature_payload: Hash<32>,
        signature: Signature,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        // Only checks that the key is registered; `signature.signature` is never verified
        // against `signature_payload`.
        let _ = signature_payload;
        if !env.storage().instance().has(&DataKey::Signer(signature.public_key)) {
            return Err(Error::UnknownSigner);
        }
        Ok(())
    }
}
