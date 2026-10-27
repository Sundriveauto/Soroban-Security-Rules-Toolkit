//! Privileged changes are not published as events.
#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Paused,
}

#[contract]
pub struct Admin;

#[contractimpl]
impl Admin {
    pub fn set_admin(e: Env, admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &admin); // expect: SG-001, SG-007, SG-010
    }

    pub fn pause(e: Env) {
        e.storage().instance().set(&DataKey::Paused, &true); // expect: SG-001, SG-010
    }

    pub fn upgrade(e: Env, wasm: Bytes) {
        e.deployer().update_current_contract_wasm(&wasm); // expect: SG-001, SG-010
    }
}
