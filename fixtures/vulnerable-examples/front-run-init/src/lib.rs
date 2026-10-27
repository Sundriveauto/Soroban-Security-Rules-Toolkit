//! VULNERABLE: the initializer is guarded against a second call, but it runs in a separate
//! transaction after deployment and only authorizes the `admin` it is given. Anyone watching the
//! network can call it first with their own address. Use `__constructor` instead.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Treasury,
}

#[contract]
pub struct Escrow;

#[contractimpl]
impl Escrow {
    pub fn initialize(env: Env, admin: Address, treasury: Address) { // expect: SG-005
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin); // expect: SG-010
        env.storage().instance().set(&DataKey::Treasury, &treasury);
    }

    pub fn treasury(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Treasury).unwrap()
    }
}
