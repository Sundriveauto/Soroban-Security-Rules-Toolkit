//! VULNERABLE: `initialize` can be called again by anyone to replace the admin.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Token,
    FeeBps,
}

fn write_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&DataKey::Admin, admin);
}

#[contract]
pub struct Pool;

#[contractimpl]
impl Pool {
    pub fn initialize(env: Env, admin: Address, token: Address, fee_bps: u32) { // expect: SG-005
        write_admin(&env, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
    }

    pub fn set_fee(env: Env, fee_bps: u32) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
    }
}
