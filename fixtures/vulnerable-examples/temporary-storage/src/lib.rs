//! VULNERABLE: long-lived state kept in temporary storage, and per-user data
//! in instance storage.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    TotalSupply,
    Balance(Address),
    Allowance(Address, Address),
    LastClaim(Address),
}

const DAY_IN_LEDGERS: u32 = 17280;

fn write_balance(env: &Env, owner: &Address, amount: i128) {
    let key = DataKey::Balance(owner.clone());
    // Balances disappear forever when the entry's TTL runs out.
    env.storage().temporary().set(&key, &amount); // expect: SG-002
}

fn read_balance(env: &Env, owner: &Address) -> i128 {
    env.storage()
        .temporary()
        .get(&DataKey::Balance(owner.clone()))
        .unwrap_or(0)
}

#[contract]
pub struct Points;

#[contractimpl]
impl Points {
    pub fn __constructor(env: Env, admin: Address) {
        let tmp = env.storage().temporary();
        tmp.set(&DataKey::Admin, &admin); // expect: SG-002
        env.storage().temporary().set(&DataKey::TotalSupply, &0i128); // expect: SG-002
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let admin: Address = env.storage().temporary().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        let balance = read_balance(&env, &to).checked_add(amount).expect("overflow");
        write_balance(&env, &to, balance);
    }

    /// Allowances with an expiry belong in temporary storage: not reported.
    pub fn approve(env: Env, from: Address, spender: Address, amount: i128, live_for: u32) {
        from.require_auth();
        let key = DataKey::Allowance(from, spender);
        env.storage().temporary().set(&key, &amount);
        env.storage().temporary().extend_ttl(&key, live_for, live_for);
    }

    /// One instance entry that grows with every user and is loaded on every call.
    pub fn claim(env: Env, user: Address) {
        user.require_auth();
        let now = env.ledger().sequence();
        env.storage().instance().set(&DataKey::LastClaim(user), &now); // expect: SG-002
        env.storage().instance().extend_ttl(DAY_IN_LEDGERS, 30 * DAY_IN_LEDGERS);
    }
}
