//! VULNERABLE: balances and a counter are written but their TTL is never extended,
//! so entries are archived when the TTL runs out and every call touching them fails.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Points(Address),
    TotalAwarded,
}

#[contract]
pub struct Rewards;

#[contractimpl]
impl Rewards {
    /// One-time configuration: not reported.
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn award(env: Env, user: Address, points: u32) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        let key = DataKey::Points(user);
        let current: u32 = env.storage().persistent().get(&key).unwrap_or(0);
        let next = current.checked_add(points).expect("overflow");
        env.storage().persistent().set(&key, &next); // expect: SG-007
        let total: u32 = env.storage().instance().get(&DataKey::TotalAwarded).unwrap_or(0);
        let total = total.checked_add(points).expect("overflow");
        env.storage().instance().set(&DataKey::TotalAwarded, &total); // expect: SG-007
    }

    pub fn points(env: Env, user: Address) -> u32 {
        env.storage().persistent().get(&DataKey::Points(user)).unwrap_or(0)
    }
}
