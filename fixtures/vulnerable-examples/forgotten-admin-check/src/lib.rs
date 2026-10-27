//! One admin setter forgot the check its siblings perform (modelled on a
//! Code4rena finding in Reflector V3: invocation costs settable by anyone).
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Vec};

#[contracttype]
pub enum DataKey {
    Admin,
    CacheSize,
    Retention,
    Costs,
}

fn require_admin(e: &Env) {
    let admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap();
    admin.require_auth();
}

fn bump(e: &Env) {
    e.storage().instance().extend_ttl(17_280, 518_400);
}

#[contract]
pub struct Oracle;

#[contractimpl]
impl Oracle {
    pub fn __constructor(e: Env, admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &admin);
    }

    // Requires admin authorization
    pub fn set_cache_size(e: Env, size: u32) {
        require_admin(&e);
        e.storage().instance().set(&DataKey::CacheSize, &size);
        bump(&e);
    }

    // Requires admin authorization
    pub fn set_retention(e: Env, seconds: u64) {
        require_admin(&e);
        e.storage().instance().set(&DataKey::Retention, &seconds);
        bump(&e);
    }

    // Update invocation costs
    // Requires admin authorization
    pub fn set_costs(e: Env, costs: Vec<u64>) {
        e.storage().instance().set(&DataKey::Costs, &costs); // expect: SG-001
        bump(&e);
    }

    pub fn costs(e: Env) -> Vec<u64> {
        e.storage().instance().get(&DataKey::Costs).unwrap_or(Vec::new(&e))
    }
}
