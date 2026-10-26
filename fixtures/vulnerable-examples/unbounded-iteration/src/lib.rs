//! VULNERABLE: loops over a storage list anyone can grow, and over
//! caller-supplied sizes.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, vec, Address, Env, Vec};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Token,
    Members,
}

fn read_members(env: &Env) -> Vec<Address> {
    env.storage()
        .persistent()
        .get(&DataKey::Members)
        .unwrap_or(vec![env])
}

fn require_admin(env: &Env) {
    let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
    admin.require_auth();
}

#[contract]
pub struct Airdrop;

#[contractimpl]
impl Airdrop {
    /// Anyone can join, so `Members` grows without limit.
    pub fn join(env: Env, member: Address) {
        member.require_auth();
        let mut members = read_members(&env);
        members.push_back(member);
        env.storage().persistent().set(&DataKey::Members, &members);
    }

    /// Eventually exceeds the transaction budget and can never succeed again.
    pub fn distribute(env: Env, amount_each: i128) {
        require_admin(&env);
        let members = read_members(&env);
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token);
        for member in members.iter() { // expect: SG-004
            client.transfer(&env.current_contract_address(), &member, &amount_each);
        }
    }

    pub fn member_count_slow(env: Env) -> u32 {
        let members: Vec<Address> = env.storage().persistent().get(&DataKey::Members).unwrap();
        members.iter().filter(|m| m.clone() != env.current_contract_address()).count() as u32 // expect: SG-004
    }

    /// The caller decides how much work is done.
    pub fn batch_pay(env: Env, recipients: Vec<Address>, amount: i128) {
        require_admin(&env);
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token);
        for r in recipients.iter() { // expect: SG-004
            client.transfer(&env.current_contract_address(), &r, &amount);
        }
    }

    pub fn ping(env: Env, rounds: u32) -> u32 {
        let mut acc = 0u32;
        for i in 0..rounds { // expect: SG-004
            acc = acc.wrapping_add(i);
        }
        env.events().publish(("ping",), acc);
        acc
    }
}
