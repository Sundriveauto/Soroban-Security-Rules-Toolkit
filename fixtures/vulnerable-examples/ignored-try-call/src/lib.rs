//! VULNERABLE: the escrow marks a payout as done even when the token transfer failed.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Token,
    Paid(Address),
}

#[contract]
pub struct Escrow;

#[contractimpl]
impl Escrow {
    pub fn __constructor(env: Env, token: Address) {
        env.storage().instance().set(&DataKey::Token, &token);
    }

    pub fn release(env: Env, buyer: Address, seller: Address, amount: i128) {
        buyer.require_auth();
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token);
        // A failed transfer is silently ignored.
        let _ = client.try_transfer(&env.current_contract_address(), &seller, &amount); // expect: SG-008
        env.storage().temporary().set(&DataKey::Paid(seller), &true);
    }

    pub fn refund(env: Env, buyer: Address, amount: i128) {
        buyer.require_auth();
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token).try_transfer(&env.current_contract_address(), &buyer, &amount); // expect: SG-008
    }

    /// Safe: the result is checked.
    pub fn release_checked(env: Env, buyer: Address, seller: Address, amount: i128) {
        buyer.require_auth();
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token);
        if client.try_transfer(&env.current_contract_address(), &seller, &amount).is_err() {
            panic!("transfer failed");
        }
    }
}
