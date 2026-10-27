//! SAFE: a token modelled on the Soroban example token. stellar-guard must
//! report nothing for this crate.
#![no_std]

mod admin;
mod balance;
mod storage_types;

#[cfg(test)]
mod test;

use soroban_sdk::{contract, contractimpl, Address, Env, String};

use crate::admin::{read_administrator, write_administrator};
use crate::balance::{read_balance, receive_balance, spend_balance};
use crate::storage_types::{AllowanceDataKey, AllowanceValue, DataKey, INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD};

fn check_nonnegative_amount(amount: i128) {
    if amount < 0 {
        panic!("negative amount is not allowed: {}", amount)
    }
}

fn read_allowance(e: &Env, from: Address, spender: Address) -> AllowanceValue {
    let key = DataKey::Allowance(AllowanceDataKey { from, spender });
    match e.storage().temporary().get::<_, AllowanceValue>(&key) {
        Some(allowance) if allowance.expiration_ledger >= e.ledger().sequence() => allowance,
        _ => AllowanceValue {
            amount: 0,
            expiration_ledger: 0,
        },
    }
}

fn write_allowance(e: &Env, from: Address, spender: Address, amount: i128, expiration_ledger: u32) {
    let allowance = AllowanceValue {
        amount,
        expiration_ledger,
    };
    let key = DataKey::Allowance(AllowanceDataKey { from, spender });
    e.storage().temporary().set(&key, &allowance);
    if amount > 0 {
        let live_for = expiration_ledger
            .checked_sub(e.ledger().sequence())
            .expect("expiration_ledger is in the past");
        e.storage().temporary().extend_ttl(&key, live_for, live_for)
    }
}

fn spend_allowance(e: &Env, from: Address, spender: Address, amount: i128) {
    let allowance = read_allowance(e, from.clone(), spender.clone());
    if allowance.amount < amount {
        panic!("insufficient allowance");
    }
    if amount > 0 {
        let remaining = allowance.amount.checked_sub(amount).expect("underflow");
        write_allowance(e, from, spender, remaining, allowance.expiration_ledger);
    }
}

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn __constructor(e: Env, admin: Address, decimal: u32, name: String, symbol: String) {
        if decimal > 18 {
            panic!("Decimal must not be greater than 18");
        }
        write_administrator(&e, &admin);
        e.storage().instance().set(&DataKey::Decimals, &decimal);
        e.storage().instance().set(&DataKey::Name, &name);
        e.storage().instance().set(&DataKey::Symbol, &symbol);
    }

    pub fn mint(e: Env, to: Address, amount: i128) {
        check_nonnegative_amount(amount);
        let admin = read_administrator(&e);
        admin.require_auth();
        e.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        receive_balance(&e, to, amount);
    }

    pub fn set_admin(e: Env, new_admin: Address) {
        let admin = read_administrator(&e);
        admin.require_auth();
        write_administrator(&e, &new_admin);
        e.events().publish((soroban_sdk::symbol_short!("admin"),), new_admin);
    }

    pub fn allowance(e: Env, from: Address, spender: Address) -> i128 {
        read_allowance(&e, from, spender).amount
    }

    pub fn approve(e: Env, from: Address, spender: Address, amount: i128, expiration_ledger: u32) {
        from.require_auth();
        check_nonnegative_amount(amount);
        write_allowance(&e, from, spender, amount, expiration_ledger);
    }

    pub fn balance(e: Env, id: Address) -> i128 {
        read_balance(&e, id)
    }

    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        check_nonnegative_amount(amount);
        spend_balance(&e, from, amount);
        receive_balance(&e, to, amount);
    }

    pub fn transfer_from(e: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        check_nonnegative_amount(amount);
        spend_allowance(&e, from.clone(), spender, amount);
        spend_balance(&e, from, amount);
        receive_balance(&e, to, amount);
    }

    pub fn burn(e: Env, from: Address, amount: i128) {
        from.require_auth();
        check_nonnegative_amount(amount);
        spend_balance(&e, from, amount);
    }

    pub fn decimals(e: Env) -> u32 {
        e.storage().instance().get(&DataKey::Decimals).unwrap()
    }
}
