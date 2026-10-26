//! VULNERABLE: signed amounts written to contract storage without a sign check.
//! A negative mint burns another user's balance; a negative repayment increases the debt.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Token,
    Balance(Address),
    Debt(Address),
}

fn read_balance(env: &Env, user: &Address) -> i128 {
    env.storage().persistent().get(&DataKey::Balance(user.clone())).unwrap_or(0)
}

fn write_balance(env: &Env, user: &Address, amount: i128) {
    env.storage().persistent().set(&DataKey::Balance(user.clone()), &amount);
}

fn check_positive(amount: i128) {
    if amount <= 0 {
        panic!("amount must be positive");
    }
}

#[contract]
pub struct Ledger;

#[contractimpl]
impl Ledger {
    pub fn __constructor(env: Env, admin: Address, token: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
    }

    /// The minter authorizes, but a negative `amount` lowers `to`'s balance.
    pub fn mint(env: Env, minter: Address, to: Address, amount: i128) {
        minter.require_auth();
        let balance = read_balance(&env, &to);
        write_balance(&env, &to, balance.checked_add(amount).expect("overflow")); // expect: SG-006
    }

    /// A negative repayment increases the debt instead of reducing it.
    pub fn repay(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        let key = DataKey::Debt(borrower);
        let debt: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let remaining = debt.checked_sub(amount).expect("underflow");
        env.storage().persistent().set(&key, &remaining); // expect: SG-006
    }

    /// Safe: checked through a helper.
    pub fn mint_checked(env: Env, minter: Address, to: Address, amount: i128) {
        minter.require_auth();
        check_positive(amount);
        let balance = read_balance(&env, &to);
        write_balance(&env, &to, balance.checked_add(amount).expect("overflow"));
    }

    /// Safe: the token contract rejects negative amounts, so the call fails.
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token).transfer(&from, &env.current_contract_address(), &amount);
        let balance = read_balance(&env, &from);
        write_balance(&env, &from, balance.checked_add(amount).expect("overflow"));
    }
}
