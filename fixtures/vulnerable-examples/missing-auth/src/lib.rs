//! VULNERABLE: privileged and fund-moving functions with no authorization.
//! Every line carrying an "expect" marker comment must be reported by stellar-guard.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, vec, Address, BytesN, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Token,
    Balance(Address),
}

fn read_token(env: &Env) -> Address {
    env.storage().instance().get(&DataKey::Token).unwrap()
}

fn read_balance(env: &Env, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(user.clone()))
        .unwrap_or(0)
}

/// Looks like an access check but never calls `require_auth`.
fn require_admin(env: &Env) {
    let _admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
}

fn write_balance(env: &Env, user: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(user.clone()), &amount);
}

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn __constructor(env: Env, admin: Address, token: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
    }

    /// Safe: the depositor authorizes the call.
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        token::Client::new(&env, &read_token(&env)).transfer(&from, &env.current_contract_address(), &amount);
        let new_balance = read_balance(&env, &from).checked_add(amount).expect("overflow");
        write_balance(&env, &from, new_balance);
    }

    /// Anyone can drain any user's balance: `user.require_auth()` is missing.
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        let balance = read_balance(&env, &user);
        if balance < amount {
            panic!("insufficient balance");
        }
        write_balance(&env, &user, balance - amount);
        let client = token::Client::new(&env, &read_token(&env));
        client.transfer(&env.current_contract_address(), &user, &amount); // expect: SG-001
    }

    /// Anyone can take over the contract.
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &new_admin); // expect: SG-001
    }

    /// Anyone can replace the contract code.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash); // expect: SG-001
    }

    /// Anyone can overwrite anyone's balance (write happens in a helper).
    pub fn credit(env: Env, user: Address, amount: i128) {
        write_balance(&env, &user, amount); // expect: SG-001
    }

    /// The helper's name suggests an admin check, but its body does not authorize.
    pub fn set_token(env: Env, token: Address) {
        require_admin(&env);
        env.storage().instance().set(&DataKey::Token, &token); // expect: SG-001
    }

    /// Authorization only happens when `notify` is set; otherwise anyone can withdraw for `user`.
    pub fn withdraw_to(env: Env, user: Address, amount: i128, notify: bool) {
        if notify {
            user.require_auth();
        }
        let client = token::Client::new(&env, &read_token(&env));
        client.transfer(&env.current_contract_address(), &user, &amount); // expect: SG-001
    }

    /// The caller authorizes, but the balance debited belongs to `from`.
    pub fn move_balance(env: Env, caller: Address, from: Address, amount: i128) {
        caller.require_auth();
        let balance = read_balance(&env, &from);
        if balance < amount {
            panic!("insufficient balance");
        }
        write_balance(&env, &from, balance - amount); // expect: SG-001
        let credited = read_balance(&env, &caller).checked_add(amount).expect("overflow");
        write_balance(&env, &caller, credited);
    }

    /// Signs an empty argument list, so the signature works for any recipient and amount.
    pub fn withdraw_signed(env: Env, user: Address, to: Address, amount: i128) {
        user.require_auth_for_args(vec![&env]); // expect: SG-001
        let client = token::Client::new(&env, &read_token(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// Read-only: not reported.
    pub fn balance(env: Env, user: Address) -> i128 {
        read_balance(&env, &user)
    }
}
