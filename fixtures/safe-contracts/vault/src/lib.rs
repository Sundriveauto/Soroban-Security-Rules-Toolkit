//! SAFE: a vault using recommended patterns. stellar-guard must report nothing.
#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, token, Address, Env, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    InsufficientBalance = 2,
    BatchTooLarge = 3,
    Overflow = 4,
    InvalidAmount = 5,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Token,
    Balance(Address),
    Depositors,
    LastPoke,
}

const MAX_BATCH: u32 = 25;
const MAX_DEPOSITORS: u32 = 100;
const DAY_IN_LEDGERS: u32 = 17280;
const TTL_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS;
const TTL_EXTEND_TO: u32 = 30 * DAY_IN_LEDGERS;

fn require_admin(env: &Env) -> Address {
    let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
    admin.require_auth();
    admin
}

fn token_client(env: &Env) -> token::Client<'_> {
    let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
    token::Client::new(env, &token)
}

fn balance_of(env: &Env, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(user.clone()))
        .unwrap_or(0)
}

fn set_balance(env: &Env, user: &Address, amount: i128) {
    let key = DataKey::Balance(user.clone());
    env.storage().persistent().set(&key, &amount);
    env.storage()
        .persistent()
        .extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
}

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    /// Classic initializer, guarded against re-initialization.
    pub fn initialize(env: Env, admin: Address, token: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        Ok(())
    }

    pub fn deposit(env: Env, from: Address, amount: i128) -> Result<(), Error> {
        from.require_auth();
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        token_client(&env).transfer(&from, &env.current_contract_address(), &amount);
        let new_balance = balance_of(&env, &from)
            .checked_add(amount)
            .ok_or(Error::Overflow)?;
        set_balance(&env, &from, new_balance);

        let mut depositors: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Depositors)
            .unwrap_or(Vec::new(&env));
        if !depositors.contains(&from) {
            if depositors.len() >= MAX_DEPOSITORS {
                return Err(Error::BatchTooLarge);
            }
            depositors.push_back(from);
            env.storage().persistent().set(&DataKey::Depositors, &depositors);
        }
        Ok(())
    }

    pub fn withdraw(env: Env, to: Address, amount: i128) -> Result<(), Error> {
        to.require_auth();
        let balance = balance_of(&env, &to);
        let remaining = balance.checked_sub(amount).ok_or(Error::Overflow)?;
        if remaining < 0 {
            return Err(Error::InsufficientBalance);
        }
        set_balance(&env, &to, remaining);
        token_client(&env).transfer(&env.current_contract_address(), &to, &amount);
        Ok(())
    }

    /// Admin payout with an explicit batch limit.
    pub fn payout(env: Env, recipients: Vec<Address>, amount: i128) -> Result<(), Error> {
        require_admin(&env);
        if recipients.len() > MAX_BATCH {
            panic_with_error!(&env, Error::BatchTooLarge);
        }
        let client = token_client(&env);
        for r in recipients.iter() {
            client.transfer(&env.current_contract_address(), &r, &amount);
        }
        Ok(())
    }

    /// Paginated read over a bounded list.
    pub fn depositors(env: Env, start: u32, limit: u32) -> Vec<Address> {
        assert!(limit <= MAX_BATCH, "limit too large");
        let all: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Depositors)
            .unwrap_or(Vec::new(&env));
        let mut page = Vec::new(&env);
        let end = start.saturating_add(limit).min(all.len());
        for i in start..end {
            page.push_back(all.get_unchecked(i));
        }
        page
    }

    /// Intentionally permissionless keeper hook, documented with a suppression.
    pub fn poke(env: Env) {
        let now = env.ledger().sequence();
        // stellar-guard-ignore SG-001 -- anyone may record a heartbeat; no value at risk
        env.storage().instance().set(&DataKey::LastPoke, &now);
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        balance_of(&env, &user)
    }
}
