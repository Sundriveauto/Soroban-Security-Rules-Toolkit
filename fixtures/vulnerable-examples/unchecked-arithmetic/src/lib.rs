//! VULNERABLE: wrapping arithmetic on token amounts (overflow-checks is off in
//! Cargo.toml) and lossy casts.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    TotalStaked,
    Stake(Address),
    RewardRate,
}

const BPS: i128 = 10_000;

fn read_stake(env: &Env, user: &Address) -> i128 {
    env.storage().persistent().get(&DataKey::Stake(user.clone())).unwrap_or(0)
}

#[contract]
pub struct Staking;

#[contractimpl]
impl Staking {
    pub fn stake(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let balance = read_stake(&env, &user);
        let new_balance = balance + amount; // expect: SG-003
        env.storage().persistent().set(&DataKey::Stake(user), &new_balance);

        let mut total_staked: i128 = env.storage().instance().get(&DataKey::TotalStaked).unwrap_or(0);
        total_staked += amount; // expect: SG-003
        env.storage().instance().set(&DataKey::TotalStaked, &total_staked);
    }

    pub fn unstake(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // No `balance >= amount` check: underflow wraps to a huge balance.
        let balance = read_stake(&env, &user);
        env.storage()
            .persistent()
            .set(&DataKey::Stake(user), &(balance - amount)); // expect: SG-003
    }

    pub fn pending_reward(env: Env, user: Address) -> u64 {
        let rate: i128 = env.storage().instance().get(&DataKey::RewardRate).unwrap_or(0);
        let reward = read_stake(&env, &user) * rate / BPS; // expect: SG-003
        reward as u64 // expect: SG-003
    }

    /// `i128` parameters are token amounts even without an amount-like name.
    pub fn quote(_env: Env, x: i128, y: i128) -> i128 {
        x * y // expect: SG-003
    }

    /// Divides before multiplying: small stakes round down to zero reward.
    pub fn share(_env: Env, amount: i128, total: i128, pool: i128) -> i128 {
        amount.checked_div(total).unwrap().checked_mul(pool).unwrap() // expect: SG-003
    }

    /// Checked arithmetic: not reported.
    pub fn stake_checked(env: Env, user: Address, amount: i128) {
        user.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let balance = read_stake(&env, &user)
            .checked_add(amount)
            .expect("stake overflow");
        env.storage().persistent().set(&DataKey::Stake(user), &balance);
    }
}
