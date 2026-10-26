//! Test-only code is excluded from analysis (declared as `#[cfg(test)] mod test;`).
//! The helper below would be flagged by SG-002 and SG-003 in contract code.
extern crate std;

use soroban_sdk::{testutils::Address as _, Address, Env};

#[allow(dead_code)]
fn unsafe_helper(e: &Env, amount: i128, balance: i128) -> i128 {
    e.storage().temporary().set(&crate::storage_types::DataKey::Admin, &Address::generate(e));
    balance + amount
}

#[test]
fn addresses_are_unique() {
    let e = Env::default();
    assert_ne!(Address::generate(&e), Address::generate(&e));
}
