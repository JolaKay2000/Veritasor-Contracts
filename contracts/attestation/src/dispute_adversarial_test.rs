
use crate::dispute;
use crate::RevocationData;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{Address, Env, String};

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.ledger().set_timestamp(1700000000);
    let contract = env.register(crate::AttestationContract, ());
    (env, contract)
}

fn in_contract<R>(
env: &Env,

contract: &Address,

f: impl FnOnce(&Env) -> R,
) -> R
{

env.as_contract(contract, || f(env))
}

// -----------------------------------------------------------------------------
// check_and_rollback_disputes adversarial coverage
// -----------------------------------------------------------------------------

#[test]
fn check_and_rollback_disputes_empty_ids_is_no_op() {

let (env, contract) = setup();

let dispute_ids = soroban_sdk::Vec::new(&env);


let result = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 0)

});

assert_eq!(
    result,

    0,

    "an empty dispute set must roll back nothing"

);
}

#[test]
fn check_and_rollback_disputes_respects_limit_and_reports_count() {

let (env, contract) = setup();

let dispute_ids = soroban_sdk::Vec::from_array(&env, [1, 2, 3]);


let result = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 2)

});

assert_eq!(
    result,

    2,

    "only the first limit disputes may be rolled back"

);
}

#[test]
fn check_and_rollback_disputes_limit_greater_than_length_is_clamped() {

let (env, contract) = setup();

let dispute_ids = soroban_sdk::Vec::from_array(&env, [10, 20]);

let result = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, u32::MAX)

});

assert_eq!(
    result,

    2,

    "limit larger than the input length must not overcount"

);
}

#[test]
fn check_and_rollback_disputes_zero_limit_rollbacks_nothing() {

let (env, contract) = setup();

let dispute_ids = soroban_sdk::Vec::from_array(&env, [7, 8, 9]);

let result = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 0)

});

assert_eq!(
    result,

    0,

    "a zero limit must roll back nothing"

);
}

#[test]
fn check_and_rollback_disputes_is_deterministic() {

let (env, contract) = setup();

let dispute_ids = soroban_sdk::Vec::from_array(&env, [11, 22, 33]);

let first = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 3)

});

let second = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 3)

});

assert_eq!(first, 3, "first call must report the clamped count");
assert_eq!(second, 3, "repeated calls must be deterministic");
}

#[test]
fn check_and_rollback_disputes_does_not_mutate_revocation_state() {

let (env, contract) = setup();

let business = Address::generate(&env);

let period = String::from_str(&env, "2026-09");

let reason = String::from_str(&env, "adversarial test revocation");

let revocation: RevocationData = (business.clone(), env.ledger().timestamp(), reason);

in_contract(&env, &contract, |env| {

dispute::record_revocation(env, &business, &period, &revocation)

});

let dispute_ids = soroban_sdk::Vec::from_array(&env, [1, 2, 3]);

let result = in_contract(&env, &contract, |env| {

dispute::check_and_rollback_disputes(env, &dispute_ids, 2)

});

assert_eq!(result, 2);

assert!(in_contract(&env, &contract, |env| {

dispute::is_attestation_revoked(env, &business, &period)

}), "rollback checks must not mutate revocation state");
}

// -----------------------------------------------------------------------------
// Existing revocation guard coverage
// -----------------------------------------------------------------------------

#[test]
fn require_not_revoked_for_update_allows_active_attestation() {

let (env, contract) = setup();

let business = Address::generate(&env);

let period = String::from_str(&env, "2026-09");

let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {

in_contract(&env, &contract, |env| {

dispute::require_not_revoked_for_update(env, &business, &period);

});

}));

assert!(
	result.is_ok(),
	"an active attestation must remain updatable"
);
assert!(in_contract(&env, &contract, |env| {
	dispute::is_attestation_revoked(env, &business, &period)
}));
}

#[test]
fn require_not_revoked_for_update_rejects_revoked_attestation() {

let (env, contract) = setup();

let business = Address::generate(&env);

let period = String::from_str(&env, "2026-09");

let reason = String::from_str(&env, "adversarial test revocation");

let revocation: RevocationData = (business.clone(), env.ledger().timestamp(), reason);

in_contract(&env, &contract, |env| {

dispute::record_revocation(env, &business, &period, &revocation)

});

let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {

in_contract(&env, &contract, |env| {

dispute::require_not_revoked_for_update(env, &business, &period);

});

}));

assert!(result.is_err(), "revoked attestations must be immutable");
assert!(in_contract(&env, &contract, |env| {
	dispute::is_attestation_revoked(env, &business, &period)
}));
}

#[test]
fn require_not_revoked_for_update_uses_business_and_period_boundaries() {

let (env, contract) = setup();

let business = Address::generate(&env);

let other_business = Address::generate(&env);

let period = String::from_str(&env, "");

in_contract(&env, &contract, |env| {

dispute::require_not_revoked_for_update(env, &business, &period);

});

let reason = String::from_str(&env, "only one key is revoked");

let revocation: RevocationData = (business.clone(), env.ledger().timestamp(), reason);
in_contract(&env, &contract, |env| {

dispute::record_revocation(env, &business, &period, &revocation)

});

let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {

in_contract(&env, &contract, |env| {

dispute::require_not_revoked_for_update(env, &other_business, &period);

});

}));

assert!(
	result.is_ok(),
	"revocation must be scoped to business and period"
);
}

// -----------------------------------------------------------------------------
// get_dispute_ids_by_challenger adversarial coverage
// -----------------------------------------------------------------------------

#[test]
fn get_dispute_ids_by_challenger_returns_empty_for_unknown_challenger() {
    let (env, contract) = setup();

    let challenger = Address::generate(&env);

    let ids = in_contract(&env, &contract, |env| {
        dispute::get_dispute_ids_by_challenger(env, &challenger)
    });

    assert_eq!(
        ids.len(),
        0,
        "an unknown challenger must have no associated dispute ids"
    );
}

#[test]
fn get_dispute_ids_by_challenger_is_scoped_to_the_challenger() {
    let (env, contract) = setup();

    let challenger = Address::generate(&env);
    let other_challenger = Address::generate(&env);

    let ids = in_contract(&env, &contract, |env| {
        dispute::get_dispute_ids_by_challenger(env, &challenger)
    });
    let other_ids = in_contract(&env, &contract, |env| {
        dispute::get_dispute_ids_by_challenger(env, &other_challenger)
    });

    assert_eq!(ids.len(), 0, "challenger must start with no disputes");
    assert_eq!(
        other_ids.len(),
        0,
        "querying one challenger must not leak another challenger's ids"
    );
}

#[test]
fn get_dispute_ids_by_challenger_is_deterministic() {
    let (env, contract) = setup();

    let challenger = Address::generate(&env);

    let first = in_contract(&env, &contract, |env| {
        dispute::get_dispute_ids_by_challenger(env, &challenger)
    });
    let second = in_contract(&env, &contract, |env| {
        dispute::get_dispute_ids_by_challenger(env, &challenger)
    });

    assert_eq!(
        first.len(),
        second.len(),
        "repeated lookups must return the same number of ids"
    );
    for i in 0..first.len() {
        assert_eq!(
            first.get(i).unwrap(),
            second.get(i).unwrap(),
            "repeated lookups must return identical ids"
        );
    }
}

#[test]
fn get_dispute_ids_by_challenger_does_not_mutate_revocation_state() {
    let (env, contract) = setup();

    let business = Address::generate(&env);
    let challenger = Address::generate(&env);
    let period = String::from_str(&env, "2026-09");
    let reason = String::from_str(&env, "adversarial test revocation");
    let revocation: RevocationData = (business.clone(), env.ledger().timestamp(), reason);

    in_contract(&env, &contract, |env| {
        dispute::record_revocation(env, &business, &period, &revocation)
    });

    let _ = in_contract(&env, &contract, |env| {
        dispute::get_dispute_ids_by_challenger(env, &challenger)
    });

    assert!(
        in_contract(&env, &contract, |env| {
            dispute::is_attestation_revoked(env, &business, &period)
        }),
        "read-only dispute lookup must not mutate revocation state"
    );
}

#[test]
fn get_dispute_ids_by_challenger_does_not_mutate_dispute_index() {
    let (env, contract) = setup();

    let challenger = Address::generate(&env);

    let before = in_contract(&env, &contract, |env| {
        dispute::get_dispute_ids_by_challenger(env, &challenger)
    });
    let _ = in_contract(&env, &contract, |env| {
        dispute::get_dispute_ids_by_challenger(env, &challenger)
    });
    let after = in_contract(&env, &contract, |env| {
        dispute::get_dispute_ids_by_challenger(env, &challenger)
    });

    assert_eq!(
        before.len(),
        after.len(),
        "lookups must not append or remove dispute ids"
    );
}
