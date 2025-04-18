use starknet::{ContractAddress, contract_address_const};
use ibtc_cairo::ibtc_manager::IBTCManager;
use ibtc_cairo::ibtc_token::IBTCToken;
use ibtc_cairo::interface::{IBTCManagerABISafeDispatcher, IBTCManagerABISafeDispatcherTrait, IBTCTokenABISafeDispatcher, IBTCTokenABISafeDispatcherTrait, IBTCManagerABIDispatcher, IBTCManagerABIDispatcherTrait, IBTCTokenABIDispatcher, IBTCTokenABIDispatcherTrait};
use openzeppelin_testing as utils;
use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address, start_cheat_transaction_version_global, test_address};
use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait, spy_events, EventSpyAssertionsTrait,
    EventSpyTrait, // Add for fetching events directly
    Event, // A structure describing a raw `Event`
};
use openzeppelin_testing::events::EventSpyExt;
use ibtc_cairo::event::{
    SetThreshold, CreateIBTCVault, SetStatusFunded
};
use core::poseidon::PoseidonTrait;
use core::hash::{HashStateTrait, HashStateExTrait};
use crate::utils::{get_signatures_from_request, get_signatures_from_messages, get_ssf_messages, get_ssp_messages, AttestorMultisigTx};
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use ibtc_cairo::ibtc_manager::{APPROVED_SIGNER};
use starknet::get_caller_address;

// Constants
const VALUE_LOCKED: u256 = 100000000; // 1 BTC
const BTC_TX_ID: u256 = 0x5e9e65610afeda9960f5f0396963fc5fc20db10d33a0ba29051cd2759d39c88;
const BTC_TX_ID2: u256 = 0x5e9e65610afeda9960f5f0396963fc5fc20db10d33a0ba29051cd2759d39c87;

fn btc_fee_recipient() -> ByteArray {
    "bcrt1qvgkz8m4m73kly4xhm28pcnv46n6u045lfq9ta3"
}

fn mock_taproot_pubkey() -> ByteArray {
    let mut buffer = "";
    buffer.append_word(0x123456789012345678901234567890, 15);
    buffer.append_word(0x1234567890123456789012345678901234, 17);
    buffer
}


fn ibtc_admin() -> ContractAddress {
    contract_address_const::<0x456>()
}

fn default_admin() -> ContractAddress {
    contract_address_const::<0x123>()
}

fn whitelist_address() -> ContractAddress {
    contract_address_const::<0x111>()
}



// Helper function to setup contracts
fn setup_contracts() -> (IBTCManagerABISafeDispatcher, IBTCTokenABISafeDispatcher, IBTCManagerABIDispatcher, IBTCTokenABIDispatcher) {
    // Deploy IBTC
    let owner = default_admin();
    let ibtc_admin = ibtc_admin();

    let ibtc_token_calldata: Array<felt252> = array![owner.into()];
    let ibtc_token_address = utils::declare_and_deploy("IBTCToken", ibtc_token_calldata);
    let ibtc_token_safe = IBTCTokenABISafeDispatcher { contract_address: ibtc_token_address };
    let ibtc_token = IBTCTokenABIDispatcher { contract_address: ibtc_token_address };
    let mut calldata: Array<felt252> = array![
        owner.into(),
        ibtc_admin.into(),
        3.into(),
        ibtc_token_address.into(),
        1, 
        0x626372743171766762387a346d346d37336b6c7934786d32387063767334, 
        0x366e3675303435496671397461, 
        11,
        1
    ];
    

    let ibtc_manager_address = utils::declare_and_deploy("IBTCManager", calldata);
    let ibtc_manager_safe = IBTCManagerABISafeDispatcher { contract_address: ibtc_manager_address };
    let ibtc_manager = IBTCManagerABIDispatcher { contract_address: ibtc_manager_address };

    // Transfer IBTC ownership to IBTCManager
    start_cheat_caller_address(ibtc_token.contract_address, owner);
    // ibtc_token.set_minter(ibtc_manager.contract_address);
    // ibtc_token.set_burner(ibtc_manager.contract_address);
    ibtc_token.transfer_ownership(ibtc_manager.contract_address);

    // Cleanup
    stop_cheat_caller_address(ibtc_token.contract_address);
    stop_cheat_caller_address(ibtc_manager.contract_address);

    (ibtc_manager_safe, ibtc_token_safe, ibtc_manager, ibtc_token)
}

fn setup_account(public_key: felt252) -> ContractAddress {
    let mut calldata = array![public_key];
    utils::declare_and_deploy("SnakeAccountMock", calldata)
}

#[test]
fn test_contracts_are_deployed_correctly() {
    let (_, _, ibtc_manager, ibtc_token) = setup_contracts();
    
    // Check IBTCManager is deployed
    assert!(ibtc_manager.contract_address != contract_address_const::<0>(), "IBTCManager not deployed");
    
    // Check IBTCManager owns IBTC
    assert!(ibtc_token.owner() == ibtc_manager.contract_address, "Wrong IBTC owner");
}

#[test]
fn test_contract_is_pausable() {
    let (ibtc_manager_safe, _, ibtc_manager, _) = setup_contracts();

    start_cheat_caller_address(ibtc_manager_safe.contract_address, ibtc_admin());
    
    // Pause contract
    ibtc_manager.pause_contract();

    // Whitelist address
    ibtc_manager.whitelist_address(whitelist_address());

    // let mut spy = spy_events();
    
    // Try to setup vault while paused
    start_cheat_caller_address(ibtc_manager_safe.contract_address, whitelist_address());
    assert!(ibtc_manager_safe.setup_vault().is_err(), "paused");

    // Unpause and try again
    start_cheat_caller_address(ibtc_manager_safe.contract_address, ibtc_admin());
    ibtc_manager.unpause_contract();

    start_cheat_caller_address(ibtc_manager_safe.contract_address, whitelist_address());
    ibtc_manager.setup_vault();
}

#[test]
fn test_set_minimum_deposit() {
    let (ibtc_manager_safe, _, ibtc_manager, _) = setup_contracts();
    let random_account = contract_address_const::<0x999>();
    
    // Try with unauthorized account
    start_cheat_caller_address(ibtc_manager_safe.contract_address, random_account);
    let result = ibtc_manager_safe.set_minimum_deposit(1000);
    assert!(result.is_err(), "Not ibtc admin");
    
    // Try with authorized account
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.set_minimum_deposit(1000);
    assert!(ibtc_manager.get_minimum_deposit() == 1000, "Wrong minimum deposit");
}

#[test]
fn test_set_maximum_deposit() {
    let (ibtc_manager_safe, _, ibtc_manager, _) = setup_contracts();
    let random_account = contract_address_const::<0x999>();
    
    // Try with unauthorized account
    start_cheat_caller_address(ibtc_manager_safe.contract_address, random_account);
    let result = ibtc_manager_safe.set_maximum_deposit(1000);
    assert!(result.is_err(), "Not ibtc admin");
    
    // Try with authorized account
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.set_maximum_deposit(1000);
    assert!(ibtc_manager.get_maximum_deposit() == 1000, "Wrong maximum deposit");
}

#[test]
fn test_set_threshold() {
    let (ibtc_manager_safe, _, ibtc_manager, _) = setup_contracts();
    let user = contract_address_const::<0x1>();
    
    // Try with unauthorized account
    start_cheat_caller_address(ibtc_manager_safe.contract_address, user);
    let result = ibtc_manager_safe.set_threshold(4);
    assert!(result.is_err(), "Not ibtc admin");

    // Try setting threshold too low
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    let result = ibtc_manager_safe.set_threshold(0);
    assert!(result.is_err(), "Threshold too low");

    // Set valid threshold
    let mut spy = spy_events();
    ibtc_manager.set_threshold(4);
    
    // Check event was emitted
    let expected_event = IBTCManager::Event::SetThreshold(
        SetThreshold {new_threshold: 4}
    );
    spy.assert_emitted_single(ibtc_manager.contract_address, expected_event);

    // Verify threshold was updated
    assert!(ibtc_manager.get_threshold() == 4, "Wrong threshold");
}

#[test]
fn test_revoke_approved_signer() {
    let (ibtc_manager_safe, _, ibtc_manager, _) = setup_contracts();
    let attestor1 = contract_address_const::<0x1>();
    let attestor2 = contract_address_const::<0x2>();
    let user = contract_address_const::<0x3>();

    // Try revoking with unauthorized account
    start_cheat_caller_address(ibtc_manager_safe.contract_address, user);
    let result = ibtc_manager_safe.revoke_role(APPROVED_SIGNER, attestor1);
    assert!(result.is_err(), "Caller is missing role");

    // Try revoking when it would decrease below threshold
    // Setup initial signers
    start_cheat_caller_address(ibtc_manager.contract_address, default_admin());
    ibtc_manager.grant_role(APPROVED_SIGNER, attestor1);
    ibtc_manager.grant_role(APPROVED_SIGNER, attestor2);

    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    let result = ibtc_manager_safe.revoke_role(APPROVED_SIGNER, attestor1);
    assert!(result.is_err(), "Threshold minimum reached");

    // Test non-renounceability
    start_cheat_caller_address(ibtc_manager.contract_address, attestor1);
    let initial_signer_count = ibtc_manager.get_signer_count();
    assert!(initial_signer_count == 2, "Wrong initial signer count");

    let result = ibtc_manager_safe.renounce_role(APPROVED_SIGNER, attestor1);
    assert!(result.is_err(), "No signer renouncement");

    // Verify signer still has role
    assert!(ibtc_manager.has_role(APPROVED_SIGNER, attestor1), "Role should not be removed");
    
    // Verify count hasn't changed
    assert!(ibtc_manager.get_signer_count() == initial_signer_count, "Signer count should not change");
}

#[test]
fn test_tss_commitment() {
    let (_, _, ibtc_manager, _) = setup_contracts();
    
    // Create and hash identifier
    let secret_identifier: felt252 = 0x1234567890abcdef1234567890abcdef;
    let hashed_identifier = PoseidonTrait::new().update_with(secret_identifier).finalize();

    // Set commitment
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.set_tss_commitment(hashed_identifier);

    // Verify commitment was set
    assert!(ibtc_manager.get_tss_commitment() == hashed_identifier, "Wrong TSS commitment");
}

#[test]
fn test_setup_vault() {
    let (ibtc_manager_safe, _, ibtc_manager, _) = setup_contracts();
    let user = contract_address_const::<0x1>();
    
    // Try without being whitelisted
    start_cheat_caller_address(ibtc_manager_safe.contract_address, user);
    let result = ibtc_manager_safe.setup_vault();
    assert!(result.is_err(), "Not Whitelisted");

    // Whitelist and try again
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.whitelist_address(user);
    start_cheat_caller_address(ibtc_manager_safe.contract_address, user);
    let mut spy = spy_events();
    ibtc_manager.setup_vault();
    // Check event was emitted
    let (_, event) = spy.get_events().events.at(1);
    let uuid_low = event.data.at(0);
    let uuid_high = event.data.at(1);
    let uuid = u256 { low: (*uuid_low).try_into().unwrap(), high: (*uuid_high).try_into().unwrap() };
    let timestamp = ibtc_manager.get_vault(uuid).timestamp;
    let expected_event = IBTCManager::Event::CreateIBTCVault(
        CreateIBTCVault {
            uuid: uuid,
            creator: user,
            timestamp
        }
    );
    spy.assert_emitted_single(ibtc_manager.contract_address, expected_event);
}

#[test]
fn test_multiple_vault_setup() {
    let (_, _, ibtc_manager, _) = setup_contracts();
    let user = contract_address_const::<0x1>();
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.whitelist_address(user);
    start_cheat_caller_address(ibtc_manager.contract_address, user);

    // Create first vault
    let mut spy1 = spy_events();
    ibtc_manager.setup_vault();
    let (_, event1) = spy1.get_events().events.at(1);
    let uuid_low1 = event1.data.at(0);
    let uuid_high1 = event1.data.at(1);
    let uuid1 = u256 { low: (*uuid_low1).try_into().unwrap(), high: (*uuid_high1).try_into().unwrap() };
    let timestamp1 = ibtc_manager.get_vault(uuid1).timestamp;
    let expected_event1 = IBTCManager::Event::CreateIBTCVault(
        CreateIBTCVault {
            uuid: uuid1,
            creator: user,
            timestamp: timestamp1
        }
    );
    spy1.assert_emitted_single(ibtc_manager.contract_address, expected_event1);

    // Create second vault
    let mut spy2 = spy_events();
    ibtc_manager.setup_vault();
    let (_, event2) = spy2.get_events().events.at(1);
    let uuid_low2 = event2.data.at(0);
    let uuid_high2 = event2.data.at(1);
    let uuid2 = u256 { low: (*uuid_low2).try_into().unwrap(), high: (*uuid_high2).try_into().unwrap() };
    let timestamp2 = ibtc_manager.get_vault(uuid2).timestamp;
    let expected_event2 = IBTCManager::Event::CreateIBTCVault(
        CreateIBTCVault {
            uuid: uuid2,
            creator: user,
            timestamp: timestamp2
        }
    );
    spy2.assert_emitted_single(ibtc_manager.contract_address, expected_event2);

    // Verify UUIDs are different
    assert!(uuid1 != uuid2, "UUIDs should be unique");
}

fn setup_attestors_and_fund(
    ibtc_manager: IBTCManagerABIDispatcher, 
    uuid: u256,
    amount: u256
) {
    // Setup attestors
    let key_pair_attestor1 = StarkCurveKeyPairImpl::generate();
    let attestor1 = setup_account(key_pair_attestor1.public_key);

    let key_pair_attestor2 = StarkCurveKeyPairImpl::generate();
    let attestor2 = setup_account(key_pair_attestor2.public_key);

    let key_pair_attestor3 = StarkCurveKeyPairImpl::generate();
    let attestor3 = setup_account(key_pair_attestor3.public_key);

    let attestors = array![
        (attestor1, key_pair_attestor1),
        (attestor2, key_pair_attestor2),
        (attestor3, key_pair_attestor3)
    ];
    
    start_cheat_caller_address(ibtc_manager.contract_address, default_admin());
    for (attestor, _) in attestors.span() {
        ibtc_manager.grant_role(APPROVED_SIGNER, *attestor);
    };

    // Generate signatures for pending status
    let pending_signatures = get_signatures_from_messages(get_ssp_messages(ibtc_manager, uuid, BTC_TX_ID, 0, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    // Set status to pending
    start_cheat_caller_address(ibtc_manager.contract_address, attestor1);
    ibtc_manager.set_status_pending(
        uuid, BTC_TX_ID, mock_taproot_pubkey(), 0, pending_signatures
    );

    // Generate signatures for funded status
    let funded_signatures = get_signatures_from_messages(get_ssf_messages(ibtc_manager, uuid, BTC_TX_ID, amount, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    // Set status to funded
    ibtc_manager.set_status_funded(uuid, BTC_TX_ID, amount, funded_signatures);
}

#[test]
fn test_get_ibtc_vault() {
    let (ibtc_manager_safe, _, ibtc_manager, _) = setup_contracts();
    let user = contract_address_const::<0x1>();

    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.whitelist_address(user);
    
    // Setup vault
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    let mut spy = spy_events();
    ibtc_manager.setup_vault();
    let (_, event) = spy.get_events().events.at(1);
    let uuid_low = event.data.at(0);
    let uuid_high = event.data.at(1);
    let uuid_low_int = (*uuid_low).try_into().unwrap();
    let uuid_high_int = (*uuid_high).try_into().unwrap();
    let uuid = u256 { low: uuid_low_int, high: uuid_high_int };
    
    // Try getting non-existent IBTCVault
    let wrong_uuid_low = 91044518406403680085907560571636167243;
    let wrong_uuid_high = 8805326864190065380747486608483342166;
    let wrong_uuid = u256 { low: wrong_uuid_low.try_into().unwrap(), high: wrong_uuid_high.try_into().unwrap() };
    let result = ibtc_manager_safe.get_vault(wrong_uuid);
    assert!(result.is_err(), "Vault not found");

    // Setup attestors and set status to funded
    setup_attestors_and_fund(ibtc_manager, uuid, VALUE_LOCKED);

    // Get IBTCVault and verify data
    let vault = ibtc_manager.get_vault(uuid);
    assert!(vault.creator == user, "Wrong creator");
    assert!(vault.value_locked == VALUE_LOCKED, "Wrong value locked");
}

#[test]
fn test_get_vault_by_index() {
    let (_, _, ibtc_manager, _) = setup_contracts();
    let user = contract_address_const::<0x1>();

    // Try getting non-existent vault by index
    let result = ibtc_manager.get_ibtc_vault_by_index(5);
    assert!(result.creator == contract_address_const::<0>(), "Should return uuid 0 for non-existent index");
    assert!(result.uuid == 0, "Should return uuid 0 for non-existent index");

    // Setup vault and fund it
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.whitelist_address(user);
    
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    let mut spy = spy_events();
    ibtc_manager.setup_vault();
    let (_, event) = spy.get_events().events.at(1);
    let uuid_low = event.data.at(0);
    let uuid_high = event.data.at(1);
    let uuid = u256 { low: (*uuid_low).try_into().unwrap(), high: (*uuid_high).try_into().unwrap() };

    // Setup attestors and set status to funded
    setup_attestors_and_fund(ibtc_manager, uuid, VALUE_LOCKED);

    // Get vault by index and verify data
    let vault = ibtc_manager.get_ibtc_vault_by_index(0);
    assert!(vault.creator == user, "Wrong creator");
    assert!(vault.value_locked == VALUE_LOCKED, "Wrong value locked");
}

#[test]
fn test_set_status_funded_validations() {
    let (ibtc_manager_safe, _, ibtc_manager, _) = setup_contracts();
    let user = contract_address_const::<0x1>();

    // Setup initial vault
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.whitelist_address(user);
    
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    let mut spy = spy_events();
    ibtc_manager.setup_vault();
    let (_, event) = spy.get_events().events.at(1);
    let uuid_low = event.data.at(0);
    let uuid_high = event.data.at(1);
    let uuid_low_int = (*uuid_low).try_into().unwrap();
    let uuid_high_int = (*uuid_high).try_into().unwrap();
    let uuid = u256 { low: uuid_low_int, high: uuid_high_int };

    // Setup attestors
    let key_pair_attestor1 = StarkCurveKeyPairImpl::generate();
    let attestor1 = setup_account(key_pair_attestor1.public_key);

    let key_pair_attestor2 = StarkCurveKeyPairImpl::generate();
    let attestor2 = setup_account(key_pair_attestor2.public_key);

    let key_pair_attestor3 = StarkCurveKeyPairImpl::generate();
    let attestor3 = setup_account(key_pair_attestor3.public_key);

    let attestors = array![
        (attestor1, key_pair_attestor1),
        (attestor2, key_pair_attestor2),
        (attestor3, key_pair_attestor3)
    ];
    
    start_cheat_caller_address(ibtc_manager.contract_address, default_admin());
    for (attestor, _) in attestors.span() {
        ibtc_manager.grant_role(APPROVED_SIGNER, *attestor);
    };

    // Set status to pending first
    let pending_signatures = get_signatures_from_messages(get_ssp_messages(ibtc_manager, uuid, BTC_TX_ID, 0, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    start_cheat_caller_address(ibtc_manager.contract_address, attestor1);
    ibtc_manager.set_status_pending(
        uuid, BTC_TX_ID, mock_taproot_pubkey(), 0, pending_signatures
    );

    // Test with not enough signatures
    let insufficient_signatures = get_signatures_from_messages(get_ssf_messages(ibtc_manager, uuid, BTC_TX_ID, VALUE_LOCKED, array![attestor1, attestor2, attestor3]), attestors.span(), 1);

    let result = ibtc_manager_safe.set_status_funded(uuid, BTC_TX_ID, VALUE_LOCKED, insufficient_signatures);
    assert!(result.is_err(), "Should fail with insufficient signatures");

    // Test with wrong function signature
    let wrong_function_signatures = get_signatures_from_request(AttestorMultisigTx {
        uuid: uuid,
        btc_tx_id: BTC_TX_ID,
        tx_type: 'post-close-dlc',
        amount: VALUE_LOCKED
    }, attestors.span(), 3);
    let result = ibtc_manager_safe.set_status_funded(uuid, BTC_TX_ID, VALUE_LOCKED, wrong_function_signatures);
    assert!(result.is_err(), "Should fail with wrong function signature");

    // Test with wrong UUID
    let wrong_uuid_low = 91044518406403680085907560571636167243;
    let wrong_uuid_high = 8805426864190065380747486608483342165;
    let wrong_uuid = u256 { low: wrong_uuid_low.try_into().unwrap(), high: wrong_uuid_high.try_into().unwrap() };
    let wrong_uuid_signatures = get_signatures_from_messages(get_ssf_messages(ibtc_manager, wrong_uuid, BTC_TX_ID, VALUE_LOCKED, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    let result = ibtc_manager_safe.set_status_funded(uuid, BTC_TX_ID, VALUE_LOCKED, wrong_uuid_signatures);
    assert!(result.is_err(), "Should fail with wrong UUID");

    // Test with wrong BTC tx ID
    let wrong_btc_tx_signatures = get_signatures_from_messages(get_ssf_messages(ibtc_manager, uuid, BTC_TX_ID2, VALUE_LOCKED, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    let result = ibtc_manager_safe.set_status_funded(uuid, BTC_TX_ID, VALUE_LOCKED, wrong_btc_tx_signatures);
    assert!(result.is_err(), "Should fail with wrong BTC tx ID");

    // Test successful funding
    let valid_signatures = get_signatures_from_messages(get_ssf_messages(ibtc_manager, uuid, BTC_TX_ID, VALUE_LOCKED, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    let mut spy = spy_events();
    ibtc_manager.set_status_funded(uuid, BTC_TX_ID, VALUE_LOCKED, valid_signatures);

    // Verify event was emitted
    let expected_event = IBTCManager::Event::SetStatusFunded(
        SetStatusFunded {
            uuid: uuid,
            btc_tx_id: BTC_TX_ID,
            creator: user,
            new_value_locked: VALUE_LOCKED,
            amount_to_mint: VALUE_LOCKED
        }
    );
    spy.assert_emitted_single(ibtc_manager.contract_address, expected_event);
}

#[test]
fn test_set_status_funded_duplicate_signers() {
    let (ibtc_manager_safe, _, ibtc_manager, _) = setup_contracts();
    let user = contract_address_const::<0x1>();

    // Setup initial vault
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.whitelist_address(user);
    
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    let mut spy = spy_events();
    ibtc_manager.setup_vault();
    let (_, event) = spy.get_events().events.at(1);
    let uuid_low = event.data.at(0);
    let uuid_high = event.data.at(1);
    let uuid = u256 { low: (*uuid_low).try_into().unwrap(), high: (*uuid_high).try_into().unwrap() };

    // Setup attestors
    let key_pair_attestor1 = StarkCurveKeyPairImpl::generate();
    let attestor1 = setup_account(key_pair_attestor1.public_key);

    let attestors = array![
        (attestor1, key_pair_attestor1),
        (attestor1, key_pair_attestor1), // Duplicate attestor
        (attestor1, key_pair_attestor1)  // Duplicate attestor
    ];
    
    start_cheat_caller_address(ibtc_manager.contract_address, default_admin());
    ibtc_manager.grant_role(APPROVED_SIGNER, attestor1);

    // Set status to pending first with duplicate signatures
    let pending_signatures = get_signatures_from_messages(get_ssp_messages(ibtc_manager, uuid, BTC_TX_ID, 0, array![attestor1, attestor1, attestor1]), attestors.span(), 3);

    start_cheat_caller_address(ibtc_manager.contract_address, attestor1);
    let result = ibtc_manager_safe.set_status_pending(
        uuid, BTC_TX_ID, mock_taproot_pubkey(), 0, pending_signatures
    );
    assert!(result.is_err(), "Should fail with duplicate signers");

    // Try to set funded status with duplicate signatures
    let duplicate_signatures = get_signatures_from_messages(get_ssf_messages(ibtc_manager, uuid, BTC_TX_ID, VALUE_LOCKED, array![attestor1, attestor1, attestor1]), attestors.span(), 3);

    let result = ibtc_manager_safe.set_status_funded(uuid, BTC_TX_ID, VALUE_LOCKED, duplicate_signatures);
    assert!(result.is_err(), "Should fail with duplicate signers");
}

// ADD MORE TEST CASE HERE

#[test]
fn test_withdraw_half_locked_tokens() {
    let (_, _, ibtc_manager, ibtc_token) = setup_contracts();
    let user = contract_address_const::<0x1>();
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.whitelist_address(user);
    
    // Setup vault and fund it
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    let mut spy = spy_events();
    ibtc_manager.setup_vault();
    let (_, event) = spy.get_events().events.at(1);
    let uuid_low = event.data.at(0);
    let uuid_high = event.data.at(1);
    let uuid = u256 { low: (*uuid_low).try_into().unwrap(), high: (*uuid_high).try_into().unwrap() };

    setup_attestors_and_fund(ibtc_manager, uuid, VALUE_LOCKED);

    // Withdraw half the tokens
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    ibtc_manager.withdraw(uuid, VALUE_LOCKED / 2);

    // Check IBTCVault state
    let vault = ibtc_manager.get_vault(uuid);
    assert!(ibtc_token.balance_of(user) == VALUE_LOCKED / 2, "Wrong balance after withdraw");
    assert!(vault.value_minted == VALUE_LOCKED / 2, "Wrong value minted");
    assert!(vault.value_locked == VALUE_LOCKED, "Value locked should not change yet");
}

#[test]
fn test_withdraw_and_redeem_bitcoin() {
    let (_, _, ibtc_manager, ibtc_token) = setup_contracts();
    let user = contract_address_const::<0x1>();

    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.whitelist_address(user);
    
    // Setup vault and fund it
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    let mut spy = spy_events();
    ibtc_manager.setup_vault();
    let (_, event) = spy.get_events().events.at(1);
    let uuid_low = event.data.at(0);
    let uuid_high = event.data.at(1);
    let uuid = u256 { low: (*uuid_low).try_into().unwrap(), high: (*uuid_high).try_into().unwrap() };

    setup_attestors_and_fund(ibtc_manager, uuid, VALUE_LOCKED);

    // Withdraw half the tokens
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    ibtc_manager.withdraw(uuid, VALUE_LOCKED / 2);

    // Setup attestors and set new pending status for redemption
    let key_pair_attestor1 = StarkCurveKeyPairImpl::generate();
    let attestor1 = setup_account(key_pair_attestor1.public_key);

    let key_pair_attestor2 = StarkCurveKeyPairImpl::generate();
    let attestor2 = setup_account(key_pair_attestor2.public_key);

    let key_pair_attestor3 = StarkCurveKeyPairImpl::generate();
    let attestor3 = setup_account(key_pair_attestor3.public_key);

    let attestors = array![
        (attestor1, key_pair_attestor1),
        (attestor2, key_pair_attestor2),
        (attestor3, key_pair_attestor3)
    ];

    start_cheat_caller_address(ibtc_manager.contract_address, default_admin());
    for (attestor, _) in attestors.span() {
        ibtc_manager.grant_role(APPROVED_SIGNER, *attestor);
    };

    let pending_signatures = get_signatures_from_messages(get_ssp_messages(ibtc_manager, uuid, BTC_TX_ID, 0, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    start_cheat_caller_address(ibtc_manager.contract_address, attestor1);
    ibtc_manager.set_status_pending(
        uuid, BTC_TX_ID, mock_taproot_pubkey(), 0, pending_signatures
    );

    // Set new funded status with half the original amount
    let funded_signatures = get_signatures_from_messages(get_ssf_messages(ibtc_manager, uuid, BTC_TX_ID, VALUE_LOCKED / 2, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    ibtc_manager.set_status_funded(uuid, BTC_TX_ID, VALUE_LOCKED / 2, funded_signatures);

    // Check final state
    let vault = ibtc_manager.get_vault(uuid);
    assert!(ibtc_token.balance_of(user) == VALUE_LOCKED / 2, "Wrong final balance");
    assert!(vault.value_locked == VALUE_LOCKED / 2, "Wrong final locked value");
    assert!(vault.value_minted == VALUE_LOCKED / 2, "Wrong final minted value");
}

#[test]
fn test_withdraw_redeem_too_much_bitcoin() {
    let (ibtc_manager_safe, _, ibtc_manager, _) = setup_contracts();
    let user = contract_address_const::<0x1>();

    // Setup initial vault
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.whitelist_address(user);
    
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    let mut spy = spy_events();
    ibtc_manager.setup_vault();
    let (_, event) = spy.get_events().events.at(1);
    let uuid_low = event.data.at(0);
    let uuid_high = event.data.at(1);
    let uuid = u256 { low: (*uuid_low).try_into().unwrap(), high: (*uuid_high).try_into().unwrap() };

    // Fund the vault
    setup_attestors_and_fund(ibtc_manager, uuid, VALUE_LOCKED);

    // Withdraw half
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    ibtc_manager.withdraw(uuid, VALUE_LOCKED / 2);

    // Setup attestors for redemption
    let key_pair_attestor1 = StarkCurveKeyPairImpl::generate();
    let attestor1 = setup_account(key_pair_attestor1.public_key);

    let key_pair_attestor2 = StarkCurveKeyPairImpl::generate();
    let attestor2 = setup_account(key_pair_attestor2.public_key);

    let key_pair_attestor3 = StarkCurveKeyPairImpl::generate();
    let attestor3 = setup_account(key_pair_attestor3.public_key);

    let attestors = array![
        (attestor1, key_pair_attestor1),
        (attestor2, key_pair_attestor2),
        (attestor3, key_pair_attestor3)
    ];

    start_cheat_caller_address(ibtc_manager.contract_address, default_admin());
    for (attestor, _) in attestors.span() {
        ibtc_manager.grant_role(APPROVED_SIGNER, *attestor);
    };

    // Try to redeem more than withdrawn
    let pending_signatures = get_signatures_from_messages(get_ssp_messages(ibtc_manager, uuid, BTC_TX_ID2, 0, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    start_cheat_caller_address(ibtc_manager.contract_address, attestor1);
    ibtc_manager.set_status_pending(
        uuid, BTC_TX_ID2, mock_taproot_pubkey(), 0, pending_signatures
    );

    // Try to set funded with less than required - this should panic
    let funded_signatures = get_signatures_from_messages(get_ssf_messages(ibtc_manager, uuid, BTC_TX_ID2, VALUE_LOCKED / 2 - 1, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    // This call should panic with 'Under collateralized'
    let result = ibtc_manager_safe.set_status_funded(uuid, BTC_TX_ID2, VALUE_LOCKED / 2 - 1, funded_signatures);
    match result {
        Result::Err(error) => {
            assert!(*error.at(0) == IBTCManager::Errors::UNDER_COLLATERALIZED, "Should fail with under collateralized error");
        },
        _ => {
            panic!("Unexpected result");
        }
    }
}

#[test]
fn test_deposit_more_bitcoin() {
    let (_, _, ibtc_manager, ibtc_token) = setup_contracts();
    let user = contract_address_const::<0x1>();
    
    // Setup initial vault
    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.whitelist_address(user);
    
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    let mut spy = spy_events();
    ibtc_manager.setup_vault();
    let (_, event) = spy.get_events().events.at(1);
    let uuid_low = event.data.at(0);
    let uuid_high = event.data.at(1);
    let uuid = u256 { low: (*uuid_low).try_into().unwrap(), high: (*uuid_high).try_into().unwrap() };

    // Fund initial amount
    setup_attestors_and_fund(ibtc_manager, uuid, VALUE_LOCKED);

    // Add more bitcoin
    let new_amount: u256 = VALUE_LOCKED + VALUE_LOCKED / 2;
    
    // Setup attestors for additional deposit
    let key_pair_attestor1 = StarkCurveKeyPairImpl::generate();
    let attestor1 = setup_account(key_pair_attestor1.public_key);

    let key_pair_attestor2 = StarkCurveKeyPairImpl::generate();
    let attestor2 = setup_account(key_pair_attestor2.public_key);

    let key_pair_attestor3 = StarkCurveKeyPairImpl::generate();
    let attestor3 = setup_account(key_pair_attestor3.public_key);

    let attestors = array![
        (attestor1, key_pair_attestor1),
        (attestor2, key_pair_attestor2),
        (attestor3, key_pair_attestor3)
    ];

    start_cheat_caller_address(ibtc_manager.contract_address, default_admin());
    for (attestor, _) in attestors.span() {
        ibtc_manager.grant_role(APPROVED_SIGNER, *attestor);
    };

    let pending_signatures = get_signatures_from_messages(get_ssp_messages(ibtc_manager, uuid, BTC_TX_ID2, 0, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    start_cheat_caller_address(ibtc_manager.contract_address, attestor1);
    ibtc_manager.set_status_pending(
        uuid, BTC_TX_ID2, mock_taproot_pubkey(), 0, pending_signatures
    );

    let funded_signatures = get_signatures_from_messages(get_ssf_messages(ibtc_manager, uuid, BTC_TX_ID2, new_amount, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    ibtc_manager.set_status_funded(uuid, BTC_TX_ID2, new_amount, funded_signatures);

    // Check final state
    let vault = ibtc_manager.get_vault(uuid);
    assert!(ibtc_token.balance_of(user) == new_amount, "Wrong balance after deposit");
    assert!(vault.value_locked == new_amount, "Wrong locked value");
    assert!(vault.value_minted == new_amount, "Wrong minted value");
}

#[test]
fn test_deposit_too_much_bitcoin() {
    let (ibtc_manager_safe, _, ibtc_manager, _) = setup_contracts();
    let user = contract_address_const::<0x1>();

    start_cheat_caller_address(ibtc_manager.contract_address, ibtc_admin());
    ibtc_manager.whitelist_address(user);
    
    // Setup initial vault
    start_cheat_caller_address(ibtc_manager.contract_address, user);
    let mut spy = spy_events();
    ibtc_manager.setup_vault();
    let (_, event) = spy.get_events().events.at(1);
    let uuid_low = event.data.at(0);
    let uuid_high = event.data.at(1);
    let uuid = u256 { low: (*uuid_low).try_into().unwrap(), high: (*uuid_high).try_into().unwrap() };
    setup_attestors_and_fund(ibtc_manager, uuid, VALUE_LOCKED);

    // Try to deposit too much
    let too_much = VALUE_LOCKED * 100;

    // Setup attestors for additional deposit
    let key_pair_attestor1 = StarkCurveKeyPairImpl::generate();
    let attestor1 = setup_account(key_pair_attestor1.public_key);

    let key_pair_attestor2 = StarkCurveKeyPairImpl::generate();
    let attestor2 = setup_account(key_pair_attestor2.public_key);

    let key_pair_attestor3 = StarkCurveKeyPairImpl::generate();
    let attestor3 = setup_account(key_pair_attestor3.public_key);

    let attestors = array![
        (attestor1, key_pair_attestor1),
        (attestor2, key_pair_attestor2),
        (attestor3, key_pair_attestor3)
    ];

    start_cheat_caller_address(ibtc_manager.contract_address, default_admin());
    for (attestor, _) in attestors.span() {
        ibtc_manager.grant_role(APPROVED_SIGNER, *attestor);
    };

    let pending_signatures = get_signatures_from_messages(get_ssp_messages(ibtc_manager, uuid, BTC_TX_ID2, 0, array![attestor1, attestor2, attestor3]), attestors.span(), 3);


    start_cheat_caller_address(ibtc_manager.contract_address, attestor1);
    ibtc_manager.set_status_pending(
        uuid, BTC_TX_ID2, mock_taproot_pubkey(), 0, pending_signatures
    );

    let funded_signatures = get_signatures_from_messages(get_ssf_messages(ibtc_manager, uuid, BTC_TX_ID2, too_much, array![attestor1, attestor2, attestor3]), attestors.span(), 3);

    let result = ibtc_manager_safe.set_status_funded(uuid, BTC_TX_ID2, too_much, funded_signatures);
    match result {
        Result::Err(error) => {
            assert!(*error.at(0) == IBTCManager::Errors::DEPOSIT_TOO_LARGE, "Deposit too large should fail");
        },
        _ => {
            panic!("Unexpected result");
        }
    }
}
