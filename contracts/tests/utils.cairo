use starknet::{ContractAddress, Span, contract_address_const};
use snforge_std::signature::stark_curve::{KeyPair, StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use ibtc_cairo::utils::{AttestorMultisigTx, OffChainMessageHashAttestorMultisigTx};
use ibtc_cairo::ibtc_manager::IBTCManager;
use ibtc_cairo::ibtc_token::IBTCToken;
use ibtc_cairo::interface::{IBTCManagerABISafeDispatcher, IBTCManagerABISafeDispatcherTrait, IBTCTokenABISafeDispatcher, IBTCTokenABISafeDispatcherTrait, IBTCManagerABIDispatcher, IBTCManagerABIDispatcherTrait, IBTCTokenABIDispatcher, IBTCTokenABIDispatcherTrait};
use openzeppelin_testing as utils;
use snforge_std::{start_cheat_caller_address, start_cheat_transaction_version_global, test_address};
use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait, spy_events, EventSpyAssertionsTrait,
    EventSpyTrait, // Add for fetching events directly
    Event, // A structure describing a raw `Event`
};
use openzeppelin_testing::events::EventSpyExt;
use ibtc_cairo::event::{SetThreshold, CreateIBTCVault};
use core::poseidon::PoseidonTrait;
use core::hash::{HashStateTrait, HashStateExTrait};
use ibtc_cairo::ibtc_manager::{APPROVED_SIGNER};

// Constants
pub const VALUE_LOCKED: u256 = 100000000; // 1 BTC
pub const BTC_TX_ID: u256 = 0x1234567890;
pub const BTC_TX_ID2: u256 = 0x1234567891;
pub const BTC_FEE_RECIPIENT: felt252 = 0x000001;

pub fn mock_taproot_pubkey() -> ByteArray {
    let mut buffer = "";
    buffer.append_word(0x123456789012345678901234567890, 15);
    buffer.append_word(0x1234567890123456789012345678901234, 17);
    buffer
}

pub fn ibtc_admin() -> ContractAddress {
    contract_address_const::<0x456>()
}

pub fn default_admin() -> ContractAddress {
    contract_address_const::<0x123>()
}

pub fn whitelist_address() -> ContractAddress {
    contract_address_const::<0x111>()
}

// Helper function to setup contracts
pub fn setup_contracts() -> (IBTCManagerABISafeDispatcher, IBTCTokenABISafeDispatcher, IBTCManagerABIDispatcher, IBTCTokenABIDispatcher) {
    // Deploy IBTC
    let ibtc_token_calldata = array![];
    let ibtc_token_address = utils::declare_and_deploy("IBTCToken", ibtc_token_calldata);
    let ibtc_token_safe = IBTCTokenABISafeDispatcher { contract_address: ibtc_token_address };
    let ibtc_token = IBTCTokenABIDispatcher { contract_address: ibtc_token_address };
    let owner = default_admin();
    let ibtc_admin = ibtc_admin();

    // Deploy IBTCManager
    let ibtc_manager_calldata: Array<felt252> = array![
        owner.into(), // owner
        ibtc_admin.into(), // admin
        3, // threshold
        ibtc_token_address.into(), // ibtc address
        BTC_FEE_RECIPIENT // btc fee recipient
    ];
    let ibtc_manager_address = utils::declare_and_deploy("IBTCManager", ibtc_manager_calldata);
    let ibtc_manager_safe = IBTCManagerABISafeDispatcher { contract_address: ibtc_manager_address };
    let ibtc_manager = IBTCManagerABIDispatcher { contract_address: ibtc_manager_address };

    // Transfer IBTC ownership to IBTCManager
    ibtc_token.transfer_ownership(ibtc_manager_address);

    (ibtc_manager_safe, ibtc_token_safe, ibtc_manager, ibtc_token)
}

pub fn setup_account(public_key: felt252) -> ContractAddress {
    let mut calldata = array![public_key];
    utils::declare_and_deploy("SnakeAccountMock", calldata)
}

pub fn get_signatures(
    message: AttestorMultisigTx,
    attestors: Span<(ContractAddress, KeyPair<felt252, felt252>)>,
    number_of_signatures: u8
) -> Span<(ContractAddress, Array<felt252>)> {
    let mut signatures = array![];
    for i in 0..number_of_signatures {
        let (attestor, key_pair) = *attestors.at(i.into());
        let message_hash = message.get_message_hash(attestor);
        let (r, s) = key_pair.sign(message_hash).unwrap();
        signatures.append((attestor, array![r, s]));
    };
    // println!("signatures: {:?}", signatures);
    signatures.span()
}

pub fn setup_attestors_and_fund(
    ibtc_manager: IBTCManagerABIDispatcher, 
    uuid: felt252,
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
    let pending_signatures = get_signatures(AttestorMultisigTx {
        uuid,
        btc_tx_id: BTC_TX_ID,
        tx_type: 'set-status-pending',
        amount: 0
    }, attestors.span(), 3);

    // println!("pending_signatures: {:?}", pending_signatures);

    // Set status to pending
    start_cheat_caller_address(ibtc_manager.contract_address, attestor1);
    ibtc_manager.set_status_pending(
        uuid, BTC_TX_ID, pending_signatures, mock_taproot_pubkey(), 0
    );

    // Generate signatures for funded status
    let funded_signatures = get_signatures(AttestorMultisigTx {
        uuid,
        btc_tx_id: BTC_TX_ID,
        tx_type: 'set-status-funded',
        amount
    }, attestors.span(), 3);

    // Set status to funded
    ibtc_manager.set_status_funded(uuid, BTC_TX_ID, funded_signatures, amount);
}