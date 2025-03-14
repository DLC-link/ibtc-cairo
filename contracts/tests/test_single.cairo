use starknet::{ContractAddress, contract_address_const};
use ibtc_cairo::ibtc_manager::IBTCManager;
use ibtc_cairo::ibtc_token::IBTCToken;
use ibtc_cairo::interface::{
    IBTCManagerABISafeDispatcher, IBTCManagerABISafeDispatcherTrait, 
    IBTCTokenABISafeDispatcher, IBTCTokenABISafeDispatcherTrait, 
    IBTCManagerABIDispatcher, IBTCManagerABIDispatcherTrait, 
    IBTCTokenABIDispatcher, IBTCTokenABIDispatcherTrait
};
use openzeppelin_testing as utils;
use snforge_std::{start_cheat_caller_address, start_cheat_transaction_version_global, test_address};
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
use crate::utils::{get_signatures, AttestorMultisigTx};
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use crate::utils::{
    setup_contracts, setup_attestors_and_fund, setup_account,
    VALUE_LOCKED, BTC_TX_ID, BTC_TX_ID2, BTC_FEE_RECIPIENT,
    ibtc_admin, default_admin, whitelist_address, mock_taproot_pubkey
};
use ibtc_cairo::ibtc_manager::{APPROVED_SIGNER};

