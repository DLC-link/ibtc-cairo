use snforge_std::DeclareResultTrait;
use starknet::{ContractAddress, contract_address_const};
use snforge_std::{declare, ContractClassTrait};
use starknet::get_caller_address;
use ibtc_cairo::interface::{IBTCTokenABIDispatcher, IBTCTokenABIDispatcherTrait, IBTCTokenABISafeDispatcher, IBTCTokenABISafeDispatcherTrait};
use openzeppelin_testing as utils;
use snforge_std::{start_cheat_caller_address, start_cheat_transaction_version_global, test_address};
use snforge_std::{EventSpy, spy_events};
use openzeppelin_testing::events::EventSpyExt;

fn ibtc_token_owner() -> ContractAddress {
    contract_address_const::<0x123>()
}

fn setup_contracts() -> (IBTCTokenABISafeDispatcher, IBTCTokenABIDispatcher) {
    let ibtc_token_calldata = array![ibtc_token_owner().into()];
    let ibtc_token_address = utils::declare_and_deploy("IBTCToken", ibtc_token_calldata);
    let ibtc_token_safe = IBTCTokenABISafeDispatcher { contract_address: ibtc_token_address };
    let ibtc_token = IBTCTokenABIDispatcher { contract_address: ibtc_token_address };

    start_cheat_caller_address(ibtc_token.contract_address, ibtc_token_owner());
    (ibtc_token_safe, ibtc_token)
}

#[test]
fn test_constructor() {
    let (_, ibtc_token) = setup_contracts();
    // Test initial values
    assert_eq!(ibtc_token.name(), "IBTC");
    assert_eq!(ibtc_token.symbol(), "IBTC");
    assert_eq!(ibtc_token.decimals(), 8);
}

#[test]
fn test_mint_by_owner() {
    let (_, ibtc_token) = setup_contracts();
    let recipient = contract_address_const::<0x456>();
    let amount = 1000_u256;

    ibtc_token.mint(recipient, amount);
    assert_eq!(ibtc_token.balance_of(recipient), amount);
    assert_eq!(ibtc_token.total_supply(), amount);
}

#[test]
fn test_mint_by_minter() {
    let (_, ibtc_token) = setup_contracts();
    let minter = contract_address_const::<0x789>();
    let recipient = contract_address_const::<0x456>();
    let amount = 1000_u256;

    ibtc_token.set_minter(minter);
    ibtc_token.mint(recipient, amount);

    assert(ibtc_token.balance_of(recipient) == amount, 'Balance incorrect');
    assert(ibtc_token.total_supply() == amount, 'Total supply is not correct');
}

#[test]
fn test_mint_by_unauthorized() {
    let (ibtc_token_safe, ibtc_token) = setup_contracts();
    let recipient = contract_address_const::<0x456>();
    let amount = 1000_u256;

    start_cheat_caller_address(ibtc_token.contract_address, contract_address_const::<0x999>());
    let result = ibtc_token_safe.mint(recipient, amount);
    assert(result.is_err(), 'Mint should fail');
}

#[test]
fn test_burn_from_by_owner() {
    let (_, ibtc_token) = setup_contracts();
    let burner = contract_address_const::<0x789>();
    let amount = 1000_u256;
    ibtc_token.mint(burner, amount);

    ibtc_token.set_burner(burner);
    ibtc_token.burn_from(burner, amount);

    assert(ibtc_token.balance_of(burner) == 0, 'Balance incorrect');
    assert(ibtc_token.total_supply() == 0, 'Total supply is not correct');
}

#[test]
fn test_burn_by_burner() {
    let (_, ibtc_token) = setup_contracts();
    let burner = contract_address_const::<0x789>();
    let amount = 1000_u256;

    ibtc_token.mint(burner, amount);
    ibtc_token.set_burner(burner);
    start_cheat_caller_address(ibtc_token.contract_address, burner);
    ibtc_token.burn(amount);

    assert(ibtc_token.balance_of(burner) == 0, 'Balance incorrect');
    assert(ibtc_token.total_supply() == 0, 'Total supply is not correct');
}

#[test]
fn test_burn_by_unauthorized() {
    let (ibtc_token_safe, ibtc_token) = setup_contracts();
    let amount = 1000_u256;

    start_cheat_caller_address(ibtc_token.contract_address, contract_address_const::<0x999>());
    let result = ibtc_token_safe.burn(amount);
    assert(result.is_err(), 'Burn should fail');
}

#[test]
fn test_burn_from_by_unauthorized() {
    let (ibtc_token_safe, ibtc_token) = setup_contracts();
    let account = contract_address_const::<0x789>();
    let amount = 1000_u256;

    start_cheat_caller_address(ibtc_token.contract_address, contract_address_const::<0x999>());
    let result = ibtc_token_safe.burn_from(account, amount);
    assert(result.is_err(), 'Burn should fail');
}

#[test]
fn test_set_minter() {
    let (_, ibtc_token) = setup_contracts();
    let minter = contract_address_const::<0x789>();
    ibtc_token.set_minter(minter);
    assert(ibtc_token.minter() == minter, 'Minter is not correct');
}

#[test]
fn test_set_burner() {
    let (_, ibtc_token) = setup_contracts();
    let burner = contract_address_const::<0x789>();
    ibtc_token.set_burner(burner);
    assert(ibtc_token.burner() == burner, 'Burner is not correct');
}

#[test]
fn test_set_minter_by_unauthorized() {
    let (ibtc_token_safe, ibtc_token) = setup_contracts();
    let minter = contract_address_const::<0x789>();
    start_cheat_caller_address(ibtc_token.contract_address, contract_address_const::<0x999>());
    let result = ibtc_token_safe.set_minter(minter);
    assert(result.is_err(), 'Set minter should fail');
}

#[test]
fn test_set_burner_by_unauthorized() {
    let (ibtc_token_safe, ibtc_token) = setup_contracts();
    let burner = contract_address_const::<0x789>();
    start_cheat_caller_address(ibtc_token.contract_address, contract_address_const::<0x999>());
    let result = ibtc_token_safe.set_burner(burner);
    assert(result.is_err(), 'Set burner should fail');
}
