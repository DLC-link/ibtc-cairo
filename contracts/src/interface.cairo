use starknet::ContractAddress;
use starknet::eth_address::EthAddress;
use starknet::ClassHash;
use crate::ibtc_library::IBTCVault;
use starknet::account::Call;

#[starknet::interface]
pub trait IBTCTokenABI<TState> {

    // IERC20
    fn total_supply(self: @TState) -> u256;
    fn balance_of(self: @TState, account: ContractAddress) -> u256;
    fn allowance(self: @TState, owner: ContractAddress, spender: ContractAddress) -> u256;
    fn transfer(ref self: TState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(
        ref self: TState, sender: ContractAddress, recipient: ContractAddress, amount: u256,
    ) -> bool;
    fn approve(ref self: TState, spender: ContractAddress, amount: u256) -> bool;

    // IERC20Metadata
    fn name(self: @TState) -> ByteArray;
    fn symbol(self: @TState) -> ByteArray;
    fn decimals(self: @TState) -> u8;

    fn mint(ref self: TState, to: ContractAddress, amount: u256);
    fn burn(ref self: TState, amount: u256);
    fn burn_from(ref self: TState, account: ContractAddress, amount: u256);

    // IOwnable
    fn owner(self: @TState) -> ContractAddress;
    fn transfer_ownership(ref self: TState, new_owner: ContractAddress);
    fn renounce_ownership(ref self: TState);

    fn set_minter(ref self: TState, minter: ContractAddress);
    fn set_burner(ref self: TState, burner: ContractAddress);

    fn minter(self: @TState) -> ContractAddress;
    fn burner(self: @TState) -> ContractAddress;

    // IUpgradeable
    fn upgrade(ref self: TState, new_class_hash: ClassHash);
    fn upgrade_and_call(
        ref self: TState, new_class_hash: ClassHash, selector: felt252, calldata: Span<felt252>,
    ) -> Span<felt252>;
}

#[starknet::interface]
pub trait IBTCManagerABI<TState> {

    // ISRC5
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;

    // deposit and withdraw
    fn setup_vault(ref self: TState) -> felt252;
    fn set_status_funded(ref self: TState, uuid: u256, btc_tx_id: u256, new_value_locked: u256, signatures: Span<(ContractAddress, Array<felt252>)>);
    fn set_status_pending(ref self: TState, uuid: u256, wdtx_id: u256, taproot_pubkey: ByteArray, new_value_locked: u256, signatures: Span<(ContractAddress, Array<felt252>)>);
    fn set_status_pendingm(ref self: TState, message: felt252, signatures: Span<(ContractAddress, Array<felt252>)>);
    fn withdraw(ref self: TState, uuid: u256, amount: u256);

    // getters
    fn get_vault(self: @TState, uuid: u256) -> IBTCVault;
    fn get_ibtc_vault_by_index(self: @TState, index: u128) -> IBTCVault;
    fn get_all_vaults(self: @TState, start_index: u256, end_index: u256) -> Array<IBTCVault>;
    fn get_all_vaults_for_address(self: @TState, owner: ContractAddress) -> Array<IBTCVault>;
    fn get_all_vault_uuids_for_address(self: @TState, owner: ContractAddress) -> Array<u256>;
    fn get_ssf_message(self: @TState, attestor: ContractAddress, uuid: u256, btc_tx_id: u256, new_value_locked: u256) -> felt252;
    fn get_ssp_message(self: @TState, attestor: ContractAddress, uuid: u256, wdtx_id: u256, new_value_locked: u256) -> felt252;
    fn is_whitelisted(self: @TState, account: ContractAddress) -> bool;
    fn get_threshold(self: @TState) -> u16;
    fn get_minimum_threshold(self: @TState) -> u16;
    fn get_signer_count(self: @TState) -> u16;
    fn get_whitelisting_enabled(self: @TState) -> bool;
    fn get_btc_mint_fee_rate(self: @TState) -> u16;
    fn get_btc_redeem_fee_rate(self: @TState) -> u16;
    fn get_btc_fee_recipient(self: @TState) -> ByteArray;
    fn get_attestor_group_pubkey(self: @TState) -> ByteArray;
    fn get_minimum_deposit(self: @TState) -> u256;
    fn get_maximum_deposit(self: @TState) -> u256;
    fn get_tss_commitment(self: @TState) -> felt252;
    fn get_user_vaults(self: @TState, owner: ContractAddress) -> Span<u256>;

    // IAccessControl
    fn has_role(self: @TState, role: felt252, account: ContractAddress) -> bool;
    fn get_role_admin(self: @TState, role: felt252) -> felt252;
    fn grant_role(ref self: TState, role: felt252, account: ContractAddress);
    fn revoke_role(ref self: TState, role: felt252, account: ContractAddress);
    fn renounce_role(ref self: TState, role: felt252, account: ContractAddress);

    // IPausable
    fn is_paused(self: @TState) -> bool;
    fn pause_contract(ref self: TState);
    fn unpause_contract(ref self: TState);

    fn set_threshold(ref self: TState, new_threshold: u16);
    fn set_tss_commitment(ref self: TState, commitment: felt252);
    fn set_attestor_group_pubkey(ref self: TState, pubkey: ByteArray);
    fn whitelist_address(ref self: TState, account: ContractAddress);
    fn unwhitelist_address(ref self: TState, account: ContractAddress);
    fn set_minimum_deposit(ref self: TState, amount: u256);
    fn set_maximum_deposit(ref self: TState, amount: u256);
    fn set_btc_mint_fee_rate(ref self: TState, rate: u16);
    fn set_btc_redeem_fee_rate(ref self: TState, rate: u16);
    fn set_btc_fee_recipient(ref self: TState, recipient: ByteArray);
    fn set_btc_fee_recipient_for_vault(ref self: TState, uuid: felt252, recipient: ByteArray);
    fn set_whitelisting_enabled(ref self: TState, enabled: bool);
    fn transfer_token_contract_ownership(ref self: TState, new_owner: ContractAddress);
    fn set_minter_on_token_contract(ref self: TState, minter: ContractAddress);
    fn set_burner_on_token_contract(ref self: TState, burner: ContractAddress);
    fn set_por_enabled(ref self: TState, enabled: bool);
    fn set_ibtc_por_feed(ref self: TState, feed: ContractAddress);

    // IUpgradeable
    fn upgrade(ref self: TState, new_class_hash: ClassHash);
    fn upgrade_and_call(
        ref self: TState, new_class_hash: ClassHash, selector: felt252, calldata: Span<felt252>,
    ) -> Span<felt252>;
}

// https://github.com/smartcontractkit/chainlink-starknet/blob/develop/examples/contracts/aggregator_consumer/src/ocr2/consumer.cairo
// https://docs.chain.link/data-feeds/starknet/tutorials/snfoundry/consumer-contract
#[derive(Copy, Drop, Serde, PartialEq, starknet::Store)]
pub struct Round {
    // used as u128 internally, but necessary for phase-prefixed round ids as returned by proxy
    round_id: felt252,
    answer: u128,
    block_num: u64,
    started_at: u64,
    updated_at: u64,
}

#[starknet::interface]
pub trait IAggregatorConsumer<TContractState> {
    fn read_latest_round(self: @TContractState) -> Round;
    fn read_ocr_address(self: @TContractState) -> starknet::ContractAddress;
    fn read_answer(self: @TContractState) -> u128;
    fn set_answer(ref self: TContractState, answer: u128);
}

#[starknet::interface]
pub trait IAccount<TContractState> {
    fn __validate__(ref self: TContractState, calls: Array<Call>) -> felt252;
    fn __execute__(ref self: TContractState, calls: Array<Call>) -> Array<Span<felt252>>;

    /// @notice Checks whether a given signature for a given hash is valid
    /// @dev Warning: To guarantee the signature cannot be replayed in other accounts or other chains, the data hashed must be unique to the account and the chain.
    /// This is true today for starknet transaction signatures and for SNIP-12 signatures but might not be true for other types of signatures
    /// @param hash The hash of the data to sign
    /// @param signature The signature to validate
    /// @return The shortstring 'VALID' when the signature is valid, 0 if the signature doesn't match the hash
    /// @dev it can also panic if the signature is not in a valid format
    fn is_valid_signature(self: @TContractState, hash: felt252, signature: Array<felt252>) -> felt252;
}
