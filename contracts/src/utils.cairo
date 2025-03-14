use starknet::{ContractAddress, Span};
use core::poseidon::poseidon_hash_span;
use starknet::{get_tx_info, get_caller_address};
use core::poseidon::PoseidonTrait;
use core::hash::{HashStateTrait, HashStateExTrait};

#[derive(Hash, Drop, Copy)]
struct StarknetDomain {
    name: felt252,
    version: felt252,
    chain_id: felt252,
    revision: felt252,
}

/// @notice Defines the function to generate the SNIP-12
pub trait IOffChainMessageHash<T> {
    fn get_message_hash(self: @T, account: ContractAddress) -> felt252;
}

/// @notice Defines the function to generates the SNIP-12
trait IStructHash<T> {
    fn get_struct_hash(self: @T) -> felt252;
}

impl StructHashStarknetDomain of IStructHash<StarknetDomain> {
    fn get_struct_hash(self: @StarknetDomain) -> felt252 {
        poseidon_hash_span(
            array![
                STARKNET_DOMAIN_TYPE_HASH,
                *self.name,
                *self.version,
                *self.chain_id,
                *self.revision
            ]
                .span()
        )
    }
}

const STARKNET_DOMAIN_TYPE_HASH: felt252 =
    selector!(
        "\"StarknetDomain\"(\"name\":\"shortstring\",\"version\":\"shortstring\",\"chainId\":\"shortstring\",\"revision\":\"shortstring\")"
    );

const ATTESTOR_MULTISIG_STRUCT_TYPE_HASH: felt252 =
    selector!("\"AttestorMultisigTx\"(\"uuid\":\"felt\",\"btc_tx_id\":\"u256\",\"tx_type\":\"felt\",\"amount\":\"u256\")\"u256\"(\"low\":\"u128\",\"high\":\"u128\")");

const U256_TYPE_HASH: felt252 = selector!("\"u256\"(\"low\":\"u128\",\"high\":\"u128\")");

#[derive(Drop, Copy, Hash)]
pub struct AttestorMultisigTx {
    uuid: felt252,
    btc_tx_id: u256,
    tx_type: felt252,
    amount: u256,
}

pub impl OffChainMessageHashAttestorMultisigTx of IOffChainMessageHash<AttestorMultisigTx> {
    fn get_message_hash(self: @AttestorMultisigTx, account: ContractAddress) -> felt252 {
        let domain = StarknetDomain {
            name: 'dappName', version: '1', chain_id: get_tx_info().unbox().chain_id, revision: 1
        };
        let mut state = PoseidonTrait::new();
        state = state.update_with('StarkNet Message');
        state = state.update_with(domain.get_struct_hash());
        // This can be a field within the struct, it doesn't have to be get_caller_address().
        state = state.update_with(account);
        state = state.update_with(self.get_struct_hash());
        // Hashing with the amount of elements being hashed
        state.finalize()
    }
}

impl StructHashAttestorMultisigTx of IStructHash<AttestorMultisigTx> {
    fn get_struct_hash(self: @AttestorMultisigTx) -> felt252 {
        let mut state = PoseidonTrait::new();
        state = state.update_with(ATTESTOR_MULTISIG_STRUCT_TYPE_HASH);
        state = state.update_with(*self.uuid);
        state = state.update_with(self.btc_tx_id.get_struct_hash());
        state = state.update_with(*self.tx_type);
        state = state.update_with(self.amount.get_struct_hash());
        state.finalize()
    }
}

impl StructHashU256 of IStructHash<u256> {
    fn get_struct_hash(self: @u256) -> felt252 {
        let mut state = PoseidonTrait::new();
        state = state.update_with(U256_TYPE_HASH);
        state = state.update_with(*self);
        state.finalize()
    }
}