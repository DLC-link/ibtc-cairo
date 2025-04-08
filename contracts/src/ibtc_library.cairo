use starknet::ContractAddress;
use starknet::storage::{
    Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
    StoragePointerWriteAccess,
};

// Define the IBTCVaultStatus enum
pub enum IBTCVaultStatus {
    READY,
    FUNDED,
    CLOSING,
    CLOSED,
    AUX_STATE_1,
    AUX_STATE_2,
    AUX_STATE_3,
    AUX_STATE_4,
    AUX_STATE_5,
}

pub impl U8TryIntoIBTCVaultStatus of TryInto<u8, IBTCVaultStatus> {
    fn try_into(self: u8) -> Option<IBTCVaultStatus> {
        match self {
            0 => Option::Some(IBTCVaultStatus::READY),
            1 => Option::Some(IBTCVaultStatus::FUNDED),
            2 => Option::Some(IBTCVaultStatus::CLOSING),
            3 => Option::Some(IBTCVaultStatus::CLOSED),
            4 => Option::Some(IBTCVaultStatus::AUX_STATE_1),
            5 => Option::Some(IBTCVaultStatus::AUX_STATE_2),
            6 => Option::Some(IBTCVaultStatus::AUX_STATE_3),
            7 => Option::Some(IBTCVaultStatus::AUX_STATE_4),
            8 => Option::Some(IBTCVaultStatus::AUX_STATE_5),
            _ => Option::None,
        }
    }
}

pub impl IBTCVaultStatusIntoU8 of Into<IBTCVaultStatus, u8> {
    fn into(self: IBTCVaultStatus) -> u8 {
        match self {
            IBTCVaultStatus::READY => 0,
            IBTCVaultStatus::FUNDED => 1,
            IBTCVaultStatus::CLOSING => 2,
            IBTCVaultStatus::CLOSED => 3,
            IBTCVaultStatus::AUX_STATE_1 => 4,
            IBTCVaultStatus::AUX_STATE_2 => 5,
            IBTCVaultStatus::AUX_STATE_3 => 6,
            IBTCVaultStatus::AUX_STATE_4 => 7,
            IBTCVaultStatus::AUX_STATE_5 => 8,
        }
    }
}

// Define the IBTCVault struct
#[derive(Serde, Drop, starknet::Store, Debug)]
pub struct IBTCVault {
    uuid: felt252,
    protocol_contract: ContractAddress,
    timestamp: u64,
    value_locked: u256,
    creator: ContractAddress,
    status: u8,
    funding_tx_id: felt252,
    closing_tx_id: felt252,
    btc_fee_recipient: ByteArray,
    btc_mint_fee_basis_points: u64,
    btc_redeem_fee_basis_points: u64,
    taproot_pubkey: ByteArray,
    value_minted: u256,
    wd_tx_id: felt252,
}
