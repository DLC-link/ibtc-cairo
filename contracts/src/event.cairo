use starknet::ContractAddress;
use starknet::eth_address::EthAddress;

#[derive(Drop, starknet::Event)]
pub struct CreateIBTCVault {
    uuid: u256,
    creator: ContractAddress,
    timestamp: u64,
}

#[derive(Drop, starknet::Event)]
pub struct SetStatusFunded {
    uuid: u256,
    btc_tx_id: u256,
    creator: ContractAddress,
    new_value_locked: u256,
    amount_to_mint: u256,
}

#[derive(Drop, starknet::Event)]
pub struct SetStatusPending {
    uuid: u256,
    btc_tx_id: u256,
    creator: ContractAddress,
    taproot_pubkey: ByteArray,
    new_value_locked: u256,
}

#[derive(Drop, starknet::Event)]
pub struct Withdraw {
    uuid: u256,
    amount: u256,
    sender: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct SetThreshold {
    new_threshold: u16,
}

#[derive(Drop, starknet::Event)]
pub struct Mint {
    to: ContractAddress,
    amount: u256,
}

#[derive(Drop, starknet::Event)]
pub struct Burn {
    from: ContractAddress,
    amount: u256,
}

#[derive(Drop, starknet::Event)]
pub struct WhitelistAddress {
    address_to_whitelist: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct UnwhitelistAddress {
    address_to_unwhitelist: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct SetMinimumDeposit {
    new_minimum_deposit: u256,
}

#[derive(Drop, starknet::Event)]
pub struct SetMaximumDeposit {
    new_maximum_deposit: u256,
}

#[derive(Drop, starknet::Event)]
pub struct SetBtcMintFeeRate {
    new_btc_mint_fee_rate: u16,
}

#[derive(Drop, starknet::Event)]
pub struct SetBtcRedeemFeeRate {
    new_btc_redeem_fee_rate: u16,
}

#[derive(Drop, starknet::Event)]
pub struct SetBtcFeeRecipient {
    btc_fee_recipient: ByteArray,
}

#[derive(Drop, starknet::Event)]
pub struct SetApprovedSigners {
    signers: Array<ContractAddress>,
}

#[derive(Drop, starknet::Event)]
pub struct SetWhitelistingEnabled {
    is_whitelisting_enabled: bool,
}

#[derive(Drop, starknet::Event)]
pub struct TransferTokenContractOwnership {
    new_owner: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct SetPorEnabled {
    is_por_enabled: bool,
}

#[derive(Drop, starknet::Event)]
pub struct SetIBtcPorFeed {
    feed: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct GrantSignerRole {
    account: EthAddress,
}

#[derive(Drop, starknet::Event)]
pub struct RevokeSignerRole {
    account: EthAddress,
}
