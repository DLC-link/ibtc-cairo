#!/bin/zsh

export STARKNET_ACCOUNT=$(pwd)/account.json
export STARKNET_KEYSTORE=$(pwd)/keystore-sepolia.json
# export STARKNET_RPC=http://127.0.0.1:5050
export STARKNET_RPC=https://starknet-sepolia.public.blastapi.io/rpc/v0_7
export STARKNET_NETWORK="sepolia"
export IBTC_TOKEN_ADDRESS=0x01f0b7ac720a0c02691a2f5ae1a66c63fee7288fa8b290ae443785c4f9992859
export IBTC_TOKEN_ADDRESS1=0x01384f3005b0ff8c0c356651a2b9aae542c6966f981139792cdf57712f87e6b8
export ACCOUNT_ADDRESS=0x022637d62614a0cb6c381dcf47eabe7290b218bb53beff5ba9f54cf291aac0dd

# constructor()
export IBTC_TOKEN_CLASS_HASH=0x0328f0b1d737ccb5ac293a812a4fa4e15fa5ac07a0c5109ad06904980da91b85
# constructor(owner)
export IBTC_TOKEN_CLASS_HASH1=0x02a9c46a4c74a01f2ba19eba97c42f28fdd3e6007559aa6dce9de9576b3be49f


starkli account fetch \
    0x22637d62614a0cb6c381dcf47eabe7290b218bb53beff5ba9f54cf291aac0dd \
    --output=account.json

starkli signer keystore from-key keystore.json

starkli declare \
    ../target/dev/ibtc_cairo_IBTCToken.contract_class.json
# Sierra compiler version not specified. Attempting to automatically decide version to use...
# Network detected: sepolia. Using the default compiler version for this network: 2.9.1. Use the --compiler-version flag to choose a different version.
# Declaring Cairo 1 class: 0x0328f0b1d737ccb5ac293a812a4fa4e15fa5ac07a0c5109ad06904980da91b85
# Compiling Sierra class to CASM with compiler version 2.9.1...
# CASM class hash: 0x06cfff5ff9903692a5b196dc733f8cfb910d51f9f83bb7038a8d45dff4b6bcc9
# Contract declaration transaction: 0x01d2ad33237c1c55a7e6d081cd4d21cc5d26b322856b7bdab15ec27de9e15f78
# Class hash declared:
# 0x0328f0b1d737ccb5ac293a812a4fa4e15fa5ac07a0c5109ad06904980da91b85

starkli deploy \
    $IBTC_TOKEN_CLASS_HASH1 \
    $ACCOUNT_ADDRESS \
    --salt=0


starkli deploy \
    $IBTC_TOKEN_CLASS_HASH \
    --salt=0
    
# Deploying class 0x0328f0b1d737ccb5ac293a812a4fa4e15fa5ac07a0c5109ad06904980da91b85 with salt 0x0000000000000000000000000000000000000000000000000000000000000000...
# The contract will be deployed at address 0x0013b0779b85f07fe58ee65343b8afd3906dd8dd5910efa57dcd414a0d9b4cdf
# Contract deployment transaction: 0x03d5d18dd334bde30807806ccd64b3304bb8dcd21a8650b811382f18eda8a288
# Contract deployed:
# 0x0013b0779b85f07fe58ee65343b8afd3906dd8dd5910efa57dcd414a0d9b4cdf

starkli call \
    0x0013b0779b85f07fe58ee65343b8afd3906dd8dd5910efa57dcd414a0d9b4cdf \
    name \
    --rpc=$STARKNET_RPC

starkli invoke \
    0x0013b0779b85f07fe58ee65343b8afd3906dd8dd5910efa57dcd414a0d9b4cdf \
    mint 0x078662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1 123 0 \
    --rpc=$STARKNET_RPC

starkli call \
    0x0013b0779b85f07fe58ee65343b8afd3906dd8dd5910efa57dcd414a0d9b4cdf \
    balance_of 0x078662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1 \
    --rpc=$STARKNET_RPC

# test mint and check balance
starkli invoke \
    $IBTC_TOKEN_ADDRESS1 \
    mint 0x07d2fd5f69c7c5465f488014f1dd95e64e1d613da5499594c1e48fc69cc57d84 123 0

starkli call \
    $IBTC_TOKEN_ADDRESS \
    balance_of 0x07d2fd5f69c7c5465f488014f1dd95e64e1d613da5499594c1e48fc69cc57d84

starkli call \
    $IBTC_TOKEN_ADDRESS \
    owner