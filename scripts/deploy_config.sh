#!/bin/bash

# Configuration file for deployment
export STARKNET_ACCOUNT="./account.json"
export STARKNET_KEYSTORE="./keystore.json"

# Network configurations
TESTNET_RPC="https://starknet-sepolia.public.blastapi.io/rpc/v0_7"
MAINNET_RPC="https://starknet-mainnet.public.blastapi.io/rpc/v0_7"

# Default to testnet
NETWORK="testnet"
STARKNET_RPC=$TESTNET_RPC

# Contract addresses (to be populated during deployment)
IBTC_TOKEN_ADDRESS=""
IBTC_MANAGER_ADDRESS=""

# Default account address (replace with your account address)
ACCOUNT_ADDRESS=""

# Contract class hashes (to be populated during declaration)
IBTC_TOKEN_CLASS_HASH=""
IBTC_MANAGER_CLASS_HASH=""