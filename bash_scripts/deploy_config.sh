#!/bin/bash

# Network configurations
TESTNET_RPC="https://starknet-sepolia.public.blastapi.io/rpc/v0_7"
MAINNET_RPC="https://starknet-mainnet.public.blastapi.io/rpc/v0_7"
DEVNET_RPC="http://localhost:5050"

# Default to devnet
NETWORK="devnet"
STARKNET_RPC=$DEVNET_RPC

# Contract addresses (to be populated during deployment)
IBTC_TOKEN_ADDRESS=""
IBTC_MANAGER_ADDRESS=""

# Default account address (replace with your account address)
ACCOUNT_ADDRESS=""

# Contract class hashes (to be populated during declaration)
IBTC_TOKEN_CLASS_HASH=""
IBTC_MANAGER_CLASS_HASH=""