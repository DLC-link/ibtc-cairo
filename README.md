# IBTC Cairo

A Cairo implementation of the DLC.Link protocol for managing Discreet Log Contracts (DLCs) on StarkNet.

## Prerequisites

- [Scarb](https://docs.swmansion.com/scarb/download)
- [SNFoundry](https://foundry-rs.github.io/starknet-foundry/getting-started/installation.html)

## Setup

1. Install dependencies:
```bash
scarb build
```

2. Run tests:
```bash
snforge test
```

## Contracts

### IBTCManager
The main contract that manages iBTC vaults. It handles:
- Vault creation and management
- Vault status tracking
- Whitelisting
- Admin controls
- Multi-signature verification

### IBTCToken
An ERC20 token contract representing wrapped BTC in the iBTC system. Features:
- Minting/burning capabilities
- Role-based access control
- Configurable minter/burner roles

# Testing
UI to test and sign message: https://dapp-argentlabs.vercel.app/starknetkitLatest (with EIP-712 support)

# References
- https://github.com/argentlabs/starknet-off-chain-signature/tree/main
- https://github.com/DLC-link/dlc-solidity/tree/53a00a3f3f01fa1dbf3240e2dc73b06de63241d0/contracts

# iBTC Cairo Contracts

## Deployment

The `scripts/deploy.sh` script handles the deployment of iBTC contracts to StarkNet networks.

### Prerequisites

Before running the deployment script, ensure you have:

- [Scarb](https://docs.swmansion.com/scarb/) installed for Cairo contract compilation
- [Starkli](https://book.starkli.rs/) installed for StarkNet interaction
- A StarkNet account and keystore set up

### Configuration

Create a `deploy_config.sh` file in the `scripts` directory with your network configuration:

```bash
# Network RPC endpoints
export MAINNET_RPC="https://your-mainnet-rpc"
export TESTNET_RPC="https://your-testnet-rpc"

# Account and keystore paths
export STARKNET_ACCOUNT="~/.starkli/account.json"
export STARKNET_KEYSTORE="~/.starkli/keystore.json"
```

### Usage

Basic usage:
```bash
./scripts/deploy.sh --network <network> --account-address <address>
```

#### Options

- `--network`: Target network for deployment (mainnet/testnet)
- `--account-address`: Your StarkNet account address
- `--skip-build`: Skip contract compilation (use existing artifacts)

#### Examples

1. Deploy to testnet with fresh build:
```bash
cd ./scripts
./deploy.sh --network testnet --account-address 0x123...
```

2. Deploy to mainnet skipping build:
```bash
cd ./scripts
./deploy.sh --network mainnet --account-address 0x123... --skip-build
```

### Deployment Process

The script performs the following steps:

1. Setup account and keystore
2. Build contracts (unless --skip-build is used)
3. Declare contracts on StarkNet
4. Deploy contracts with constructor arguments
5. Verify deployments by calling contract methods
6. Save deployment addresses to `deployment_<network>.json`

### Output

After successful deployment, contract addresses and class hashes are saved to `deployment_<network>.json`:

```json
{
    "network": "testnet",
    "ibtc_token": {
        "address": "0x...",
        "class_hash": "0x..."
    },
    "ibtc_manager": {
        "address": "0x...",
        "class_hash": "0x..."
    },
    "timestamp": "2024-..."
}
```

### Error Handling

The script includes error handling for common scenarios:
- Missing prerequisites (scarb, starkli)
- Missing configuration
- Contract build failures
- Deployment failures
- Already deployed contracts (continues with existing addresses)
