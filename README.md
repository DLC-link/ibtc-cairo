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

## Running in Dev Container (easiest way)

Open the project in a dev container with the configuration at `.devcontainer.json`. This container already has scarb, starkli, and starknet-devnet installed.

```json
{
    "name": "dev",
    "image": "starknetfoundation/starknet-dev:2.9.4",
    "customizations": {
        "vscode": {
            "extensions": [
                "StarkWare.cairo1",
                "tamasfe.even-better-toml"
            ]
        }
    },
    "forwardPorts": [
        5050
    ]
}
```

Open the first terminal tab and run the starknet-devnet
```
starknet-devnet --seed 0
```

Open the second terminal tab and run the deploy script (update the account info the `.env` file)
```bash
cd scripts/
yarn
node deploy.js [devnet|testnet|mainnet]?
```

To run some basic tests (testing upgrades)
```bash
node basic-test.js [devnet|testnet|mainnet]?
```

## Using sncast script (deprecated)

Import the first account in the devnet's account list to the sncast profile.
```bash
cd bash_scripts/
sncast \
    account import \
    --url http://127.0.0.1:5050/rpc \
    --name devnet-account \
    --add-profile dev \
    --address 0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691 \
    --private-key 0x0000000000000000000000000000000071d7bb07b9a64f6f78ac4c816aff4da9 \
    --type oz
```

Run the deploy script with the sncast profile
```bash
cd bash_scripts/
sncast --profile dev script run ibtc_deploy_script
```

## Contracts

### DLCManager
The main contract that manages DLCs. It handles:
- Vault creation and management
- DLC status tracking
- Whitelisting
- Admin controls
- Multi-signature verification

### DLCBTC
An ERC20 token contract representing wrapped BTC in the DLC system. Features:
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