#!/bin/bash

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../contracts" &> /dev/null && pwd )"

# Source configuration
source "$SCRIPT_DIR/deploy_config.sh"

export STARKNET_ACCOUNT="$SCRIPT_DIR/account.json"
export STARKNET_KEYSTORE="$SCRIPT_DIR/keystore.json"

# set -x

SALT=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
print_step() {
    echo -e "${YELLOW}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if ! command -v $1 &> /dev/null; then
        print_error "$1 could not be found. Please install it first."
        exit 1
    fi
}

# Check required tools
check_command "starkli"
check_command "scarb"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --account-address)
            ACCOUNT_ADDRESS="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --starknet-account)
            STARKNET_ACCOUNT="$2"
            shift 2
            ;;
        --starknet-keystore)
            STARKNET_KEYSTORE="$2"
            shift 2
            ;;
        --rpc-url)
            export STARKNET_RPC="$2"
            shift 2
            ;;
        *)
            print_error "Unknown argument $1"
            exit 1
            ;;
    esac
done

# Set network configuration
if [ "$NETWORK" = "mainnet" ]; then
    export STARKNET_RPC=$MAINNET_RPC
    print_step "Using Mainnet configuration"
elif [ "$NETWORK" = "testnet" ]; then
    export STARKNET_RPC=$TESTNET_RPC
    print_step "Using Testnet configuration"
elif [ "$NETWORK" = "devnet" ]; then
    export STARKNET_RPC=$DEVNET_RPC
    print_step "Using Devnet configuration"
else
    print_error "Invalid network. Please use 'mainnet', 'testnet', or 'devnet'"
    exit 1
fi

# Function to determine which signer flags to use
get_signer_flags() {
    # If PRIVATE_KEY environment variable is set, use it directly
    if [ -n "$PRIVATE_KEY" ]; then
        echo "--private-key $PRIVATE_KEY --strk"
    else
        echo "--strk"
    fi
}

# Setup account and keystore if not exists
setup_account() {
    print_step "Setting up account and keystore..."

    if [ ! -f "$STARKNET_ACCOUNT" ]; then
        if [ -z "$ACCOUNT_ADDRESS" ]; then
            print_error "Account address is required. Please provide it with --account-address"
            exit 1
        fi

        print_step "Fetching account..."
        starkli account fetch $ACCOUNT_ADDRESS --output=$STARKNET_ACCOUNT --rpc $STARKNET_RPC
    fi

    if [ ! -f "$STARKNET_KEYSTORE" ] && [ -z "$PRIVATE_KEY" ]; then
        print_step "Creating keystore..."
        starkli signer keystore from-key $STARKNET_KEYSTORE
    fi
}

# Declare contracts
declare_contracts() {
    print_step "Declaring contracts..."

    # Get the appropriate signer flags based on available credentials
    SIGNER_FLAGS=$(get_signer_flags)
    echo "Using signer flags: $SIGNER_FLAGS"

    # Build contracts first if not skipped
    if [ "$SKIP_BUILD" != "true" ]; then
        print_step "Building contracts..."
        (cd "$PROJECT_ROOT" && scarb build)
    else
        print_step "Skipping contract build..."
    fi

    # Check if contract artifacts exist
    if [ ! -f "$PROJECT_ROOT/target/dev/ibtc_cairo_IBTCToken.contract_class.json" ] || [ ! -f "$PROJECT_ROOT/target/dev/ibtc_cairo_IBTCManager.contract_class.json" ]; then
        print_error "Contract artifacts not found. Please build contracts first or remove --skip-build option"
        exit 1
    fi

    # Declare IBTCToken
    print_step "Declaring IBTCToken..."
    IBTC_TOKEN_CLASS_HASH=$(starkli declare "$PROJECT_ROOT/target/dev/ibtc_cairo_IBTCToken.contract_class.json" $SIGNER_FLAGS --watch --rpc $STARKNET_RPC --gas 99000)
    print_success "IBTCToken declared with class hash: $IBTC_TOKEN_CLASS_HASH"

    # Declare IBTCManager
    print_step "Declaring IBTCManager..."
    IBTC_MANAGER_CLASS_HASH=$(starkli declare "$PROJECT_ROOT/target/dev/ibtc_cairo_IBTCManager.contract_class.json" $SIGNER_FLAGS --watch --rpc $STARKNET_RPC --gas 99000)
    print_success "IBTCManager declared with class hash: $IBTC_MANAGER_CLASS_HASH"
}

# Deploy contracts
deploy_contracts() {
    print_step "Deploying contracts..."

    # Get the appropriate signer flags based on available credentials
    SIGNER_FLAGS=$(get_signer_flags)

    # Deploy IBTCToken
    print_step "Deploying IBTCToken..."
    if DEPLOY_OUTPUT=$(starkli deploy $IBTC_TOKEN_CLASS_HASH \
        $ACCOUNT_ADDRESS \
        $SIGNER_FLAGS \
        --watch \
        --rpc $STARKNET_RPC \
        --salt=$SALT 2>&1); then
        IBTC_TOKEN_ADDRESS=$(echo "$DEPLOY_OUTPUT" | tail -n 1)
        print_success "IBTCToken deployed at: $IBTC_TOKEN_ADDRESS"
    else
        if echo "$DEPLOY_OUTPUT" | grep -q "contract already deployed"; then
            # Extract address from the line containing "contract already deployed at address"
            IBTC_TOKEN_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep "contract already deployed at address" | grep -o "0x[0-9a-fA-F]\{64\}")
            if [ -z "$IBTC_TOKEN_ADDRESS" ]; then
                # Fallback: try to get address from "will be deployed at address" line
                IBTC_TOKEN_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep "will be deployed at address" | grep -o "0x[0-9a-fA-F]\{64\}")
            fi
            if [ -n "$IBTC_TOKEN_ADDRESS" ]; then
                print_success "IBTCToken already deployed at: $IBTC_TOKEN_ADDRESS"
            else
                print_error "Failed to extract IBTCToken address from error message:"
                echo "$DEPLOY_OUTPUT"
                exit 1
            fi
        else
            print_error "Failed to deploy IBTCToken:"
            echo "$DEPLOY_OUTPUT"
            exit 1
        fi
    fi

    # Deploy IBTCManager with constructor arguments
    print_step "Deploying IBTCManager..."
    if DEPLOY_OUTPUT=$(starkli deploy $IBTC_MANAGER_CLASS_HASH \
        $ACCOUNT_ADDRESS \
        $ACCOUNT_ADDRESS \
        3 \
        $IBTC_TOKEN_ADDRESS \
        0x000001 \
        $SIGNER_FLAGS \
        --watch \
        --rpc $STARKNET_RPC \
        --salt=$SALT 2>&1); then
        IBTC_MANAGER_ADDRESS=$(echo "$DEPLOY_OUTPUT" | tail -n 1)
        print_success "IBTCManager deployed at: $IBTC_MANAGER_ADDRESS"
    else
        if echo "$DEPLOY_OUTPUT" | grep -q "contract already deployed"; then
            # Extract address from the line containing "contract already deployed at address"
            IBTC_MANAGER_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep "contract already deployed at address" | grep -o "0x[0-9a-fA-F]\{64\}")
            if [ -z "$IBTC_MANAGER_ADDRESS" ]; then
                # Fallback: try to get address from "will be deployed at address" line
                IBTC_MANAGER_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep "will be deployed at address" | grep -o "0x[0-9a-fA-F]\{64\}")
            fi
            if [ -n "$IBTC_MANAGER_ADDRESS" ]; then
                print_success "IBTCManager already deployed at: $IBTC_MANAGER_ADDRESS"
            else
                print_error "Failed to extract IBTCManager address from error message:"
                echo "$DEPLOY_OUTPUT"
                exit 1
            fi
        else
            print_error "Failed to deploy IBTCManager:"
            echo "$DEPLOY_OUTPUT"
            exit 1
        fi
    fi
}

# Verify deployments
verify_deployment() {
    print_step "Verifying deployments..."

    # Verify IBTCToken
    print_step "Verifying IBTCToken..."
    starkli call $IBTC_TOKEN_ADDRESS name --rpc $STARKNET_RPC

    # Verify IBTCManager
    print_step "Verifying IBTCManager..."
    starkli call $IBTC_MANAGER_ADDRESS get_threshold --rpc $STARKNET_RPC
}

# Save deployment addresses
save_deployment() {
    print_step "Saving deployment addresses..."

    cat > "$SCRIPT_DIR/deployment_$NETWORK.json" << EOF
{
    "network": "$NETWORK",
    "ibtc_token": {
        "address": "$IBTC_TOKEN_ADDRESS",
        "class_hash": "$IBTC_TOKEN_CLASS_HASH"
    },
    "ibtc_manager": {
        "address": "$IBTC_MANAGER_ADDRESS",
        "class_hash": "$IBTC_MANAGER_CLASS_HASH"
    },
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
    print_success "Deployment addresses saved to deployment_$NETWORK.json"
}

# Main deployment flow
main() {
    setup_account
    # declare_contracts
    # deploy_contracts
    verify_deployment
    # save_deployment

    print_success "Deployment completed successfully!"
}

# Run main function
main
