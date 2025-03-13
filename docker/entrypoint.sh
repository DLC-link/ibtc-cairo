#!/bin/sh

# Create log directory
mkdir -p /app/logs

# Start starknet-devnet in the background, binding to all interfaces
starknet-devnet --seed 0 --host 0.0.0.0 --port 5050 > /app/logs/starknet-devnet.log 2>&1 &
DEVNET_PID=$!

echo "Started starknet-devnet with PID: $DEVNET_PID"

# Wait for starknet-devnet to start
echo "Waiting for Starknet Devnet to start..."
sleep 2

# Check if devnet is running
while ! grep -q "Starknet Devnet listening" /app/logs/starknet-devnet.log; do
  echo "Still waiting for Starknet Devnet to initialize..."
  sleep 2

  # Check if process is still running
  if ! ps -p $DEVNET_PID > /dev/null; then
    echo "ERROR: Starknet Devnet process died!"
    cat /app/logs/starknet-devnet.log
    exit 1
  fi
done

echo "Starknet Devnet started successfully on 0.0.0.0:5050"

# Ensure needed files/directories exist with proper permissions
chmod 755 /app/docker/account.json || true
chmod 755 /app/docker/keystore.json || true
chmod +x /app/bash_scripts/*.sh

# Set up environment variables for starkli
export STARKNET_RPC="http://127.0.0.1:5050"
export STARKNET_ACCOUNT="/app/docker/account.json"
export STARKNET_KEYSTORE="/app/docker/keystore.json"
export PRIVATE_KEY="0x0000000000000000000000000000000071d7bb07b9a64f6f78ac4c816aff4da9" # Dev account 1
export STARKLI_NO_PLAIN_KEY_WARNING=true

echo "Running deployment script..."

cd /app/bash_scripts && ./deploy.sh \
  --account-address 0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691 \
  --skip-build \
  --starknet-account /app/docker/account.json \
  --starknet-keystore /app/docker/keystore.json \

echo "Deployment completed. Container will continue running..."

tail -f /app/logs/starknet-devnet.log
