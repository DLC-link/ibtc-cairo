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

# Set up environment variables for Node.js deployment
ACCOUNT_ADDRESS="0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691"
PRIVATE_KEY="0x0000000000000000000000000000000071d7bb07b9a64f6f78ac4c816aff4da9"

# Create .env file for deployment script
cat > /app/scripts/.env << EOL
STARKNET_ACCOUNT_ADDRESS=${ACCOUNT_ADDRESS}
STARKNET_PRIVATE_KEY=${PRIVATE_KEY}
DEVNET_RPC=http://127.0.0.1:5050
EOL

echo "Running Node.js deployment script..."

cd /app/scripts && node deploy.js devnet

echo "Deployment completed. Container will continue running..."

tail -f /app/logs/starknet-devnet.log
