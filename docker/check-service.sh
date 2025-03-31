#!/bin/sh
if grep -q "Deployment Complete" /app/logs/starknet-devnet.log; then
  exit 0
else
  exit 1
fi
