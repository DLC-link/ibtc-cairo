import { Provider, Account, constants } from "starknet";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Network configurations
export const NETWORKS = {
    mainnet: {
        name: "mainnet",
        rpc: process.env.MAINNET_RPC || "https://starknet-mainnet.public.blastapi.io"
    },
    testnet: {
        name: "testnet",
        rpc: process.env.TESTNET_RPC || "https://starknet-testnet.public.blastapi.io"
    },
    devnet: {
        name: "devnet",
        rpc: process.env.DEVNET_RPC || "http://127.0.0.1:5050"
    }
};

// Helper functions
export const log = {
    step: (msg) => console.log("\x1b[33m[STEP]\x1b[0m", msg),
    success: (msg) => console.log("\x1b[32m[SUCCESS]\x1b[0m", msg),
    error: (msg) => console.log("\x1b[31m[ERROR]\x1b[0m", msg)
};

export async function setupProvider(network) {
    const networkConfig = NETWORKS[network];
    if (!networkConfig) {
        throw new Error(`Invalid network. Please use 'mainnet', 'testnet', or 'devnet'`);
    }

    log.step(`Using ${networkConfig.name} configuration`);
    return new Provider({ nodeUrl: networkConfig.rpc });
}

export async function setupAccount(provider, accountAddress, privateKey) {
    if (!accountAddress || !privateKey) {
        throw new Error("Account address and private key are required");
    }

    log.step("Setting up account...");
    return new Account(provider, accountAddress, privateKey, undefined, constants.TRANSACTION_VERSION.V3);
}