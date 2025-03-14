import { Provider, Account, Contract, json, constants } from "starknet";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config();

// Network configurations
const NETWORKS = {
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

// Constants
const SALT = "0x0";
const BTC_FEE_RECIPIENT = "0x000001";
const THRESHOLD = 3;

// Helper functions
const log = {
    step: (msg) => console.log("\x1b[33m[STEP]\x1b[0m", msg),
    success: (msg) => console.log("\x1b[32m[SUCCESS]\x1b[0m", msg),
    error: (msg) => console.log("\x1b[31m[ERROR]\x1b[0m", msg)
};

async function setupProvider(network) {
    const networkConfig = NETWORKS[network];
    if (!networkConfig) {
        throw new Error(`Invalid network. Please use 'mainnet', 'testnet', or 'devnet'`);
    }

    log.step(`Using ${networkConfig.name} configuration`);
    return new Provider({ nodeUrl: networkConfig.rpc });
}

async function setupAccount(provider, accountAddress, privateKey) {
    if (!accountAddress || !privateKey) {
        throw new Error("Account address and private key are required");
    }

    log.step("Setting up account...");
    return new Account(provider, accountAddress, privateKey, undefined, constants.TRANSACTION_VERSION.V3);
}

async function declareContracts(account, contractPaths) {
    log.step("Declaring contracts...");

    const declarations = {};
    
    for (const [name, path] of Object.entries(contractPaths)) {
        log.step(`Declaring ${name}...`);
        try {
            const contractClass = json.parse(fs.readFileSync(path.contractClass).toString("ascii"));
            const compiledContractClass = json.parse(fs.readFileSync(path.compiledContractClass).toString("ascii"));
            const declareResponse = await account.declare({
                contract: contractClass,
                casm: compiledContractClass
            });
            
            await account.waitForTransaction(declareResponse.transaction_hash);
            declarations[name] = {
                classHash: declareResponse.class_hash,
                tx: declareResponse.transaction_hash
            };
            
            log.success(`${name} declared with class hash: ${declareResponse.class_hash}`);
        } catch (error) {
            let isAlreadyDeclared = error?.baseError?.data?.execution_error?.includes(" is already declared");
            if (isAlreadyDeclared) {
                log.success(`${name} already declared`);
                let classHash = error?.baseError?.data?.execution_error.match(/Class with hash (0x[a-f0-9]+) is already declared/)?.[1];
                declarations[name] = { classHash };
            } else {
                throw error;
            }
        }
    }

    return declarations;
}

async function deployContracts(account, declarations) {
    log.step("Deploying contracts...");

    const deployments = {};

    // Deploy IBTCToken
    log.step("Deploying IBTCToken...");
    try {
        const tokenDeployResponse = await account.deployContract({
            classHash: declarations.IBTCToken.classHash,
            constructorCalldata: [account.address],
            salt: SALT
        });
        await account.waitForTransaction(tokenDeployResponse.transaction_hash);
        const tokenAddress = tokenDeployResponse.contract_address;
        log.success(`IBTCToken deployed at: ${tokenAddress}`);
        deployments.IBTCToken = {
            address: tokenAddress,
            classHash: declarations.IBTCToken.classHash
        };
    } catch (err) {
        let isAlreadyDeployed = err?.baseError?.data?.execution_error?.includes("contract already deployed at address");
        if (isAlreadyDeployed) {
            let contractAddress = err?.baseError?.data?.execution_error?.match(/contract already deployed at address (0x[a-f0-9]+)/)?.[1];
            console.log(`IBTCToken already deployed at ${contractAddress}`);
            deployments.IBTCToken = {
                address: contractAddress,
                classHash: declarations.IBTCToken.classHash
            };
        } else {
            throw err;
        }
    }

    // Deploy IBTCManager
    log.step("Deploying IBTCManager...");
    try {
        const managerDeployResponse = await account.deployContract({
            classHash: declarations.IBTCManager.classHash,
            constructorCalldata: [
                account.address, // default_admin
                account.address, // ibtc_admin_role
                THRESHOLD,
                deployments.IBTCToken.address,
                BTC_FEE_RECIPIENT
            ],
            salt: SALT
        });
        await account.waitForTransaction(managerDeployResponse.transaction_hash);
        const managerAddress = managerDeployResponse.contract_address;
        log.success(`IBTCManager deployed at: ${managerAddress}`);
        deployments.IBTCManager = {
            address: managerAddress,
            classHash: declarations.IBTCManager.classHash
        };
    } catch (err) {
        let isAlreadyDeployed = err?.baseError?.data?.execution_error?.includes("contract already deployed at address");
        if (isAlreadyDeployed) {
            let contractAddress = err?.baseError?.data?.execution_error?.match(/contract already deployed at address (0x[a-f0-9]+)/)?.[1];
            console.log(`IBTCManager already deployed at ${contractAddress}`);
            deployments.IBTCManager = {
                address: contractAddress,
                classHash: declarations.IBTCManager.classHash
            };
        } else {
            throw err;
        }
    }

    return deployments;
}

async function verifyDeployment(provider, deployments) {
    log.step("Verifying deployments...");

    // Verify IBTCToken
    log.step("Verifying IBTCToken...");
    const tokenContract = new Contract(
        json.parse(fs.readFileSync("../contracts/target/dev/ibtc_cairo_IBTCToken.contract_class.json").toString("ascii")).abi,
        deployments.IBTCToken.address,
        provider
    );
    const tokenName = await tokenContract.name();
    log.success(`IBTCToken name: ${tokenName}`);

    // Verify IBTCManager
    log.step("Verifying IBTCManager...");
    const managerContract = new Contract(
        json.parse(fs.readFileSync("../contracts/target/dev/ibtc_cairo_IBTCManager.contract_class.json").toString("ascii")).abi,
        deployments.IBTCManager.address,
        provider
    );
    const threshold = await managerContract.get_threshold();
    log.success(`IBTCManager threshold: ${threshold}`);
}

async function saveDeployment(network, declarations, deployments) {
    log.step("Saving deployment addresses...");
    
    const deployment = {
        network,
        ibtc_token: {
            address: deployments.IBTCToken.address,
            class_hash: declarations.IBTCToken.classHash
        },
        ibtc_manager: {
            address: deployments.IBTCManager.address,
            class_hash: declarations.IBTCManager.classHash
        },
        timestamp: new Date().toISOString()
    };

    const deploymentPath = path.join(__dirname, `deployment_${network}.json`);
    fs.writeFileSync(deploymentPath, JSON.stringify(deployment, null, 2));
    log.success(`Deployment addresses saved to deployment_${network}.json`);
}

async function main() {
    try {
        // Get command line arguments
        const network = process.argv[2] || "testnet";
        const accountAddress = process.env.STARKNET_ACCOUNT_ADDRESS;
        const privateKey = process.env.STARKNET_PRIVATE_KEY;

        // Setup
        const provider = await setupProvider(network);
        const account = await setupAccount(provider, accountAddress, privateKey);

        // Contract paths
        const contractPaths = {
            IBTCToken: {
                contractClass: path.join(__dirname, "../contracts/target/dev/ibtc_cairo_IBTCToken.contract_class.json"),
                compiledContractClass: path.join(__dirname, "../contracts/target/dev/ibtc_cairo_IBTCToken.compiled_contract_class.json")
            },
            IBTCManager: {
                contractClass: path.join(__dirname, "../contracts/target/dev/ibtc_cairo_IBTCManager.contract_class.json"),
                compiledContractClass: path.join(__dirname, "../contracts/target/dev/ibtc_cairo_IBTCManager.compiled_contract_class.json")
            }
        };

        // Deploy flow
        const declarations = await declareContracts(account, contractPaths);
        const deployments = await deployContracts(account, declarations);
        await verifyDeployment(provider, deployments);
        await saveDeployment(network, declarations, deployments);

        log.success("Deployment completed successfully!");
    } catch (error) {
        log.error(`Deployment failed: ${error.message}`);
        throw error;
    }
}

// Run deployment
main();