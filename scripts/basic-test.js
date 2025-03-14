import fs from "fs";
import path from "path";
import { Contract, json } from "starknet";
import { fileURLToPath } from "url";
import { log, setupProvider, setupAccount } from "./utils.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getDeployedContracts(network, provider) {
    const deploymentPath = path.join(__dirname, `deployment_${network}.json`);
    const deployments = JSON.parse(fs.readFileSync(deploymentPath).toString("ascii"));

    const tokenContract = new Contract(
        json.parse(fs.readFileSync("../contracts/target/dev/ibtc_cairo_IBTCToken.contract_class.json").toString("ascii")).abi,
        deployments.IBTCToken.address,
        provider
    );
    const managerContract = new Contract(
        json.parse(fs.readFileSync("../contracts/target/dev/ibtc_cairo_IBTCManager.contract_class.json").toString("ascii")).abi,
        deployments.IBTCManager.address,
        provider
    );
    return {
        IBTCToken: tokenContract,
        IBTCManager: managerContract
    }
}

async function doBasicTests() {
    // Get command line arguments
    const network = process.argv[2] || "testnet";
    const accountAddress = process.env.STARKNET_ACCOUNT_ADDRESS;
    const privateKey = process.env.STARKNET_PRIVATE_KEY;

    // Setup
    const provider = await setupProvider(network);
    const account = await setupAccount(provider, accountAddress, privateKey);

    log.step("Doing basic tests...");

    const {
        IBTCToken: tokenContract,
        IBTCManager: managerContract
    } = getDeployedContracts(network, provider);

    // Test IBTCManager upgrade
    log.step("Testing IBTCManager upgrade...");
    const declarationPath = path.join(__dirname, `declaration_${network}.json`);
    const declarations = JSON.parse(fs.readFileSync(declarationPath).toString("ascii"));

    const managerContractClassHash = declarations.IBTCManager.classHash;
    const managerMockContractClassHash = declarations.IBTCManagerMock.classHash;

    const upgradeCall = managerContract.populate("upgrade", {
        new_class_hash: managerMockContractClassHash
    });
    const { transaction_hash } = await account.execute(upgradeCall);
    await provider.waitForTransaction(transaction_hash);
    log.success(`IBTCManager logic upgraded, tx: ${transaction_hash}`);

    // rollback the logic
    const rollbackCall = managerContract.populate("upgrade", {
        new_class_hash: managerContractClassHash
    });
    const { transaction_hash: rollbackTransactionHash } = await account.execute(rollbackCall);
    await provider.waitForTransaction(rollbackTransactionHash);
    log.success(`IBTCManager logic rolled back, tx: ${rollbackTransactionHash}`);
}

doBasicTests();