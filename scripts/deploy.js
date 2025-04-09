/** @format */

import { Contract, json } from 'starknet';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { log, setupProvider, setupAccount } from './utils.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const __deployments = path.join(__dirname, '../deployments');

// Constants
const SALT = '0x1';
const BTC_FEE_RECIPIENT = 'bcrt1qt2qlxef4nqrkn0xvy0qevvm60pzc40g7a3j50m';
const THRESHOLD = 2;
const ATTESTORS = [
  '0x078662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1',
  '0x049dfb8ce986e21d354ac93ea65e6a11f639c1934ea253e5ff14ca62eca0f38e',
  '0x04f348398f859a55a0c80b1446c5fdc37edb3a8478a32f10764659fc241027d3',
];

async function declareContracts(account, contractPaths) {
  log.step('Declaring contracts...');

  const declarations = {};

  for (const [name, path] of Object.entries(contractPaths)) {
    log.step(`Declaring ${name}...`);
    try {
      const contractClass = json.parse(fs.readFileSync(path.contractClass).toString('ascii'));
      const compiledContractClass = json.parse(fs.readFileSync(path.compiledContractClass).toString('ascii'));
      const declareResponse = await account.declare({
        contract: contractClass,
        casm: compiledContractClass,
      });

      await account.waitForTransaction(declareResponse.transaction_hash);
      declarations[name] = {
        classHash: declareResponse.class_hash,
        tx: declareResponse.transaction_hash,
      };

      log.success(`${name} declared with class hash: ${declareResponse.class_hash}`);
    } catch (error) {
      let isAlreadyDeclared = error?.baseError?.data?.execution_error?.includes(' is already declared');
      if (isAlreadyDeclared) {
        log.success(`${name} already declared`);
        let classHash = error?.baseError?.data?.execution_error.match(
          /Class with hash (0x[a-f0-9]+) is already declared/
        )?.[1];
        declarations[name] = { classHash };
      } else {
        throw error;
      }
    }
  }
  declarations.timestamp = new Date().toISOString();
  return declarations;
}

async function deployContracts(account, declarations, provider) {
  log.step('Deploying contracts...');

  const deployments = {};

  // Deploy IBTCToken
  log.step('Deploying IBTCToken...');
  try {
    const tokenDeployResponse = await account.deployContract({
      classHash: declarations.IBTCToken.classHash,
      constructorCalldata: [account.address], // default owner
      salt: SALT,
    });
    await account.waitForTransaction(tokenDeployResponse.transaction_hash);
    const tokenAddress = tokenDeployResponse.contract_address;
    log.success(`IBTCToken deployed at: ${tokenAddress}`);
    deployments.IBTCToken = {
      address: tokenAddress,
      classHash: declarations.IBTCToken.classHash,
    };
  } catch (err) {
    let isAlreadyDeployed = err?.baseError?.data?.execution_error?.includes('contract already deployed at address');
    if (isAlreadyDeployed) {
      let contractAddress = err?.baseError?.data?.execution_error?.match(
        /contract already deployed at address (0x[a-f0-9]+)/
      )?.[1];
      console.log(`IBTCToken already deployed at ${contractAddress}`);
      deployments.IBTCToken = {
        address: contractAddress,
        classHash: declarations.IBTCToken.classHash,
      };
    } else {
      throw err;
    }
  }

  // Deploy IBTCManager
  log.step('Deploying IBTCManager...');
  try {
    const managerDeployResponse = await account.deployContract({
      classHash: declarations.IBTCManager.classHash,
      constructorCalldata: [
        account.address, // default_admin
        account.address, // ibtc_admin_role
        THRESHOLD,
        deployments.IBTCToken.address,
        BTC_FEE_RECIPIENT,
        // Add attestors array (using account address as placeholder)
        // First parameter is the length of the array
        ATTESTORS.length, // Number of attestors
        // Then each attestor address
        ...ATTESTORS,
      ],
      salt: SALT,
    });
    await account.waitForTransaction(managerDeployResponse.transaction_hash);
    const managerAddress = managerDeployResponse.contract_address;
    log.success(`IBTCManager deployed at: ${managerAddress}`);
    deployments.IBTCManager = {
      address: managerAddress,
      classHash: declarations.IBTCManager.classHash,
    };
    deployments.timestamp = new Date().toISOString();
  } catch (err) {
    let isAlreadyDeployed = err?.baseError?.data?.execution_error?.includes('contract already deployed at address');
    if (isAlreadyDeployed) {
      let contractAddress = err?.baseError?.data?.execution_error?.match(
        /contract already deployed at address (0x[a-f0-9]+)/
      )?.[1];
      console.log(`IBTCManager already deployed at ${contractAddress}`);
      deployments.IBTCManager = {
        address: contractAddress,
        classHash: declarations.IBTCManager.classHash,
      };
    } else {
      throw err;
    }
  }

  // transfer ownership of IBTCToken to IBTCManager
  log.step('Transferring ownership of IBTCToken to IBTCManager...');
  try {
    const tokenContract = new Contract(
      json.parse(
        fs.readFileSync('../contracts/target/dev/ibtc_cairo_IBTCToken.contract_class.json').toString('ascii')
      ).abi,
      deployments.IBTCToken.address,
      provider
    );
    const transferOwnershipCall = tokenContract.populate('transfer_ownership', {
      new_owner: deployments.IBTCManager.address,
    });
    const { transaction_hash } = await account.execute(transferOwnershipCall);
    await provider.waitForTransaction(transaction_hash);
    log.success(`Ownership transferred, tx: ${transaction_hash}`);
  } catch (err) {
    log.error(`Failed to transfer ownership of IBTCToken to IBTCManager: ${err.message}`);
  }

  return deployments;
}

async function verifyDeployment(provider, deployments) {
  log.step('Verifying deployments...');

  // Verify IBTCToken
  log.step('Verifying IBTCToken...');
  const tokenContract = new Contract(
    json.parse(
      fs.readFileSync('../contracts/target/dev/ibtc_cairo_IBTCToken.contract_class.json').toString('ascii')
    ).abi,
    deployments.IBTCToken.address,
    provider
  );
  const tokenName = await tokenContract.name();
  log.success(`IBTCToken name: ${tokenName}`);

  // Verify IBTCManager
  log.step('Verifying IBTCManager...');
  const managerContract = new Contract(
    json.parse(
      fs.readFileSync('../contracts/target/dev/ibtc_cairo_IBTCManager.contract_class.json').toString('ascii')
    ).abi,
    deployments.IBTCManager.address,
    provider
  );
  const threshold = await managerContract.get_threshold();
  log.success(`IBTCManager threshold: ${threshold}`);

  // Verify IBTCManager is the owner of IBTCToken
  log.step('Verifying IBTCManager is the owner of IBTCToken...');
  const tokenOwner = await tokenContract.owner();
  log.success(`IBTCToken owner: ${tokenOwner}, IBTCManager: ${deployments.IBTCManager.address}`);
}

async function saveDeployment(network, deployments, declarations) {
  log.step('Saving declarations...');
  const declarationPath = path.join(__deployments, `declaration_${network}.json`);
  fs.writeFileSync(declarationPath, JSON.stringify(declarations, null, 2));
  log.success(`Declarations saved to ${declarationPath}`);

  log.step('Saving deployment addresses...');
  const deploymentPath = path.join(__deployments, `deployment_${network}.json`);
  fs.writeFileSync(deploymentPath, JSON.stringify(deployments, null, 2));
  log.success(`Deployment addresses saved to ${deploymentPath}`);
}

async function main() {
  try {
    // Get command line arguments
    const network = process.argv[2] || 'testnet';
    const accountAddress = process.env.STARKNET_ACCOUNT_ADDRESS;
    const privateKey = process.env.STARKNET_PRIVATE_KEY;

    console.log(`Setting up provider for network: ${network}`);
    console.log(`Setting up account with address: ${accountAddress}`);
    console.log(`Setting up private key: ${privateKey}`);

    // Setup
    const provider = await setupProvider(network);
    const account = await setupAccount(provider, accountAddress, privateKey);

    // Contract paths
    const contractPaths = {
      IBTCToken: {
        contractClass: path.join(__dirname, '../contracts/target/dev/ibtc_cairo_IBTCToken.contract_class.json'),
        compiledContractClass: path.join(
          __dirname,
          '../contracts/target/dev/ibtc_cairo_IBTCToken.compiled_contract_class.json'
        ),
      },
      IBTCManager: {
        contractClass: path.join(__dirname, '../contracts/target/dev/ibtc_cairo_IBTCManager.contract_class.json'),
        compiledContractClass: path.join(
          __dirname,
          '../contracts/target/dev/ibtc_cairo_IBTCManager.compiled_contract_class.json'
        ),
      },
      IBTCManagerMock: {
        contractClass: path.join(__dirname, '../contracts/target/dev/ibtc_cairo_IBTCManagerMock.contract_class.json'),
        compiledContractClass: path.join(
          __dirname,
          '../contracts/target/dev/ibtc_cairo_IBTCManagerMock.compiled_contract_class.json'
        ),
      },
    };

    // Deploy flow
    const declarations = await declareContracts(account, contractPaths);
    const deployments = await deployContracts(account, declarations, provider);
    await verifyDeployment(provider, deployments);
    await saveDeployment(network, deployments, declarations);

    log.success('Deployment completed successfully!');
  } catch (error) {
    log.error(`Deployment failed: ${error.message}`);
    throw error;
  }
}

// Run deployment
main();
