pub const IBTC_ADMIN_ROLE: felt252 = selector!("IBTC_ADMIN_ROLE");
pub const WHITELISTED_CONTRACT: felt252 = selector!("WHITELISTED_CONTRACT");
pub const APPROVED_SIGNER: felt252 = selector!("APPROVED_SIGNER");
pub const DEFAULT_ADMIN_ROLE: felt252 = selector!("DEFAULT_ADMIN_ROLE");

#[starknet::contract]
pub mod IBTCManager {
    use core::iter::IntoIterator;
    use openzeppelin::access::accesscontrol::AccessControlComponent;
    use openzeppelin::access::accesscontrol::interface::IAccessControl;
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::security::PausableComponent;
    use openzeppelin::upgrades::UpgradeableComponent;
    use openzeppelin::upgrades::interface::IUpgradeable;
    use starknet::{ClassHash, get_caller_address};
    use crate::ibtc_manager::{IBTC_ADMIN_ROLE, WHITELISTED_CONTRACT, APPROVED_SIGNER, DEFAULT_ADMIN_ROLE};
    use core::starknet::info::get_execution_info;
    use core::panic_with_felt252;
    use core::poseidon::poseidon_hash_span;
    use core::starknet::contract_address_to_felt252;
    use crate::event::{CreateIBTCVault, SetStatusFunded, SetStatusPending, Withdraw, SetThreshold, Mint, Burn, WhitelistAddress, UnwhitelistAddress, SetMinimumDeposit, SetMaximumDeposit, SetBtcMintFeeRate, SetBtcRedeemFeeRate, SetBtcFeeRecipient, SetWhitelistingEnabled, TransferTokenContractOwnership, SetPorEnabled, SetIBtcPorFeed, GrantSignerRole, RevokeSignerRole};
    
    use starknet::storage::{Mutable, MutableVecTrait, StorageAsPath, StoragePath, Vec, VecTrait};
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePathEntry};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    use crate::ibtc_library::{IBTCVault, IBTCVaultStatus};
    use starknet::eth_address::EthAddress;
    use starknet::secp256k1::Secp256k1Point;
    use starknet::secp256_trait::{Signature, signature_from_vrs, recover_public_key};
    use starknet::eth_signature::{verify_eth_signature, public_key_point_to_eth_address};
    use crate::interface::{IBTCTokenABIDispatcher, IBTCTokenABIDispatcherTrait};
    use crate::interface::{IAccountDispatcher, IAccountDispatcherTrait};

    use starknet::info::{get_block_number};
    use starknet::syscalls::get_block_hash_syscall;
    use starknet::{SyscallResult, SyscallResultTrait, ContractAddress};
    use starknet::info::get_block_info;

    use crate::utils::{AttestorMultisigTx, OffChainMessageHashAttestorMultisigTx};

    component!(path: AccessControlComponent, storage: accesscontrol, event: AccessControlEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);
    component!(path: PausableComponent, storage: pausable, event: PausableEvent);

    // AccessControl
    impl AccessControlInternalImpl = AccessControlComponent::InternalImpl<ContractState>;

    // SRC5
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;

    // Upgradeable
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl PausableImpl = PausableComponent::PausableImpl<ContractState>;
    impl PausableInternalImpl = PausableComponent::InternalImpl<ContractState>;

    // Define storage variables
    #[storage]
    struct Storage {
        #[substorage(v0)]
        accesscontrol: AccessControlComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        pausable: PausableComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
        threshold: u16,
        minimum_threshold: u16,
        index: u128,
        tss_commitment: felt252,
        ibtc_token: ContractAddress,
        minimum_deposit: u256,
        maximum_deposit: u256,
        whitelisting_enabled: bool,
        whitelisted_addresses: Map<ContractAddress, bool>,
        btc_mint_fee_rate: u16,
        btc_redeem_fee_rate: u16,
        btc_fee_recipient: ByteArray,
        seen_signers: Map<(ContractAddress, felt252), bool>,
        ibtc_vaults: Map<u128, IBTCVault>,
        ibtc_vault_ids_by_uuid: Map<felt252, u128>,
        user_vaults: Map<ContractAddress, Vec<felt252>>,
        signer_count: u16,
        por_enabled: bool,
        total_value_minted: u256,
        attestor_group_pubkey: ByteArray,
        ibtc_por_feed: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Debug {
        message: felt252,
    }

    // Define events
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccessControlEvent: AccessControlComponent::Event,
        #[flat]
        PausableEvent: PausableComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
        CreateIBTCVault: CreateIBTCVault,
        SetStatusFunded: SetStatusFunded,
        SetStatusPending: SetStatusPending,
        Withdraw: Withdraw,
        SetThreshold: SetThreshold,
        Mint: Mint,
        Burn: Burn,
        WhitelistAddress: WhitelistAddress,
        UnwhitelistAddress: UnwhitelistAddress,
        SetMinimumDeposit: SetMinimumDeposit,
        SetMaximumDeposit: SetMaximumDeposit,
        SetBtcMintFeeRate: SetBtcMintFeeRate,
        SetBtcRedeemFeeRate: SetBtcRedeemFeeRate,
        SetBtcFeeRecipient: SetBtcFeeRecipient,
        SetWhitelistingEnabled: SetWhitelistingEnabled,
        TransferTokenContractOwnership: TransferTokenContractOwnership,
        SetPorEnabled: SetPorEnabled,
        SetIBtcPorFeed: SetIBtcPorFeed,
        GrantSignerRole: GrantSignerRole,
        RevokeSignerRole: RevokeSignerRole,
        Debug: Debug,
    }

    pub mod Errors {
        pub const THRESHOLD_TOO_LOW: felt252 = 'Threshold too low';
        pub const NOT_ENOUGH_SIGNATURES: felt252 = 'Not enough signatures';
        pub const DUPLICATE_SIGNATURE: felt252 = 'Duplicate signature';
        pub const INVALID_SIGNER: felt252 = 'Invalid signer';
        pub const NOT_WHITELISTED: felt252 = 'Not whitelisted';
        pub const IBTC_VAULT_NOT_FOUND: felt252 = 'IBTC vault not found';
        pub const INVALID_RANGE: felt252 = 'Invalid range';
        pub const INCOMPATIBLE_ROLE: felt252 = 'Incompatible role';
        pub const IBTC_VAULT_NOT_PENDING: felt252 = 'IBTC vault not pending';
        pub const UNDER_COLLATERALIZED: felt252 = 'Under collateralized';
        pub const DEPOSIT_TOO_LARGE: felt252 = 'Deposit too large';
        pub const DEPOSIT_TOO_SMALL: felt252 = 'Deposit too small';
        pub const NOT_APPROVED_SUBMITTER: felt252 = 'Not approved submitter';
        pub const IBTC_VAULT_NOT_READY_OR_FUNDED: felt252 = 'IBTC vault not ready or funded';
        pub const NOT_OWNER: felt252 = 'Not owner';
        pub const IBTC_VAULT_NOT_FUNDED: felt252 = 'IBTC vault not funded';
        pub const INSUFFICIENT_TOKEN_BALANCE: felt252 = 'Insufficient token balance';
        pub const INSUFFICIENT_MINTED_BALANCE: felt252 = 'Insufficient minted balance';
        pub const THRESHOLD_MINIMUM_REACHED: felt252 = 'Threshold minimum reached';
        pub const NO_SIGNER_RENOUNCEMENT: felt252 = 'No signer renouncement';
        pub const INVALID_SIGNATURE_LENGTH: felt252 = 'Invalid signature length';
        pub const INVALID_SIGNATURE: felt252 = 'Invalid signature';
    }

    // Constructor to initialize roles and other settings
    #[constructor]
    fn constructor(
        ref self: ContractState,
        default_admin: ContractAddress,
        ibtc_admin_role: ContractAddress,
        threshold: u16,
        token_contract: ContractAddress,
        btc_fee_recipient_to_set: ByteArray,
    ) {
        self.accesscontrol.initializer();
        // Grant roles
        self.accesscontrol._grant_role(DEFAULT_ADMIN_ROLE, default_admin);
        self.accesscontrol._grant_role(IBTC_ADMIN_ROLE, ibtc_admin_role);
        self.accesscontrol.set_role_admin(DEFAULT_ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        self.accesscontrol.set_role_admin(IBTC_ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        self.accesscontrol.set_role_admin(WHITELISTED_CONTRACT, DEFAULT_ADMIN_ROLE);
        self.accesscontrol.set_role_admin(APPROVED_SIGNER, DEFAULT_ADMIN_ROLE);

        // Set thresholds
        self.minimum_threshold.write(2);
        if threshold < self.minimum_threshold.read() {
            panic_with_felt252(Errors::THRESHOLD_TOO_LOW);
        }
        self.threshold.write(threshold);
        // Initialize other storage variables
        self.index.write(0);
        self.tss_commitment.write(0);
        self.ibtc_token.write(token_contract);
        self.minimum_deposit.write(1_000_000_u256); // 0.01 BTC
        self.maximum_deposit.write(500_000_000_u256); // 5 BTC
        self.whitelisting_enabled.write(true);
        self.btc_mint_fee_rate.write(12); // 0.12% BTC fee
        self.btc_redeem_fee_rate.write(15); // 0.15% BTC fee
        self.btc_fee_recipient.write(btc_fee_recipient_to_set);
        self.por_enabled.write(false);
        self.total_value_minted.write(0);
    }

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn get_previous_block_hash(ref self: ContractState) -> Option<felt252> {
            // Retrieve the current block number
            let current_block_number = get_block_number();
    
            // Ensure the current block number is greater than zero
            if current_block_number > 0 {
                // Calculate the previous block number
                // https://book.cairo-lang.org/appendix-08-system-calls.html?highlight=get_block_hash_syscall#get_block_hash
                // can only get block hash within the range of [first_v0_12_0_block, current_block - 10]
                let previous_block_number = current_block_number - 10;
                self.emit(Debug{message: previous_block_number.into()});
    
                // Retrieve the hash of the previous block
                Option::Some(get_block_hash_syscall(previous_block_number).unwrap_syscall())
            } else {
                // No previous block exists (current block is the genesis block)
                Option::None
            }
        }

        fn _generate_uuid(
            ref self: ContractState,
            sender: ContractAddress,
            nonce: u128,
            previous_block_hash: felt252
        ) -> felt252 {
            // Retrieve the current chain ID
            let chain_id = get_execution_info().tx_info.chain_id;
        
            // Prepare the data array for hashing
            let data = [
                sender.into(),
                nonce.into(),
                previous_block_hash,
                chain_id,
            ];
        
            // Compute the Poseidon hash over the data array
            poseidon_hash_span(data.span())
        }

        fn _attestor_multisig_is_valid(
            ref self: ContractState,
            message: AttestorMultisigTx,
            signatures: Span<(ContractAddress, Array<felt252>)>
        ) {
            let threshold = self.threshold.read();
            assert(signatures.len() >= threshold.into(), Errors::NOT_ENOUGH_SIGNATURES);
            for (attestor, signature) in signatures {
                let message_hash = message.get_message_hash(*attestor);
                let valid_length = signature.len() == 2;
                if !valid_length {
                    panic_with_felt252(Errors::INVALID_SIGNATURE_LENGTH);
                }
                let is_valid_signature = IAccountDispatcher { contract_address: *attestor }
                    .is_valid_signature(message_hash, signature.clone());
                // println!("is_valid_signature: {:?}", is_valid_signature);
                assert(is_valid_signature == 'VALID', Errors::INVALID_SIGNATURE);
                assert(self.accesscontrol.has_role(APPROVED_SIGNER, *attestor), Errors::INVALID_SIGNER);
                self._check_signer_unique(*attestor, message_hash);
            }
        }

        fn _check_signer_unique(
            ref self: ContractState,
            attestor_pub_key: ContractAddress,
            message_hash: felt252,
        ) {
            assert(!self.seen_signers.read((attestor_pub_key, message_hash)), Errors::DUPLICATE_SIGNATURE);
            self.seen_signers.write((attestor_pub_key, message_hash), true);
        }

        fn _mint_tokens(
            ref self: ContractState,
            to: ContractAddress,
            amount: u256,
        ) {
            let ibtc_token = self.ibtc_token.read();
            let ibtc_token_dispatcher = IBTCTokenABIDispatcher { contract_address: ibtc_token };
            ibtc_token_dispatcher.mint(to, amount);
            self.emit(Mint{to, amount});
        }

        fn _burn_tokens(
            ref self: ContractState,
            from: ContractAddress,
            amount: u256,
        ) {
            let ibtc_token = self.ibtc_token.read();
            let ibtc_token_dispatcher = IBTCTokenABIDispatcher { contract_address: ibtc_token };
            ibtc_token_dispatcher.burn_from(from, amount);
            self.emit(Burn{from, amount});
        }

        fn _only_whitelisted(self: @ContractState) {
            let account = get_caller_address();
            let whitelisting_enabled = self.whitelisting_enabled.read();
            if (whitelisting_enabled && !self.whitelisted_addresses.read(account)) {
                panic_with_felt252(Errors::NOT_WHITELISTED);
            }
        }

        fn _only_vault_creator(self: @ContractState, uuid: felt252) {
            let ibtc_idx = self.ibtc_vault_ids_by_uuid.read(uuid);
            let ibtc = self.ibtc_vaults.read(ibtc_idx);
            let creator = ibtc.creator;
            let caller = get_caller_address();
            assert(creator == caller, Errors::NOT_OWNER);
        }

        fn _has_any_roles(self: @ContractState, account: ContractAddress) -> bool {
            self.accesscontrol.has_role(IBTC_ADMIN_ROLE, account) ||
            self.accesscontrol.has_role(WHITELISTED_CONTRACT, account) ||
            self.accesscontrol.has_role(APPROVED_SIGNER, account)
        }

        fn _check_mint(self: @ContractState, amount: u256, current_total_minted: u256) -> bool {
            if amount == 0 {
                return false;
            }

            let proposed_total_value_minted = current_total_minted + amount;
            self._check_por(proposed_total_value_minted)
        }

        fn _check_por(self: @ContractState, proposed_total_value_minted: u256) -> bool {
            if (!self.por_enabled.read()) {
                return true;
            }

            // TODO: Implement POR
            true
        }
    }

    #[generate_trait]
    #[abi(per_item)]
    impl ExternalImpl of ExternalTrait {
        #[external(v0)]
        fn pause_contract(ref self: ContractState) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.pausable.pause();
        }

        #[external(v0)]
        fn unpause_contract(ref self: ContractState) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.pausable.unpause();
        }

        #[external(v0)]
        fn setup_vault(ref self: ContractState) -> felt252 {
            self.pausable.assert_not_paused();
            self._only_whitelisted();

            let _uuid = self._generate_uuid(get_caller_address(), self.index.read(), self.get_previous_block_hash().unwrap());
            let ibtc = IBTCVault {
                uuid: _uuid,
                protocol_contract: get_caller_address(),
                value_locked: 0,
                value_minted: 0,
                timestamp: get_block_info().block_timestamp,
                creator: get_caller_address(),
                status: IBTCVaultStatus::READY.into(),
                funding_tx_id: 0.into(),
                closing_tx_id: 0.into(),
                btc_fee_recipient: self.btc_fee_recipient.read().into(),
                btc_mint_fee_basis_points: self.btc_mint_fee_rate.read().into(),
                btc_redeem_fee_basis_points: self.btc_redeem_fee_rate.read().into(),
                taproot_pubkey: "",
                wd_tx_id: 0.into(),
            };
            self.ibtc_vaults.write(self.index.read(), ibtc);
            // println!("new uuid: {:?}", _uuid);

            self.emit(CreateIBTCVault{uuid: _uuid, creator: get_caller_address(), timestamp: get_block_info().block_timestamp});

            self.ibtc_vault_ids_by_uuid.write(_uuid, self.index.read());
            self.user_vaults.entry(get_caller_address()).append().write(_uuid);
            self.index.write(self.index.read() + 1);

            _uuid
        }

        #[external(v0)]
        fn set_status_funded(ref self: ContractState, uuid: felt252, btc_tx_id: u256, signatures: Span<(ContractAddress, Array<felt252>)>, new_value_locked: u256) {
            self.pausable.assert_not_paused();
            self.accesscontrol.assert_only_role(APPROVED_SIGNER);

            let message = AttestorMultisigTx {
                uuid,
                btc_tx_id,
                tx_type: 'set-status-funded',
                amount: new_value_locked,
            };
            self._attestor_multisig_is_valid(message, signatures);

            let ibtc_idx = self.ibtc_vault_ids_by_uuid.entry(uuid).read();
            let mut ibtc = self.ibtc_vaults.entry(ibtc_idx).read();
            let creator = ibtc.creator;

            if ibtc.uuid == 0 {
                panic_with_felt252(Errors::IBTC_VAULT_NOT_FOUND);
            }
            if ibtc.status != IBTCVaultStatus::AUX_STATE_1.into() {
                panic_with_felt252(Errors::IBTC_VAULT_NOT_PENDING);
            }

            if new_value_locked < ibtc.value_minted {
                panic_with_felt252(Errors::UNDER_COLLATERALIZED);
            }
            let amount_to_mint = new_value_locked - ibtc.value_minted;

            let mut amount_to_lock_diff = 0;
            if new_value_locked > ibtc.value_locked {
                amount_to_lock_diff = new_value_locked - ibtc.value_locked;
            } else {
                amount_to_lock_diff = ibtc.value_locked - new_value_locked;
            }
            if amount_to_lock_diff > self.maximum_deposit.read() {
                panic_with_felt252(Errors::DEPOSIT_TOO_LARGE);
            }
            if amount_to_lock_diff < self.minimum_deposit.read() {
                panic_with_felt252(Errors::DEPOSIT_TOO_SMALL);
            }

            ibtc.funding_tx_id = btc_tx_id;
            ibtc.wd_tx_id = 0;
            ibtc.status = IBTCVaultStatus::FUNDED.into();

            ibtc.value_locked = new_value_locked;
            ibtc.value_minted = new_value_locked;
            self.ibtc_vaults.entry(ibtc_idx).write(ibtc);
            
            if self._check_mint(amount_to_mint, self.total_value_minted.read()) {
                self.total_value_minted.write(self.total_value_minted.read() + amount_to_mint);
                self._mint_tokens(creator, amount_to_mint);
            }

            self.emit(SetStatusFunded{uuid, btc_tx_id, creator, new_value_locked, amount_to_mint});
        }

        #[external(v0)]
        fn set_status_pending(ref self: ContractState, uuid: felt252, wdtx_id: u256, signatures: Span<(ContractAddress, Array<felt252>)>, taproot_pubkey: ByteArray, new_value_locked: u256) {
            self.pausable.assert_not_paused();
            self.accesscontrol.assert_only_role(APPROVED_SIGNER);

            let message = AttestorMultisigTx {
                uuid,
                btc_tx_id: wdtx_id,
                tx_type: 'set-status-pending',
                amount: new_value_locked,
            };
            self._attestor_multisig_is_valid(message, signatures);

            let ibtc_vault_idx = self.ibtc_vault_ids_by_uuid.entry(uuid).read();
            let mut ibtc_vault = self.ibtc_vaults.entry(ibtc_vault_idx).read();
            let creator = ibtc_vault.creator;

            if ibtc_vault.uuid == 0 {
                panic_with_felt252(Errors::IBTC_VAULT_NOT_FOUND);
            }
            if ibtc_vault.status != IBTCVaultStatus::READY.into() &&
                ibtc_vault.status != IBTCVaultStatus::FUNDED.into() {
                panic_with_felt252(Errors::IBTC_VAULT_NOT_READY_OR_FUNDED);
            }

            ibtc_vault.status = IBTCVaultStatus::AUX_STATE_1.into();
            ibtc_vault.wd_tx_id = wdtx_id;
            ibtc_vault.taproot_pubkey = taproot_pubkey.clone();
            self.ibtc_vaults.entry(ibtc_vault_idx).write(ibtc_vault);

            self.emit(SetStatusPending{uuid, btc_tx_id: wdtx_id, creator, taproot_pubkey, new_value_locked});
        }

        #[external(v0)]
        fn withdraw(ref self: ContractState, uuid: felt252, amount: u256) {
            self._only_vault_creator(uuid);
            self.pausable.assert_not_paused();
            
            let ibtc_vault_idx = self.ibtc_vault_ids_by_uuid.entry(uuid).read();
            let mut ibtc_vault = self.ibtc_vaults.entry(ibtc_vault_idx).read();
            let creator = ibtc_vault.creator;

            if ibtc_vault.uuid == 0 {
                panic_with_felt252(Errors::IBTC_VAULT_NOT_FOUND);
            }
            if ibtc_vault.status != IBTCVaultStatus::FUNDED.into() {
                panic_with_felt252(Errors::IBTC_VAULT_NOT_FUNDED);
            }

            let ibtc_token = self.ibtc_token.read();
            let ibtc_token_dispatcher = IBTCTokenABIDispatcher { contract_address: ibtc_token };
            if amount > ibtc_token_dispatcher.balance_of(creator) {
                panic_with_felt252(Errors::INSUFFICIENT_TOKEN_BALANCE);
            }
            if amount > ibtc_vault.value_minted {
                panic_with_felt252(Errors::INSUFFICIENT_MINTED_BALANCE);
            }

            ibtc_vault.value_minted = ibtc_vault.value_minted - amount;
            self.ibtc_vaults.entry(ibtc_vault_idx).write(ibtc_vault);
            self.total_value_minted.write(self.total_value_minted.read() - amount);
            self._burn_tokens(creator, amount);

            self.emit(Withdraw{uuid, amount, sender: get_caller_address()});
        }

        #[external(v0)]
        fn get_ibtc_vault(self: @ContractState, uuid: felt252) -> IBTCVault {
            let ibtc_vault_idx = self.ibtc_vault_ids_by_uuid.read(uuid);
            let ibtc_vault = self.ibtc_vaults.read(ibtc_vault_idx);
            if (ibtc_vault.uuid == 0 || ibtc_vault.uuid != uuid) {
                panic_with_felt252(Errors::IBTC_VAULT_NOT_FOUND);
            }
            ibtc_vault
        }

        #[external(v0)]
        fn get_ibtc_vault_by_index(self: @ContractState, index: u128) -> IBTCVault {
            self.ibtc_vaults.entry(index).read()
        }

        #[external(v0)]
        fn get_all_ibtcs(self: @ContractState, start_index: u128, end_index: u128) -> Array<IBTCVault> {
            if (start_index > end_index) {
                panic_with_felt252(Errors::INVALID_RANGE);
            }
            let mut ibtc_subset = ArrayTrait::<IBTCVault>::new();
            for i in start_index..end_index {
                ibtc_subset.append(self.ibtc_vaults.entry(i).read());
            };
            ibtc_subset
        }

        #[external(v0)]
        fn get_vault(self: @ContractState, uuid: felt252) -> IBTCVault {
            self.get_ibtc_vault(uuid)
        }

        #[external(v0)]
        fn get_all_vault_uuids_for_address(self: @ContractState, owner: ContractAddress) -> Array<felt252> {
            let mut vault_ids = array![];
            for i in 0..self.user_vaults.entry(owner).len() {
                vault_ids.append(self.user_vaults.entry(owner).at(i).read());
            };
            vault_ids
        }

        #[external(v0)]
        fn get_all_vaults_for_address(self: @ContractState, owner: ContractAddress) -> Array<IBTCVault> {
            let uuids = self.get_all_vault_uuids_for_address(owner);
            let mut vaults = array![];
            for uuid in uuids {
                vaults.append(self.get_vault(uuid));
            };
            vaults
        }

        #[external(v0)]
        fn get_user_vaults(self: @ContractState, owner: ContractAddress) -> Span<felt252> {
            let mut uuids = array![];
            for i in 0..self.user_vaults.entry(owner).len() {
                uuids.append(self.user_vaults.entry(owner).at(i).read());
            };
            uuids.span()
        }

        #[external(v0)]
        fn is_whitelisted(self: @ContractState, account: ContractAddress) -> bool {
            self.whitelisted_addresses.entry(account).read()
        }

        #[external(v0)]
        fn get_threshold(self: @ContractState) -> u16 {
            self.threshold.read()
        }

        #[external(v0)]
        fn get_minimum_threshold(self: @ContractState) -> u16 {
            self.minimum_threshold.read()
        }

        #[external(v0)]
        fn get_signer_count(self: @ContractState) -> u16 {
            self.signer_count.read()
        }

        #[external(v0)]
        fn get_whitelisting_enabled(self: @ContractState) -> bool {
            self.whitelisting_enabled.read()
        }

        #[external(v0)]
        fn get_btc_mint_fee_rate(self: @ContractState) -> u16 {
            self.btc_mint_fee_rate.read()
        }

        #[external(v0)]
        fn get_btc_redeem_fee_rate(self: @ContractState) -> u16 {
            self.btc_redeem_fee_rate.read()
        }

        #[external(v0)]
        fn get_btc_fee_recipient(self: @ContractState) -> ByteArray {
            self.btc_fee_recipient.read()
        }

        #[external(v0)]
        fn get_attestor_group_pubkey(self: @ContractState) -> ByteArray {
            self.attestor_group_pubkey.read()
        }

        #[external(v0)]
        fn get_minimum_deposit(self: @ContractState) -> u256 {
            self.minimum_deposit.read()
        }

        #[external(v0)]
        fn get_maximum_deposit(self: @ContractState) -> u256 {
            self.maximum_deposit.read()
        }

        #[external(v0)]
        fn get_tss_commitment(self: @ContractState) -> felt252 {
            self.tss_commitment.read()
        }

        // setters
        #[external(v0)]
        fn set_threshold(ref self: ContractState, new_threshold: u16) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            if new_threshold < self.minimum_threshold.read() {
                panic_with_felt252(Errors::THRESHOLD_TOO_LOW);
            }
            self.threshold.write(new_threshold);
            self.emit(SetThreshold{new_threshold});
        }

        #[external(v0)]
        fn set_tss_commitment(ref self: ContractState, commitment: felt252) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.tss_commitment.write(commitment);
        }

        #[external(v0)]
        fn set_attestor_group_pubkey(ref self: ContractState, pubkey: ByteArray) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.attestor_group_pubkey.write(pubkey);
        }

        #[external(v0)]
        fn whitelist_address(ref self: ContractState, account: ContractAddress) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.whitelisted_addresses.entry(account).write(true);
            self.emit(WhitelistAddress{address_to_whitelist: account});
        }

        #[external(v0)]
        fn unwhitelist_address(ref self: ContractState, account: ContractAddress) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.whitelisted_addresses.entry(account).write(false);
            self.emit(UnwhitelistAddress{address_to_unwhitelist: account});
        }

        #[external(v0)]
        fn set_minimum_deposit(ref self: ContractState, amount: u256) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.minimum_deposit.write(amount);
            self.emit(SetMinimumDeposit{new_minimum_deposit: amount});
        }

        #[external(v0)]
        fn set_maximum_deposit(ref self: ContractState, amount: u256) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.maximum_deposit.write(amount);
            self.emit(SetMaximumDeposit{new_maximum_deposit: amount});
        }

        #[external(v0)]
        fn set_btc_mint_fee_rate(ref self: ContractState, rate: u16) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.btc_mint_fee_rate.write(rate);
            self.emit(SetBtcMintFeeRate{new_btc_mint_fee_rate: rate});
        }

        #[external(v0)]
        fn set_btc_redeem_fee_rate(ref self: ContractState, rate: u16) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.btc_redeem_fee_rate.write(rate);
            self.emit(SetBtcRedeemFeeRate{new_btc_redeem_fee_rate: rate});
        }

        #[external(v0)]
        fn set_btc_fee_recipient(ref self: ContractState, recipient: ByteArray) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            let recipient_clone = recipient.clone();
            self.btc_fee_recipient.write(recipient);
            self.emit(SetBtcFeeRecipient{btc_fee_recipient: recipient_clone});
        }

        #[external(v0)]
        fn set_btc_fee_recipient_for_vault(ref self: ContractState, uuid: felt252, recipient: ByteArray) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            let ibtc_idx = self.ibtc_vault_ids_by_uuid.entry(uuid).read();
            let mut ibtc = self.ibtc_vaults.entry(ibtc_idx).read();
            ibtc.btc_fee_recipient = recipient;
            self.ibtc_vaults.entry(ibtc_idx).write(ibtc);
        }

        #[external(v0)]
        fn set_whitelisting_enabled(ref self: ContractState, enabled: bool) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.whitelisting_enabled.write(enabled);
            self.emit(SetWhitelistingEnabled{is_whitelisting_enabled: enabled});
        }

        #[external(v0)]
        fn transfer_token_contract_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            let ibtc_token = self.ibtc_token.read();
            let ibtc_token_dispatcher = IBTCTokenABIDispatcher { contract_address: ibtc_token };
            ibtc_token_dispatcher.transfer_ownership(new_owner);
            self.emit(TransferTokenContractOwnership{new_owner});
        }

        #[external(v0)]
        fn set_minter_on_token_contract(ref self: ContractState, minter: ContractAddress) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            let ibtc_token = self.ibtc_token.read();
            let ibtc_token_dispatcher = IBTCTokenABIDispatcher { contract_address: ibtc_token };
            ibtc_token_dispatcher.set_minter(minter);
        }

        #[external(v0)]
        fn set_burner_on_token_contract(ref self: ContractState, burner: ContractAddress) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            let ibtc_token = self.ibtc_token.read();
            let ibtc_token_dispatcher = IBTCTokenABIDispatcher { contract_address: ibtc_token };
            ibtc_token_dispatcher.set_burner(burner);
        }

        #[external(v0)]
        fn set_por_enabled(ref self: ContractState, enabled: bool) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.por_enabled.write(enabled);
            self.emit(SetPorEnabled{is_por_enabled: enabled});
        }

        #[external(v0)]
        fn set_ibtc_por_feed(ref self: ContractState, feed: ContractAddress) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.ibtc_por_feed.write(feed);
            self.emit(SetIBtcPorFeed{feed});
        }
    }

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.accesscontrol.assert_only_role(IBTC_ADMIN_ROLE);
            self.upgradeable.upgrade(new_class_hash);
        }
    }

    #[abi(embed_v0)]
    impl AccessControlImpl of IAccessControl<ContractState> {
        fn has_role(self: @ContractState, role: felt252, account: ContractAddress) -> bool {
            self.accesscontrol.has_role(role, account)
        }

        fn get_role_admin(self: @ContractState, role: felt252) -> felt252 {
            self.accesscontrol.get_role_admin(role)
        }

        fn grant_role(ref self: ContractState, role: felt252, account: ContractAddress) {
            if (self._has_any_roles(account)) {
                panic_with_felt252(Errors::INCOMPATIBLE_ROLE);
            }
            self.accesscontrol.grant_role(role, account);
            if (role == APPROVED_SIGNER) {
                self.signer_count.write(self.signer_count.read() + 1);
            }
        }

        fn revoke_role(ref self: ContractState, role: felt252, account: ContractAddress) {
            self.accesscontrol.revoke_role(role, account);

            if (role == APPROVED_SIGNER) {
                if (self.signer_count.read() == self.minimum_threshold.read()) {
                    panic_with_felt252(Errors::THRESHOLD_MINIMUM_REACHED);
                }
                self.signer_count.write(self.signer_count.read() - 1);
            }
        }

        fn renounce_role(ref self: ContractState, role: felt252, account: ContractAddress) {
            if (account == get_caller_address() && role == APPROVED_SIGNER) {
                panic_with_felt252(Errors::NO_SIGNER_RENOUNCEMENT);
            }
            self.accesscontrol.renounce_role(role, account);
        }
    }
}
