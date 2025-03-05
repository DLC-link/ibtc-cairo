// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts for Cairo ^0.20.0

#[starknet::contract]
mod IBTCToken {
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::token::erc20::{ERC20Component, ERC20HooksEmptyImpl};
    use openzeppelin::upgrades::UpgradeableComponent;
    use openzeppelin::upgrades::interface::IUpgradeable;
    use openzeppelin::token::erc20::interface::IERC20Metadata;
    use starknet::{ClassHash, ContractAddress, get_caller_address};
    use openzeppelin::utils::serde::SerializedAppend;

    component!(path: ERC20Component, storage: erc20, event: ERC20Event);
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    // Ownable Mixin
    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl ERC20Impl = ERC20Component::ERC20Impl<ContractState>;
    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl ERC20MetadataImpl of IERC20Metadata<ContractState> {
        fn name(self: @ContractState) -> ByteArray {
            self.erc20.name()
        }

        fn symbol(self: @ContractState) -> ByteArray {
            self.erc20.symbol()
        }

        fn decimals(self: @ContractState) -> u8 {
            8
        }
    }

    // Upgradeable
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        pub ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        pub erc20: ERC20Component::Storage,
        #[substorage(v0)]
        pub upgradeable: UpgradeableComponent::Storage,
        _minter: ContractAddress,
        _burner: ContractAddress,
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct MinterSet {
        minter: ContractAddress,
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct BurnerSet {
        burner: ContractAddress,
    }

    pub mod Errors {
        pub const NOT_MINTER_OR_OWNER: felt252 = 'Not the minter or owner';
        pub const NOT_BURNER: felt252 = 'Not the burner';
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        ERC20Event: ERC20Component::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
        MinterSet: MinterSet,
        BurnerSet: BurnerSet,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.ownable.initializer(owner);
        self.erc20.initializer("IBTC", "IBTC");
    }

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn assert_only_owner_or_minter(ref self: ContractState) {
            let owner = self.ownable.owner();
            let minter = self._minter.read();
            let caller = get_caller_address();
            assert(owner == caller || minter == caller, Errors::NOT_MINTER_OR_OWNER);
        }

        fn assert_only_burner(ref self: ContractState) {
            let burner = self._burner.read();
            let caller = get_caller_address();
            assert(burner == caller, Errors::NOT_BURNER);
        }
    }

    #[generate_trait]
    #[abi(per_item)]
    impl ExternalImpl of ExternalTrait {
        #[external(v0)]
        fn burn(ref self: ContractState, amount: u256) {
            self.assert_only_burner();
            self.erc20.burn(get_caller_address(), amount);
        }

        #[external(v0)]
        fn burn_from(ref self: ContractState, account: ContractAddress, amount: u256) {
            self.ownable.assert_only_owner();
            self.erc20.burn(account, amount);
        }

        #[external(v0)]
        fn mint(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            self.assert_only_owner_or_minter();
            self.erc20.mint(recipient, amount);
        }

        #[external(v0)]
        fn set_minter(ref self: ContractState, minter: ContractAddress) {
            self.ownable.assert_only_owner();
            self._minter.write(minter);
            self.emit(MinterSet { minter });
        }

        #[external(v0)]
        fn set_burner(ref self: ContractState, burner: ContractAddress) {
            self.ownable.assert_only_owner();
            self._burner.write(burner);
            self.emit(BurnerSet { burner });
        }

        #[external(v0)]
        fn minter(self: @ContractState) -> ContractAddress {
            self._minter.read()
        }

        #[external(v0)]
        fn burner(self: @ContractState) -> ContractAddress {
            self._burner.read()
        }
    }
    
    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.ownable.assert_only_owner();
            self.upgradeable.upgrade(new_class_hash);
        }
    }
}
