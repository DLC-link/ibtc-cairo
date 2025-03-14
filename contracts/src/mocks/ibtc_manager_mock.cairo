#[starknet::contract]
pub mod IBTCManagerMock {
    use openzeppelin::upgrades::UpgradeableComponent;
    use openzeppelin::upgrades::interface::IUpgradeable;
    use starknet::{ClassHash};
    use starknet::storage::{Mutable, MutableVecTrait, StorageAsPath, StoragePath, Vec, VecTrait};
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePathEntry};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    // Upgradeable
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    #[constructor]
    fn constructor(
        ref self: ContractState
    ) {}

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
    }

    #[storage]
    pub struct Storage {
        #[substorage(v0)]
        pub upgradeable: UpgradeableComponent::Storage,
    }

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            // NOTE: allow anyone to upgrade, this contract is just for testing purposes
            self.upgradeable.upgrade(new_class_hash);
        }
    }
}
