#[starknet::contract]
mod mock_access_control {
    use access_control::access_control::access_control_component;
    use starknet::ContractAddress;

    component!(path: access_control_component, storage: access_control, event: AccessControlEvent);

    #[abi(embed_v0)]
    impl AccessControlPublic = access_control_component::AccessControl<ContractState>;
    impl AccessControlHelpers = access_control_component::AccessControlHelpers<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        access_control: access_control_component::Storage
    }

    #[event]
    #[derive(Copy, Drop, starknet::Event, PartialEq)]
    enum Event {
        AccessControlEvent: access_control_component::Event
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress, roles: Option<u128>) {
        self.access_control.initializer(admin, roles);
    }
}
