use starknet::ContractAddress;

#[starknet::interface]
pub trait IAccessControl<TContractState> {
    fn get_roles(self: @TContractState, account: ContractAddress) -> u128;
    fn has_role(self: @TContractState, role: u128, account: ContractAddress) -> bool;
    fn get_admin(self: @TContractState) -> ContractAddress;
    fn get_pending_admin(self: @TContractState) -> ContractAddress;
    fn grant_role(ref self: TContractState, role: u128, account: ContractAddress);
    fn revoke_role(ref self: TContractState, role: u128, account: ContractAddress);
    fn renounce_role(ref self: TContractState, role: u128);
    fn set_pending_admin(ref self: TContractState, new_admin: ContractAddress);
    fn accept_admin(ref self: TContractState);
}

#[starknet::component]
pub mod access_control_component {
    use core::num::traits::Zero;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use starknet::{ContractAddress, get_caller_address};

    #[storage]
    pub struct Storage {
        admin: ContractAddress,
        pending_admin: ContractAddress,
        roles: Map::<ContractAddress, u128>
    }

    #[event]
    #[derive(Copy, Drop, starknet::Event, PartialEq)]
    pub enum Event {
        AdminChanged: AdminChanged,
        NewPendingAdmin: NewPendingAdmin,
        RoleGranted: RoleGranted,
        RoleRevoked: RoleRevoked,
    }

    #[derive(Copy, Drop, starknet::Event, PartialEq)]
    pub struct AdminChanged {
        old_admin: ContractAddress,
        new_admin: ContractAddress
    }

    #[derive(Copy, Drop, starknet::Event, PartialEq)]
    pub struct NewPendingAdmin {
        new_admin: ContractAddress
    }

    #[derive(Copy, Drop, starknet::Event, PartialEq)]
    pub struct RoleGranted {
        user: ContractAddress,
        role_granted: u128
    }

    #[derive(Copy, Drop, starknet::Event, PartialEq)]
    pub struct RoleRevoked {
        user: ContractAddress,
        role_revoked: u128
    }

    #[embeddable_as(AccessControl)]
    pub impl AccessControlPublic<
        TContractState, +HasComponent<TContractState>
    > of super::IAccessControl<ComponentState<TContractState>> {
        //
        // getters
        //

        fn get_roles(self: @ComponentState<TContractState>, account: ContractAddress) -> u128 {
            self.roles.read(account)
        }

        fn has_role(self: @ComponentState<TContractState>, role: u128, account: ContractAddress) -> bool {
            let roles: u128 = self.roles.read(account);
            // masks roles such that all bits are zero, except the bit(s) representing `role`, which may be zero or one
            let masked_roles: u128 = roles & role;
            // if masked_roles is non-zero, the account has the queried role
            masked_roles != 0
        }

        fn get_admin(self: @ComponentState<TContractState>) -> ContractAddress {
            self.admin.read()
        }

        fn get_pending_admin(self: @ComponentState<TContractState>) -> ContractAddress {
            self.pending_admin.read()
        }

        //
        // setters
        //

        fn grant_role(ref self: ComponentState<TContractState>, role: u128, account: ContractAddress) {
            self.assert_admin();
            self.grant_role_helper(role, account);
        }

        fn revoke_role(ref self: ComponentState<TContractState>, role: u128, account: ContractAddress) {
            self.assert_admin();
            self.revoke_role_helper(role, account);
        }

        fn renounce_role(ref self: ComponentState<TContractState>, role: u128) {
            self.revoke_role_helper(role, get_caller_address());
        }

        fn set_pending_admin(ref self: ComponentState<TContractState>, new_admin: ContractAddress) {
            self.assert_admin();
            self.set_pending_admin_helper(new_admin);
        }

        //
        // external
        //

        fn accept_admin(ref self: ComponentState<TContractState>) {
            let caller: ContractAddress = get_caller_address();
            assert(self.get_pending_admin() == caller, 'Caller not pending admin');
            self.set_admin_helper(caller);

            self.pending_admin.write(Zero::zero());
        }
    }

    #[generate_trait]
    pub impl AccessControlHelpers<
        TContractState, +HasComponent<TContractState>
    > of AccessControlHelpersTrait<TContractState> {
        fn initializer(ref self: ComponentState<TContractState>, admin: ContractAddress, roles: Option<u128>) {
            self.set_admin_helper(admin);
            if roles.is_some() {
                self.grant_role_helper(roles.unwrap(), admin);
            }
        }

        //
        // asserts
        //

        fn assert_has_role(self: @ComponentState<TContractState>, role: u128) {
            assert(self.has_role(role, get_caller_address()), 'Caller missing role');
        }

        fn assert_admin(self: @ComponentState<TContractState>) {
            assert(self.admin.read() == get_caller_address(), 'Caller not admin');
        }

        //
        // internal
        //

        fn set_admin_helper(ref self: ComponentState<TContractState>, new_admin: ContractAddress) {
            let old_admin = self.admin.read();
            self.admin.write(new_admin);

            self.emit(AdminChanged { old_admin, new_admin });
        }

        fn set_pending_admin_helper(ref self: ComponentState<TContractState>, new_admin: ContractAddress) {
            self.pending_admin.write(new_admin);

            self.emit(NewPendingAdmin { new_admin });
        }

        fn grant_role_helper(ref self: ComponentState<TContractState>, role: u128, account: ContractAddress) {
            let roles: u128 = self.roles.read(account);
            self.roles.write(account, roles | role);

            self.emit(RoleGranted { user: account, role_granted: role });
        }

        fn revoke_role_helper(ref self: ComponentState<TContractState>, role: u128, account: ContractAddress) {
            let roles: u128 = self.roles.read(account);
            let updated_roles: u128 = roles & (~role);
            self.roles.write(account, updated_roles);

            self.emit(RoleRevoked { user: account, role_revoked: role });
        }
    }
}
