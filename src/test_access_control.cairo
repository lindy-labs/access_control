mod test_access_control {
    use access_control::access_control::access_control_component::{AccessControlPublic, AccessControlHelpers};
    use access_control::access_control::access_control_component;
    //use opus::tests::common;
    use access_control::mock_access_control::mock_access_control;
    use snforge_std::{spy_events, SpyOn, EventSpy, EventFetcher, event_name_hash, Event, start_prank, CheatTarget};
    use starknet::contract_address::{ContractAddress, ContractAddressZeroable, contract_address_try_from_felt252};
    //
    // Constants
    //

    // mock roles
    const R1: u128 = 1_u128;
    const R2: u128 = 2_u128;
    const R3: u128 = 128_u128;
    const R4: u128 = 256_u128;

    fn admin() -> ContractAddress {
        contract_address_try_from_felt252('access control admin').unwrap()
    }

    fn badguy() -> ContractAddress {
        contract_address_try_from_felt252('bad guy').unwrap()
    }

    fn user() -> ContractAddress {
        contract_address_try_from_felt252('user').unwrap()
    }

    fn zero_addr() -> ContractAddress {
        ContractAddressZeroable::zero()
    }

    //
    // Test setup
    //

    fn state() -> mock_access_control::ContractState {
        mock_access_control::contract_state_for_testing()
    }

    fn setup(caller: ContractAddress) -> mock_access_control::ContractState {
        let mut state = state();
        state.access_control.initializer(admin(), Option::None);

        start_prank(CheatTarget::All, caller);

        state
    }

    fn set_pending_admin(
        ref state: mock_access_control::ContractState, caller: ContractAddress, pending_admin: ContractAddress
    ) {
        start_prank(CheatTarget::All, caller);
        state.set_pending_admin(pending_admin);
    }

    fn default_grant(ref state: mock_access_control::ContractState) {
        let u = user();
        state.grant_role(R1, u);
        state.grant_role(R2, u);
    }

    //
    // Tests
    //

    #[test]
    fn test_initializer() {
        let admin = admin();

        let state = setup(admin);

        assert(state.get_admin() == admin, 'initialize wrong admin');
    //let event = pop_log::<access_control_component::AdminChanged>(zero_addr()).unwrap();
    //assert(event.old_admin.is_zero(), 'should be zero address');
    //assert(event.new_admin == admin(), 'wrong admin in event');

    //assert(pop_log_raw(zero_addr()).is_none(), 'unexpected event');
    }

    #[test]
    fn test_grant_role() {
        let mut state = setup(admin());
        //common::drop_all_events(zero_addr());

        default_grant(ref state);

        let u = user();
        assert(state.has_role(R1, u), 'role R1 not granted');
        assert(state.has_role(R2, u), 'role R2 not granted');
        assert(state.get_roles(u) == R1 + R2, 'not all roles granted');
    //let event = pop_log::<access_control_component::RoleGranted>(zero_addr()).unwrap();
    //assert(event.user == u, 'wrong user in event #1');
    //assert(event.role_granted == R1, 'wrong role in event #1');

    //let event = pop_log::<access_control_component::RoleGranted>(zero_addr()).unwrap();
    // assert(event.user == u, 'wrong user in event #2');
    // assert(event.role_granted == R2, 'wrong role in event #2');

    // assert(pop_log_raw(zero_addr()).is_none(), 'unexpected event');
    }

    #[test]
    #[should_panic(expected: ('Caller not admin',))]
    fn test_grant_role_not_admin() {
        let mut state = setup(badguy());
        state.grant_role(R2, badguy());
    }

    #[test]
    fn test_grant_role_multiple_users() {
        let mut state = setup(admin());
        default_grant(ref state);

        let u = user();
        let u2 = contract_address_try_from_felt252('user 2').unwrap();
        state.grant_role(R2 + R3 + R4, u2);
        assert(state.get_roles(u) == R1 + R2, 'wrong roles for u');
        assert(state.get_roles(u2) == R2 + R3 + R4, 'wrong roles for u2');
    }

    #[test]
    fn test_revoke_role() {
        let mut state = setup(admin());
        default_grant(ref state);

        //common::drop_all_events(zero_addr());

        let u = user();
        state.revoke_role(R1, u);
        assert(state.has_role(R1, u) == false, 'role R1 not revoked');
        assert(state.has_role(R2, u), 'role R2 not kept');
        assert(state.get_roles(u) == R2, 'incorrect roles');
    // let event = pop_log::<access_control_component::RoleRevoked>(zero_addr()).unwrap();
    // assert(event.user == u, 'wrong user in event');
    // assert(event.role_revoked == R1, 'wrong role in event');

    // assert(pop_log_raw(zero_addr()).is_none(), 'unexpected event');
    }

    #[test]
    #[should_panic(expected: ('Caller not admin',))]
    fn test_revoke_role_not_admin() {
        let mut state = setup(admin());
        start_prank(CheatTarget::All, badguy());
        state.revoke_role(R1, user());
    }

    #[test]
    fn test_renounce_role() {
        let mut state = setup(admin());
        default_grant(ref state);

        //common::drop_all_events(zero_addr());

        let u = user();
        start_prank(CheatTarget::All, u);
        state.renounce_role(R1);
        assert(state.has_role(R1, u) == false, 'R1 role kept');

        // renouncing non-granted role should pass
        let non_existent_role: u128 = 64;
        state.renounce_role(non_existent_role);
    // let event = pop_log::<access_control_component::RoleRevoked>(zero_addr()).unwrap();
    // assert(event.user == u, 'wrong user in event #1');
    // assert(event.role_revoked == R1, 'wrong role in event #1');

    // let event = pop_log::<access_control_component::RoleRevoked>(zero_addr()).unwrap();
    // assert(event.user == u, 'wrong user in event #2');
    // assert(event.role_revoked == non_existent_role, 'wrong role in event #2');

    // assert(pop_log_raw(zero_addr()).is_none(), 'unexpected event');
    }

    #[test]
    fn test_set_pending_admin() {
        let mut state = setup(admin());

        //common::drop_all_events(zero_addr());

        let pending_admin = user();
        state.set_pending_admin(pending_admin);
        assert(state.get_pending_admin() == pending_admin, 'pending admin not changed');
    // let event = pop_log::<access_control_component::NewPendingAdmin>(zero_addr()).unwrap();
    // assert(event.new_admin == pending_admin, 'wrong user in event');

    // assert(pop_log_raw(zero_addr()).is_none(), 'unexpected event');
    }

    #[test]
    #[should_panic(expected: ('Caller not admin',))]
    fn test_set_pending_admin_not_admin() {
        let mut state = setup(admin());
        start_prank(CheatTarget::All, badguy());
        state.set_pending_admin(badguy());
    }

    #[test]
    fn test_accept_admin() {
        let current_admin = admin();
        let mut state = setup(current_admin);

        let pending_admin = user();
        set_pending_admin(ref state, current_admin, pending_admin);

        //common::drop_all_events(zero_addr());

        start_prank(CheatTarget::All, pending_admin);
        state.accept_admin();

        assert(state.get_admin() == pending_admin, 'admin not changed');
        assert(state.get_pending_admin().is_zero(), 'pending admin not reset');
    // let event = pop_log::<access_control_component::AdminChanged>(zero_addr()).unwrap();
    // assert(event.old_admin == current_admin, 'wrong old admin in event');
    // assert(event.new_admin == pending_admin, 'wrong new admin in event');

    // assert(pop_log_raw(zero_addr()).is_none(), 'unexpected event');
    }

    #[test]
    #[should_panic(expected: ('Caller not pending admin',))]
    fn test_accept_admin_not_pending_admin() {
        let current_admin = admin();
        let mut state = setup(current_admin);

        let pending_admin = user();
        set_pending_admin(ref state, current_admin, pending_admin);

        start_prank(CheatTarget::All, badguy());
        state.accept_admin();
    }

    #[test]
    fn test_assert_has_role() {
        let mut state = setup(admin());
        default_grant(ref state);

        start_prank(CheatTarget::All, user());
        // should not throw
        state.access_control.assert_has_role(R1);
        state.access_control.assert_has_role(R1 + R2);
    }

    #[test]
    #[should_panic(expected: ('Caller missing role',))]
    fn test_assert_has_role_panics() {
        let mut state = setup(admin());
        default_grant(ref state);

        start_prank(CheatTarget::All, user());
        state.access_control.assert_has_role(R3);
    }
}
