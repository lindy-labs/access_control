mod test_access_control {
    use access_control::access_control_component::{AccessControlPublic, AccessControlHelpers};
    use access_control::access_control_component;
    use access_control::tests::mock_access_control::mock_access_control;
    use snforge_std::cheatcodes::events::EventAssertions;
    use snforge_std::{
        spy_events, SpyOn, EventSpy, EventFetcher, event_name_hash, Event, start_prank, CheatTarget, test_address,
        PrintTrait
    };
    use starknet::contract_address::{ContractAddress, ContractAddressZeroable, contract_address_try_from_felt252};
    //
    // Constants
    //

    // mock roles
    const R1: u128 = 1_u128;
    const R2: u128 = 2_u128;
    const R3: u128 = 128_u128;
    const R4: u128 = 256_u128;

    const ADMIN_ADDR: felt252 = 'access control admin';

    fn admin() -> ContractAddress {
        contract_address_try_from_felt252(ADMIN_ADDR).unwrap()
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
        let mut spy = spy_events(SpyOn::One(test_address()));

        let admin = admin();

        let state = setup(admin);

        assert(state.get_admin() == admin, 'initialize wrong admin');

        let expected_events = array![
            (
                test_address(),
                access_control_component::Event::AdminChanged(
                    access_control_component::AdminChanged { old_admin: zero_addr(), new_admin: admin(), }
                )
            ),
        ];
        spy.fetch_events();

        assert(spy.events.len() == 1, 'wrong number of events');

        let (_, event) = spy.events.at(0);
        assert(*event.keys[1] == event_name_hash('AdminChanged'), 'wrong event name');
        assert(*event.data[0] == 0, 'should be zero address');
        assert(*event.data[1] == ADMIN_ADDR, 'should be admin adddress');
    }

    #[test]
    fn test_grant_role() {
        let mut state = setup(admin());

        let mut spy = spy_events(SpyOn::One(test_address()));

        default_grant(ref state);

        let u = user();
        assert(state.has_role(R1, u), 'role R1 not granted');
        assert(state.has_role(R2, u), 'role R2 not granted');
        assert(state.get_roles(u) == R1 + R2, 'not all roles granted');

        spy.fetch_events();

        assert(spy.events.len() == 2, 'wrong number of events');

        let (from, event) = spy.events.at(0);
        assert(*event.keys[1] == event_name_hash('RoleGranted'), 'wrong event name');
        assert(*event.data[0] == u.into(), 'wrong user in event #1');
        assert(*event.data[1] == R1.into(), 'wrong role in event #1');

        let (from, event) = spy.events.at(1);
        assert(*event.keys[1] == event_name_hash('RoleGranted'), 'wrong event name');
        assert(*event.data[0] == u.into(), 'wrong user in event #2');
        assert(*event.data[1] == R2.into(), 'wrong role in event #2');
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

        let mut spy = spy_events(SpyOn::One(test_address()));

        let u = user();
        state.revoke_role(R1, u);
        assert(state.has_role(R1, u) == false, 'role R1 not revoked');
        assert(state.has_role(R2, u), 'role R2 not kept');
        assert(state.get_roles(u) == R2, 'incorrect roles');

        spy.fetch_events();

        assert(spy.events.len() == 1, 'wrong number of events');

        let (_, event) = spy.events.at(0);
        assert(*event.keys[1] == event_name_hash('RoleRevoked'), 'wrong event name');
        assert(*event.data[0] == u.into(), 'wrong user in event');
        assert(*event.data[1] == R1.into(), 'wrong role in event');
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

        let mut spy = spy_events(SpyOn::One(test_address()));

        let u = user();
        start_prank(CheatTarget::All, u);
        state.renounce_role(R1);
        assert(state.has_role(R1, u) == false, 'R1 role kept');

        // renouncing non-granted role should pass
        let non_existent_role: u128 = 64;
        state.renounce_role(non_existent_role);

        spy.fetch_events();

        assert(spy.events.len() == 2, 'wrong number of events');

        let (from, event) = spy.events.at(0);
        assert(*event.keys[1] == event_name_hash('RoleRevoked'), 'wrong event name');
        assert(*event.data[0] == u.into(), 'wrong user in event #1');
        assert(*event.data[1] == R1.into(), 'wrong role in event #1');

        let (from, event) = spy.events.at(1);
        assert(*event.keys[1] == event_name_hash('RoleRevoked'), 'wrong event name');
        assert(*event.data[0] == u.into(), 'wrong user in event #2');
        assert(*event.data[1] == non_existent_role.into(), 'wrong role in event #2');
    }

    #[test]
    fn test_set_pending_admin() {
        let mut state = setup(admin());

        let mut spy = spy_events(SpyOn::One(test_address()));

        let pending_admin = user();
        state.set_pending_admin(pending_admin);
        assert(state.get_pending_admin() == pending_admin, 'pending admin not changed');

        spy.fetch_events();

        assert(spy.events.len() == 1, 'wrong number of events');

        let (from, event) = spy.events.at(0);
        assert(*event.keys[1] == event_name_hash('NewPendingAdmin'), 'wrong event name');
        assert(*event.data[0] == pending_admin.into(), 'wrong user in event');
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

        let mut spy = spy_events(SpyOn::One(test_address()));

        start_prank(CheatTarget::All, pending_admin);
        state.accept_admin();

        assert(state.get_admin() == pending_admin, 'admin not changed');
        assert(state.get_pending_admin().is_zero(), 'pending admin not reset');

        spy.fetch_events();

        assert(spy.events.len() == 1, 'wrong number of events');

        let (from, event) = spy.events.at(0);
        assert(*event.keys[1] == event_name_hash('AdminChanged'), 'wrong event name');
        assert(*event.data[0] == current_admin.into(), 'wrong old admin in event');
        assert(*event.data[1] == pending_admin.into(), 'wrong new admin in event');
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
