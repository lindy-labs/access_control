mod test_access_control {
    use access_control::access_control_component::{AccessControlHelpers, AccessControlPublic};
    use access_control::tests::mock_access_control::mock_access_control;
    use core::num::traits::Zero;
    use snforge_std::{EventSpyTrait, spy_events, start_cheat_caller_address, test_address};
    use starknet::ContractAddress;
    //
    // Constants
    //

    // mock roles
    const R1: u128 = 1_u128;
    const R2: u128 = 2_u128;
    const R3: u128 = 128_u128;
    const R4: u128 = 256_u128;

    const ADMIN_ADDR: felt252 = 'access control admin';
    const ADMIN: ContractAddress = ADMIN_ADDR.try_into().unwrap();
    const BAD_GUY: ContractAddress = 'bad guy'.try_into().unwrap();
    const USER: ContractAddress = 'user'.try_into().unwrap();

    //
    // Test setup
    //

    fn state() -> mock_access_control::ContractState {
        mock_access_control::contract_state_for_testing()
    }

    fn setup(caller: ContractAddress) -> mock_access_control::ContractState {
        let mut state = state();
        state.access_control.initializer(ADMIN, Option::None);

        start_cheat_caller_address(test_address(), caller);

        state
    }

    fn set_pending_admin(
        ref state: mock_access_control::ContractState, caller: ContractAddress, pending_admin: ContractAddress,
    ) {
        start_cheat_caller_address(test_address(), caller);
        state.set_pending_admin(pending_admin);
    }

    fn default_grant(ref state: mock_access_control::ContractState) {
        state.grant_role(R1, USER);
        state.grant_role(R2, USER);
    }

    //
    // Tests
    //

    #[test]
    fn test_initializer() {
        let mut spy = spy_events();

        let state = setup(ADMIN);

        assert(state.get_admin() == ADMIN, 'initialize wrong admin');

        let events = spy.get_events();

        let (_, event) = events.events.at(0);

        assert_eq!(events.events.len(), 1, "wrong number of events");
        assert_eq!(event.keys[1], @selector!("AdminChanged"), "wrong event name");
        assert_eq!(*event.data[0], 0, "should be zero address");
        assert_eq!(*event.data[1], ADMIN.into(), "should be admin adddress");
    }

    #[test]
    fn test_grant_role() {
        let mut state = setup(ADMIN);

        let mut spy = spy_events();

        default_grant(ref state);

        assert(state.has_role(R1, USER), 'role R1 not granted');
        assert(state.has_role(R2, USER), 'role R2 not granted');
        assert_eq!(state.get_roles(USER), R1 + R2, "not all roles granted");

        let events = spy.get_events();

        assert_eq!(events.events.len(), 2, "wrong number of events");

        let (_, event) = events.events.at(0);
        assert_eq!(event.keys[1], @selector!("RoleGranted"), "wrong event name");
        assert_eq!(*event.data[0], USER.into(), "wrong user in event #1");
        assert_eq!(*event.data[1], R1.into(), "wrong role in event #1");

        let (_, event) = events.events.at(1);
        assert_eq!(event.keys[1], @selector!("RoleGranted"), "wrong event name");
        assert_eq!(*event.data[0], USER.into(), "wrong user in event #2");
        assert_eq!(*event.data[1], R2.into(), "wrong role in event #2");
    }

    #[test]
    #[should_panic(expected: 'Caller not admin')]
    fn test_grant_role_not_admin() {
        let mut state = setup(BAD_GUY);
        state.grant_role(R2, BAD_GUY);
    }

    #[test]
    fn test_grant_role_multiple_users() {
        let mut state = setup(ADMIN);
        default_grant(ref state);

        let u2: ContractAddress = 'user 2'.try_into().unwrap();
        state.grant_role(R2 + R3 + R4, u2);
        assert_eq!(state.get_roles(USER), R1 + R2, "wrong roles for u");
        assert_eq!(state.get_roles(u2), R2 + R3 + R4, "wrong roles for u2");
    }

    #[test]
    fn test_revoke_role() {
        let mut state = setup(ADMIN);
        default_grant(ref state);

        let mut spy = spy_events();

        state.revoke_role(R1, USER);
        assert_eq!(state.has_role(R1, USER), false, "role R1 not revoked");
        assert(state.has_role(R2, USER), 'role R2 not kept');
        assert_eq!(state.get_roles(USER), R2, "incorrect roles");

        let events = spy.get_events();

        assert_eq!(events.events.len(), 1, "wrong number of events");

        let (_, event) = events.events.at(0);
        assert_eq!(event.keys[1], @selector!("RoleRevoked"), "wrong event name");
        assert_eq!(*event.data[0], USER.into(), "wrong user in event");
        assert_eq!(*event.data[1], R1.into(), "wrong role in event");
    }

    #[test]
    #[should_panic(expected: 'Caller not admin')]
    fn test_revoke_role_not_admin() {
        let mut state = setup(ADMIN);
        start_cheat_caller_address(test_address(), BAD_GUY);
        state.revoke_role(R1, USER);
    }

    #[test]
    fn test_renounce_role() {
        let mut state = setup(ADMIN);
        default_grant(ref state);

        let mut spy = spy_events();

        start_cheat_caller_address(test_address(), USER);
        state.renounce_role(R1);
        assert(!state.has_role(R1, USER), 'R1 role kept');

        // renouncing non-granted role should pass
        let non_existent_role: u128 = 64;
        state.renounce_role(non_existent_role);

        let events = spy.get_events();

        assert_eq!(events.events.len(), 2, "wrong number of events");

        let (_, event) = events.events.at(0);
        assert_eq!(event.keys[1], @selector!("RoleRevoked"), "wrong event name");
        assert_eq!(*event.data[0], USER.into(), "wrong user in event #1");
        assert_eq!(*event.data[1], R1.into(), "wrong role in event #1");

        let (_, event) = events.events.at(1);
        assert_eq!(event.keys[1], @selector!("RoleRevoked"), "wrong event name");
        assert_eq!(*event.data[0], USER.into(), "wrong user in event #2");
        assert_eq!(*event.data[1], non_existent_role.into(), "wrong role in event #2");
    }

    #[test]
    fn test_set_pending_admin() {
        let mut state = setup(ADMIN);

        let mut spy = spy_events();

        let pending_admin = USER;
        state.set_pending_admin(pending_admin);
        assert(state.get_pending_admin() == pending_admin, 'pending admin not changed');

        let events = spy.get_events();

        assert_eq!(events.events.len(), 1, "wrong number of events");

        let (_, event) = events.events.at(0);
        assert_eq!(event.keys[1], @selector!("NewPendingAdmin"), "wrong event name");
        assert_eq!(*event.data[0], pending_admin.into(), "wrong user in event");
    }

    #[test]
    #[should_panic(expected: 'Caller not admin')]
    fn test_set_pending_admin_not_admin() {
        let mut state = setup(ADMIN);
        start_cheat_caller_address(test_address(), BAD_GUY);
        state.set_pending_admin(BAD_GUY);
    }

    #[test]
    fn test_accept_admin() {
        let current_admin = ADMIN;
        let mut state = setup(current_admin);

        let pending_admin = USER;
        set_pending_admin(ref state, current_admin, pending_admin);

        let mut spy = spy_events();

        start_cheat_caller_address(test_address(), pending_admin);
        state.accept_admin();

        assert(state.get_admin() == pending_admin, 'admin not changed');
        assert(state.get_pending_admin().is_zero(), 'pending admin not reset');

        let events = spy.get_events();

        assert_eq!(events.events.len(), 1, "wrong number of events");

        let (_, event) = events.events.at(0);
        assert_eq!(event.keys[1], @selector!("AdminChanged"), "wrong event name");
        assert_eq!(*event.data[0], current_admin.into(), "wrong old admin in event");
        assert_eq!(*event.data[1], pending_admin.into(), "wrong new admin in event");
    }

    #[test]
    #[should_panic(expected: 'Caller not pending admin')]
    fn test_accept_admin_not_pending_admin() {
        let current_admin = ADMIN;
        let mut state = setup(current_admin);

        let pending_admin = USER;
        set_pending_admin(ref state, current_admin, pending_admin);

        start_cheat_caller_address(test_address(), BAD_GUY);
        state.accept_admin();
    }

    #[test]
    fn test_assert_has_role() {
        let mut state = setup(ADMIN);
        default_grant(ref state);

        start_cheat_caller_address(test_address(), USER);
        // should not throw
        state.access_control.assert_has_role(R1);
        state.access_control.assert_has_role(R1 + R2);
    }

    #[test]
    #[should_panic(expected: 'Caller missing role')]
    fn test_assert_has_role_panics() {
        let mut state = setup(ADMIN);
        default_grant(ref state);

        start_cheat_caller_address(test_address(), USER);
        state.access_control.assert_has_role(R3);
    }
}
