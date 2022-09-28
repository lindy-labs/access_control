%lang starknet

from starkware.cairo.common.bool import TRUE
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin

from contracts.accesscontrol_library import AccessControl
// these imported public functions are part of the contract's interface
from contracts.accesscontrol_external import (
    change_admin,
    get_admin,
    get_roles,
    grant_role,
    has_role,
    renounce_role,
    revoke_role,
)
from tests.roles import AccRoles

from contracts.aliases import address, bool, ufelt
//
// Access Control - Constructor
//

@constructor
func constructor{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(admin: address) {
    AccessControl.initializer(admin);
    return ();
}

//
// Access Control - Modifiers
//

@view
func assert_has_role{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(role: ufelt) {
    AccessControl.assert_has_role(role);
    return ();
}

@view
func assert_admin{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}() {
    AccessControl.assert_admin();
    return ();
}

//
// Access Control - Getters
//

@view
func can_execute{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(user: address) -> (authorized: bool) {
    let authorized: bool = AccessControl.has_role(AccRoles.EXECUTE, user);
    return (authorized,);
}

@view
func can_write{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(user) -> (authorized: bool) {
    let authorized: bool = AccessControl.has_role(AccRoles.WRITE, user);
    return (authorized,);
}

@view
func can_read{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(user) -> (authorized: bool) {
    let authorized: bool = AccessControl.has_role(AccRoles.READ, user);
    return (authorized,);
}
