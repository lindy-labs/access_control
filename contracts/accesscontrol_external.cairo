%lang starknet

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin

from contracts.accesscontrol_library import AccessControl
from contracts.aliases import address, bool, ufelt

//
// Getters
//

@view
func get_roles{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(account: address) -> (roles: ufelt) {
    let roles: ufelt = AccessControl.get_roles(account);
    return (roles,);
}

@view
func has_role{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(role: ufelt, account) -> (has_role: bool) {
    let has_role: bool = AccessControl.has_role(role, account);
    return (has_role,);
}

@view
func get_admin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    admin: address
) {
    let admin: address = AccessControl.get_admin();
    return (admin,);
}

//
// External
//

@external
func grant_role{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(role: ufelt, account: address) {
    AccessControl.grant_role(role, account);
    return ();
}

@external
func revoke_role{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(role: ufelt, account: address) {
    AccessControl.revoke_role(role, account);
    return ();
}

@external
func renounce_role{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(role: ufelt, account: address) {
    AccessControl.renounce_role(role, account);
    return ();
}

@external
func change_admin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    new_admin: address
) {
    AccessControl.change_admin(new_admin);
    return ();
}
