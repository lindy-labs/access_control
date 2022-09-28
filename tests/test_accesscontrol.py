import asyncio
from enum import IntEnum
from itertools import combinations
from typing import Callable, List, Tuple

import pytest
from starkware.starknet.testing.contract import StarknetContract
from starkware.starknet.testing.objects import StarknetCallInfo
from starkware.starknet.testing.starknet import Starknet
from starkware.starkware_utils.error_handling import StarkException

from tests.utils import assert_event_emitted, compile_contract, str_to_felt

FALSE = 0
TRUE = 1

ACC_OWNER = str_to_felt("acc owner")
NEW_ACC_OWNER = str_to_felt("new acc owner")
ACC_USER = str_to_felt("acc user")
BAD_GUY = str_to_felt("bad guy")


class Roles(IntEnum):
    EXECUTE = 1
    WRITE = 2
    READ = 4


SUDO_USER: int = sum([r.value for r in Roles])

ROLES_COMBINATIONS: List[Tuple[Roles, ...]] = []

for i in range(1, len(Roles) + 1):
    for j in combinations(Roles, i):
        ROLES_COMBINATIONS.append(j)


@pytest.fixture(scope="session")
def event_loop():
    return asyncio.new_event_loop()


@pytest.fixture(scope="session")
async def starknet_session() -> Starknet:
    starknet = await Starknet.empty()
    return starknet


@pytest.fixture
async def acc(starknet_session) -> StarknetContract:
    contract = compile_contract("tests/test_accesscontrol.cairo")
    return await starknet_session.deploy(contract_class=contract, constructor_calldata=[ACC_OWNER])


@pytest.fixture
async def sudo_user(acc):
    # Grant user all permissions
    await acc.grant_role(SUDO_USER, ACC_USER).execute(caller_address=ACC_OWNER)


@pytest.fixture
async def ACC_change_admin(acc) -> StarknetCallInfo:
    tx = await acc.change_admin(NEW_ACC_OWNER).execute(caller_address=ACC_OWNER)
    return tx


@pytest.fixture
async def ACC_new_admin(acc, ACC_change_admin) -> StarknetContract:
    return acc


@pytest.fixture
def ACC_both(request) -> StarknetContract:
    """
    Wrapper fixture to pass two different instances of acc to `pytest.parametrize`,
    before and after change of admin.

    Returns a tuple of the acc contract and the caller
    """
    caller = ACC_OWNER if request.param == "acc" else NEW_ACC_OWNER
    return (request.getfixturevalue(request.param), caller)


@pytest.mark.asyncio
async def test_ACC_setup(acc):
    admin = (await acc.get_admin().execute()).result.admin
    assert admin == ACC_OWNER

    await acc.assert_admin().execute(caller_address=ACC_OWNER)

    with pytest.raises(StarkException, match="AccessControl: caller is not admin"):
        await acc.assert_admin().execute(caller_address=NEW_ACC_OWNER)


@pytest.mark.asyncio
async def test_change_admin(acc, ACC_change_admin):
    # Check event
    assert_event_emitted(
        ACC_change_admin,
        acc.contract_address,
        "AdminChanged",
        [ACC_OWNER, NEW_ACC_OWNER],
    )

    # Check admin
    admin = (await acc.get_admin().execute()).result.admin
    assert admin == NEW_ACC_OWNER

    await acc.assert_admin().execute(caller_address=NEW_ACC_OWNER)

    with pytest.raises(StarkException, match="AccessControl: caller is not admin"):
        await acc.assert_admin().execute(caller_address=ACC_OWNER)


@pytest.mark.asyncio
async def test_change_admin_unauthorized(acc):
    with pytest.raises(StarkException, match="AccessControl: caller is not admin"):
        await acc.change_admin(BAD_GUY).execute(caller_address=BAD_GUY)


@pytest.mark.parametrize("given_roles", ROLES_COMBINATIONS)
@pytest.mark.parametrize("revoked_roles", ROLES_COMBINATIONS)
@pytest.mark.parametrize("ACC_both", ["acc", "ACC_new_admin"], indirect=["ACC_both"])
@pytest.mark.asyncio
async def test_grant_and_revoke_role(ACC_both, given_roles, revoked_roles):
    acc, admin = ACC_both

    # Compute value of given role
    given_role_value = sum([r.value for r in given_roles])

    tx = await acc.grant_role(given_role_value, ACC_USER).execute(caller_address=admin)

    # Check event
    assert_event_emitted(tx, acc.contract_address, "RoleGranted", [given_role_value, ACC_USER])

    # Check role
    role = (await acc.get_roles(ACC_USER).execute()).result.roles
    assert role == given_role_value

    # Check roles granted
    for r in Roles:
        role_value = r.value

        # Check `has_role`
        has_role = (await acc.has_role(role_value, ACC_USER).execute()).result.has_role

        # Check getter
        role_name = r.name.lower()
        getter: Callable = acc.get_contract_function(f"can_{role_name}")
        can_perform_role = (await getter(ACC_USER).execute()).result.authorized

        expected = TRUE if r in given_roles else FALSE
        assert has_role == can_perform_role == expected

    # Grant the role again to confirm behaviour is correct
    await acc.grant_role(given_role_value, ACC_USER).execute(caller_address=admin)
    role = (await acc.get_roles(ACC_USER).execute()).result.roles
    assert role == given_role_value

    # Compute value of revoked role
    revoked_role_value = sum([r.value for r in revoked_roles])

    tx = await acc.revoke_role(revoked_role_value, ACC_USER).execute(caller_address=admin)

    # Check event
    assert_event_emitted(tx, acc.contract_address, "RoleRevoked", [revoked_role_value, ACC_USER])

    # Check role
    updated_role = (await acc.get_roles(ACC_USER).execute()).result.roles
    expected_role = given_role_value & (~revoked_role_value)
    assert updated_role == expected_role

    # Check roles remaining
    updated_role_list = [i for i in given_roles if i not in revoked_roles]
    for r in Roles:
        role_value = r.value

        # Check `has_role`
        has_role = (await acc.has_role(role_value, ACC_USER).execute()).result.has_role

        # Check getter
        role_name = r.name.lower()
        getter: Callable = acc.get_contract_function(f"can_{role_name}")
        can_perform_role = (await getter(ACC_USER).execute()).result.authorized

        if r in updated_role_list:
            assert has_role == can_perform_role == TRUE
            await acc.assert_has_role(role_value).execute(caller_address=ACC_USER)
        else:
            assert has_role == can_perform_role == FALSE
            with pytest.raises(
                StarkException,
                match=f"AccessControl: caller is missing role {role_value}",
            ):
                await acc.assert_has_role(role_value).execute(caller_address=ACC_USER)

    # Revoke the role again to confirm behaviour is as intended
    await acc.revoke_role(revoked_role_value, ACC_USER).execute(caller_address=admin)
    updated_role = (await acc.get_roles(ACC_USER).execute()).result.roles
    assert updated_role == expected_role


@pytest.mark.usefixtures("sudo_user")
@pytest.mark.asyncio
async def test_role_actions_unauthorized(acc):
    with pytest.raises(StarkException, match="AccessControl: caller is not admin"):
        await acc.grant_role(SUDO_USER, BAD_GUY).execute(caller_address=BAD_GUY)

    with pytest.raises(StarkException, match="AccessControl: caller is not admin"):
        await acc.revoke_role(SUDO_USER, ACC_USER).execute(caller_address=BAD_GUY)

    with pytest.raises(StarkException, match="AccessControl: can only renounce roles for self"):
        await acc.renounce_role(SUDO_USER, ACC_USER).execute(caller_address=BAD_GUY)


@pytest.mark.parametrize("renounced_roles", ROLES_COMBINATIONS)
@pytest.mark.usefixtures("sudo_user")
@pytest.mark.asyncio
async def test_renounce_role(acc, renounced_roles):
    renounced_role_value = sum([r.value for r in renounced_roles])
    tx = await acc.renounce_role(renounced_role_value, ACC_USER).execute(caller_address=ACC_USER)

    assert_event_emitted(tx, acc.contract_address, "RoleRevoked", [renounced_role_value, ACC_USER])

    # Check role
    updated_role = (await acc.get_roles(ACC_USER).execute()).result.roles
    expected_role = SUDO_USER & (~renounced_role_value)
    assert updated_role == expected_role

    # Check roles remaining
    updated_role_list = [i for i in Roles if i not in renounced_roles]
    for r in Roles:
        role_value = r.value

        # Check `has_role`
        has_role = (await acc.has_role(role_value, ACC_USER).execute()).result.has_role

        # Check getter
        role_name = r.name.lower()
        getter: Callable = acc.get_contract_function(f"can_{role_name}")
        can_perform_role = (await getter(ACC_USER).execute()).result.authorized

        if r in updated_role_list:
            assert has_role == can_perform_role == TRUE
            await acc.assert_has_role(role_value).execute(caller_address=ACC_USER)
        else:
            assert has_role == can_perform_role == FALSE
            with pytest.raises(
                StarkException,
                match=f"AccessControl: caller is missing role {role_value}",
            ):
                await acc.assert_has_role(role_value).execute(caller_address=ACC_USER)
