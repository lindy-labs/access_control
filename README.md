# Member-based access control library for Cairo

![tests](https://github.com/lindy-labs/cairo-accesscontrol/actions/workflows/tests.yml/badge.svg)

This library is an implementation of member-based access control in Cairo for [StarkNet](https://www.cairo-lang.org/docs/), which allows an address to be assigned multiple roles using a single storage mapping. 

The design of this library was originally inspired by OpenZeppelin's [access control library](https://github.com/OpenZeppelin/cairo-contracts/tree/main/src/openzeppelin/access/accesscontrol), as well as Python's [flags](https://docs.python.org/3/library/enum.html) and Vyper's [enums](https://docs.python.org/3/library/enum.html).

## Overview

This library uses felt values in the form of 2<sup>n</sup>, where `n` is in the range `0 <= n <= 251`, to represent user-defined roles as members. 

Roles should be defined in a separate Cairo contract as its own namespace. For example:

```cairo
namespace Roles {
    const MANAGER = 2 ** 0;
    const STAFF = 2 ** 1;
    const USER = 2 ** 2;
}
```

Multiple roles can be represented as a single value by performing bitwise AND. Using the above example, an address can be assigned both the `MANAGER` and `STAFF` roles using a single value of 3 (equivalent to `Roles.MANAGER | Roles.STAFF` or `2 ** 0 + 2 ** 1`).

Similarly, multiple roles can be granted, revoked or checked for in a single transaction using bitwise operations:
- granting role(s) is a bitwise AND operation of the currently assigned value and the value of the new role(s);
- revoking role(s) is a bitwise AND operation of the currently assigned value and the complement (bitwise NOT) of the value of the role(s) to be revoked; and
- checking for membership is a bitwise OR operation of the currently assigned value and the value of the role(s) being checked for.

Note that functions which rely on this access control library will require the `bitwise_ptr` implicit argument and `BitwiseBuiltin`.


## Usage

To use this library in a Cairo contract:
1. Include a copy of `accesscontrol_library.cairo` in your project, and import the library into the Cairo contract.
2. Define the available roles as constants in a namespace in a separate Cairo contract, and import this namespace into the Cairo contract.

For example, assuming you have a `contracts/` folder with `accesscontrol_library.cairo` and `roles.cairo`, and you want to import both into a Cairo file within the same folder:

```cairo
%lang starknet

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin
from contracts.accesscontrol_library import AccessControl
from contracts.roles import Roles

@view
func is_manager{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(user: felt) -> (authorized: felt) {
    let authorized: felt = AccessControl.has_role(Roles.MANAGER, user);
    return (authorized,);
}

@external
func authorize{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    role: felt, user: felt
) {
    AccessControl.assert_admin();
    AccessControl._grant_role(role, user);
    return ();
}

@external
func manager_only_action{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() {
    AccessControl.assert_has_role(Roles.MANAGER);
    // Insert logic here
    return ();
}
```

You can also refer to the test file `tests/test_accesscontrol.cairo` for another example.

We have also included a set of external and view functions in `accesscontrol_external.cairo` that you can import into your Cairo contracts. 

## Development

### Set up the project

Clone the repository

```bash
git clone git@github.com:lindy-labs/cairo-accesscontrol.git
```

`cd` into it and create a Python virtual environment:

```bash
cd cairo-accesscontrol
python3 -m venv env
source env/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

### Run tests

To run the tests:

```bash
pytest
```

## Formal Verification
The Access Control library is not currently formally verified, but it will soon be formally verified by Lindy Labs' formal verification unit. 


## Contribute

We welcome contributions of any kind! Please feel free to submit an issue or open a PR if you have a solution to an existing bug.

## License

This library is released under the [MIT License](LICENSE).
