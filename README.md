# Member-based access control library for Cairo

![tests](https://github.com/lindy-labs/cairo-accesscontrol/actions/workflows/tests.yml/badge.svg)

This library implements member-based access control as a component in Cairo for [StarkNet](https://www.cairo-lang.org/docs/), which allows an address to be assigned multiple roles using a single storage mapping. 

The design of this library was originally inspired by OpenZeppelin's [access control library](https://github.com/OpenZeppelin/cairo-contracts), as well as Python's [flags](https://docs.python.org/3/library/enum.html) and Vyper's [enums](https://docs.vyperlang.org/en/stable/types.html#enums).

## Overview

This library uses `u128` values in the form of 2<sup>n</sup>, where `n` is in the range `0 <= n < 128`, to represent user-defined roles as members. 

We recommend users to define the roles in a standalone Cairo contract as its own namespace. For example:

```cairo
mod roles {
    const MANAGER: u128 = 1;
    const STAFF: u128 = 2;
    const USER: u128 = 4;
}
```

Multiple roles can be represented as a single value by performing bitwise AND. Using the above example, an address can be assigned both the `MANAGER` and `STAFF` roles using a single value of 3 (equivalent to `roles.MANAGER | roles.STAFF` or `2 ** 0 + 2 ** 1`).

Similarly, multiple roles can be granted, revoked or checked for in a single transaction using bitwise operations:
- granting role(s) is a bitwise AND operation of the currently assigned value and the value of the new role(s);
- revoking role(s) is a bitwise AND operation of the currently assigned value and the complement (bitwise NOT) of the value of the role(s) to be revoked; and
- checking for membership is a bitwise OR operation of the currently assigned value and the value of the role(s) being checked for.

## Usage

To use this library, add the repository as a dependency in your `Scarb.toml`:

```
[dependencies]
wadray = { git = "https://github.com/lindy-labs/cairo-wadray.git" }
```

Next, define the available roles as constants in a module in a separate Cairo file, and import this module into the Cairo contract.
```cairo
mod user_roles {
    const MANAGER: u128 = 1;
    const STAFF: u128 = 2;
    const USER: u128 = 4;
}
```
then import both the component and the roles into your Cairo contract

For example, assuming you have a `src/` folder with the roles defined in a `user_roles` module in `roles.cairo`:

```
use starknet::ContractAddress;

#[starknet::interface]
trait IMockContract<TContractState> {
    fn is_manager(self: @TContractState, user: ContractAddress) -> bool;
}

#[starknet::contract]
mod mock_contract {
    use access_control::access_control::access_control_component;
    use src::roles::user_roles;
    use starknet::ContractAddress;
    use super::IMockContract;

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

    #[abi(embed_v0)]
    impl IMockContractImpl of IMockContract<ContractState> {
        fn is_manager(self: @ContractState, user: ContractAddress) -> bool {
            self.access_control.has_role(user_roles::MANAGER, user)
        }
    }
}
```

## Development

### Prerequisites

- [Cairo](https://github.com/starkware-libs/cairo)
- [Scarb](https://docs.swmansion.com/scarb)
- [Starknet Foundry](https://github.com/foundry-rs/starknet-foundry)

### Run tests

To run the tests:

```bash
scarb test
```

## Formal Verification
The Access Control library is not currently formally verified, but it will soon be formally verified by Lindy Labs' formal verification unit. 


## Contribute

We welcome contributions of any kind! Please feel free to submit an issue or open a PR if you have a solution to an existing bug.

## License

This library is released under the [MIT License](LICENSE).
