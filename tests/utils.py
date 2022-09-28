import os
from functools import cache
from typing import Callable, Iterable, List, Union

from starkware.starknet.business_logic.execution.objects import Event
from starkware.starknet.compiler.compile import compile_starknet_files
from starkware.starknet.public.abi import get_selector_from_name
from starkware.starknet.services.api.contract_class import ContractClass


def here() -> str:
    return os.path.abspath(os.path.dirname(__file__))


def contract_path(rel_contract_path: str) -> str:
    return os.path.join(here(), "..", rel_contract_path)


@cache
def compile_contract(rel_contract_path: str) -> ContractClass:
    contract_src = contract_path(rel_contract_path)
    tld = os.path.join(here(), "..")
    return compile_starknet_files(
        [contract_src],
        debug_info=True,
        disable_hint_validation=True,
        cairo_path=[tld],
    )


def assert_event_emitted(
    tx_exec_info, from_address, name, data: Union[None, Callable[[List[int]], bool], Iterable] = None
):
    key = get_selector_from_name(name)

    if isinstance(data, Callable):
        assert any([data(e.data) for e in tx_exec_info.raw_events if e.from_address == from_address and key in e.keys])
    elif data is not None:
        assert (
            Event(
                from_address=from_address,
                keys=[key],
                data=data,
            )
            in tx_exec_info.raw_events
        )
    else:  # data=None
        assert any([e for e in tx_exec_info.raw_events if e.from_address == from_address and key in e.keys])


def str_to_felt(text: str) -> int:
    b_text = bytes(text, "ascii")
    return int.from_bytes(b_text, "big")
