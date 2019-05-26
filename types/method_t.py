from __future__ import annotations

import re
from dataclasses import InitVar, dataclass
from functools import partial

from binaryninja import (Architecture, BinaryView, Endianness, Function,
                         FunctionParameter, Structure, StructureType, Symbol,
                         SymbolType, Type, log_debug)

from .types import _get_structure_members as get_structure_members
from .types import _lookup_type
from .types import _parse_function_type as parse_function_type
from .types import basic_types
from .types import _get_from_bytes as get_from_bytes

@dataclass
class MethodList:
    address: int
    entsize: int
    count: InitVar[int]
    first: Method
    methods: dict

    @classmethod
    def from_address(cls, address: int, self_type: str, view: BinaryView):
        if address == 0:
            return None

        method_list_t_type = view.types['method_list_t']

        method_list_t = Type.named_type_from_type(
            'method_list_t', method_list_t_type
        )

        method_t = view.types['method_t']

        if view.get_data_var_at(address) is None:
            view.define_user_data_var(address, method_list_t)

        members = get_structure_members(address, method_list_t_type, view)

        methods = dict()
        start = address + method_list_t_type.width
        end = start + members['count'] * method_t.width
        step = method_t.width
        for method_addr in range(start, end, step):
            method = Method.from_address(method_addr, self_type, view)
            if method is not None:
                methods[method.name] = method

        return cls(address, **members, methods=methods)


@dataclass
class Method:
    address: int
    name: str
    types: list
    imp: Function

    @classmethod
    def from_address(cls, address: int, self_type: str, view: BinaryView):
        if address == 0:
            return None

        if self_type not in view.types:
            view.define_user_type(
                self_type, Type.structure_type(Structure())
            )

        method_t_type = view.types['method_t']
        method_t = Type.named_type_from_type(
            'method_t', method_t_type
        )

        if view.get_data_var_at(address) is None:
            view.define_user_data_var(address, method_t)

        members = get_structure_members(address, method_t_type, view)

        members['name'] = (
            view.get_ascii_string_at(members['name'], 1).value
            if members['name'] else ''
        )

        members['types'] = parse_function_type(
            view.get_ascii_string_at(members['types'], 1).value
            if members['types'] else '',
            self_type,
            view
        )

        members['imp'] = view.get_function_at(members['imp'])

        if members['imp'] is not None:
            method_name = f'-[{self_type} {members["name"]}]'

            if view.symbols.get(method_name):
                namespace = f'{members["imp"].start}'
            else:
                namespace = None

            view.define_user_symbol(
                Symbol(
                    SymbolType.FunctionSymbol,
                    members['imp'].start,
                    method_name,
                    namespace=namespace
                )
            )

            if members['types'] is not None:
                members['imp'].function_type = members['types']

        return cls(address, **members)
