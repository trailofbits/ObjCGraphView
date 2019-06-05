from __future__ import annotations

import re
from dataclasses import InitVar, dataclass
from functools import partial

from binaryninja import (Architecture, BinaryView, Endianness, Function,
                         FunctionParameter, Structure, StructureType, Symbol,
                         SymbolType, Type, log_debug)

from .types import _get_from_bytes as get_from_bytes
from .types import _get_structure_members as get_structure_members
from .types import _lookup_type
from .types import _parse_function_type as parse_function_type
from .types import basic_types


@dataclass
class Property:
    address: int
    name: str
    attributes: str

    @classmethod
    def from_address(cls, address: int, view: BinaryView):
        if address == 0:
            return None

        property_t_type = view.get_type_by_name('property_t')

        if property_t_type is None:
            return

        property_t = Type.named_type_from_type(
            'property_t', property_t_type
        )

        if view.get_data_var_at(address) is None:
            view.define_user_data_var(
                address, property_t
            )

        members = get_structure_members(address, property_t_type, view)

        members['name'] = (
            view.get_ascii_string_at(members['name'], 1).value
            if members['name'] else ''
        )

        members['attributes'] = (
            view.get_ascii_string_at(members['attributes'], 1).value
            if members['attributes'] else ''
        )

        return cls(address, **members)


@dataclass
class PropertyList:
    address: int
    entsize: int
    count: int
    properties: dict

    @classmethod
    def from_address(cls, address: int, view: BinaryView):
        if address == 0:
            return None

        property_list_t_type = view.get_type_by_name('property_list_t')

        property_list_t = Type.named_type_from_type(
            'property_list_t', property_list_t_type
        )

        property_t = view.get_type_by_name('property_t')

        if view.get_data_var_at(address) is None:
            view.define_user_data_var(address, property_list_t)

        members = get_structure_members(address, property_list_t_type, view)

        properties = dict()
        start = address + property_list_t_type.width
        end = start + members['count'] * property_t.width
        step = property_t.width
        for property_addr in range(start, end, step):
            property_ = Property.from_address(property_addr, view)
            if property_ is not None:
                properties[property_.name] = property_

        return cls(address, **members, properties=properties)
