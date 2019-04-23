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
from .method_t import MethodList

@dataclass
class ProtocolList:
    address: int
    count: int
    protocols: dict

    @classmethod
    def from_address(cls, address: int, view: BinaryView):
        if address == 0:
            return None

        from_bytes = get_from_bytes(view)

        protocol_list_t_type = view.types['protocol_list_t']

        protocol_list_t = Type.named_type_from_type(
            'protocol_list_t', protocol_list_t_type
        )

        protocol_t = view.types['protocol_t']

        members = get_structure_members(address, protocol_list_t_type, view)

        view.define_user_data_var(address, protocol_list_t)

        protocols = {}
        start = address + protocol_list_t_type.width
        end = start + members['count'] * view.address_size
        step = view.address_size
        for protocol_ptr in range(start, end, step):
            if not view.get_data_var_at(protocol_ptr):
                view.define_user_data_var(
                    protocol_ptr,
                    Type.pointer(view.arch, protocol_t)
                )
            protocol = Protocol.from_address(
                from_bytes(
                    view.read(protocol_ptr, view.address_size)
                ),
                view
            )

            protocols[protocol.name] = protocol

        return cls(address, **members, protocols=protocols)


@dataclass
class Protocol:
    address: int
    isa: Class
    name: str
    protocols: int
    instanceMethods: MethodList
    classMethods: int
    optionalInstanceMethods: int
    optionalClassMethods: int
    instanceProperties: int
    size: int
    flags: int
    extendedMethodTypes: int

    @classmethod
    def from_address(cls, address: int, view: BinaryView) -> Protocol:
        if address == 0:
            return None

        from .class_t import Class

        from_bytes = partial(
            int.from_bytes,
            byteorder=(
                "little"
                if view.endianness == Endianness.LittleEndian
                else "big"
            )
        )

        protocol_t = Type.named_type_from_type(
            'protocol_t', view.types['protocol_t']
        )

        if not view.get_data_var_at(address):
            view.define_user_data_var(
                address,
                protocol_t
            )

        members = {
            m.name: from_bytes(view.read(address + m.offset, m.type.width))
            for m in view.types['protocol_t'].structure.members
        }

        members['isa'] = Class.from_address(members['isa'], view)

        members['name'] = (
            view.get_ascii_string_at(members['name'], 1).value
            if members['name'] != 0 else ''
        )

        if members['name'] not in view.types:
            view.define_user_type(
                members['name'],
                Type.structure_type(Structure())
            )

        members['protocols'] = ProtocolList.from_address(
            members['protocols'], view
        )

        members['instanceMethods'] = MethodList.from_address(
            members['instanceMethods'], members['name'], view
        )

        members['optionalInstanceMethods'] = MethodList.from_address(
            members['optionalInstanceMethods'], members['name'], view
        )

        new_protocol = cls(address, **members)
        view.session_data['Protocols'][new_protocol.name] = new_protocol
        return new_protocol