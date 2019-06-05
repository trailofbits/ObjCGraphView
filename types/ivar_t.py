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
class IvarList:
    address: int
    entsize: int
    count: int
    ivars: dict

    @classmethod
    def from_address(cls, address: int, class_name: str, view: BinaryView):
        if address == 0:
            return None

        from_bytes = get_from_bytes(view)

        ivar_list_t_type = view.get_type_by_name('ivar_list_t')

        ivar_list_t = Type.named_type_from_type(
            'ivar_list_t', ivar_list_t_type
        )

        ivar_t = view.get_type_by_name('ivar_t')

        members = get_structure_members(address, ivar_list_t_type, view)

        view.define_user_data_var(address, ivar_list_t)

        ivars = {}
        start = address + ivar_list_t_type.width
        end = start + members['count'] * ivar_t.width
        step = ivar_t.width
        for ivar in range(start, end, step):
            new_ivar = Ivar.from_address(ivar, class_name, view)
            ivars[new_ivar.name] = new_ivar

        return cls(address, **members, ivars=ivars)


@dataclass
class Ivar:
    address: int
    offset: int
    name: str
    type: Type
    alignment: int
    size: int

    @classmethod
    def from_address(cls, address: int, class_name: str, view: BinaryView):
        if address == 0:
            return None

        from_bytes = get_from_bytes(view)

        ivar_t_type = view.get_type_by_name('ivar_t')
        ivar_t = Type.named_type_from_type(
            'ivar_t', ivar_t_type
        )

        members = get_structure_members(address, ivar_t_type, view)
        member_dict = {m.name: m for m in ivar_t_type.structure.members}

        # x64 uses uint64_t for offset, but everything else
        # uses uint32_t
        ivar_offset_type = (
            member_dict['offset'].type.target
            if view.arch != Architecture['x86_64']
            else Type.int(8, False)
        )
        ivar_offset_type.const = True

        if view.get_data_var_at(address) is None:
            view.define_user_data_var(address, ivar_t)

        if members['name'] != 0:
            name_string = view.get_ascii_string_at(members['name'], 1)
            if name_string is not None:
                members['name'] = name_string.value
        else:
            members['name'] = ''

        if members['type']:
            type_string = view.get_ascii_string_at(members['type'], 1).value
            members['type'] = _lookup_type(type_string, view)

        if not members['type']:
            members['type'] = Type.pointer(view.arch, Type.void())

        if members['offset']:
            view.define_user_data_var(members['offset'], ivar_offset_type)
            view.define_user_symbol(
                Symbol(
                    SymbolType.DataSymbol,
                    members['offset'],
                    f'{members["name"]}_offset',
                    namespace=class_name
                )
            )
            members['offset'] = from_bytes(
                view.read(members['offset'],
                          member_dict['offset'].type.target.width)
            )
        else:
            members['offset'] = None

        return cls(address, **members)