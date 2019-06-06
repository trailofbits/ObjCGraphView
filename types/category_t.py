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
from .protocol_t import ProtocolList

@dataclass
class Category:
    address: int
    name: str
    cls: Class
    instanceMethods: MethodList
    classMethods: MethodList
    protocols: ProtocolList
    instanceProperties: int

    @classmethod
    def from_address(cls, address: int, view: BinaryView) -> Category:
        if address == 0:
            return None

        from .class_t import Class, ClassRO

        category_t_type = view.get_type_by_name('category_t')

        if category_t_type is None:
            return

        category_t = Type.named_type_from_type(
            'category_t', category_t_type
        )

        if view.get_data_var_at(address) is None:
            view.define_user_data_var(address, category_t)

        members = get_structure_members(address, category_t_type, view)

        members['name'] = (
            view.get_ascii_string_at(members['name'], 1).value
            if members['name'] else ''
        )

        members['cls'] = Class.from_address(
            members['cls'], view
        )

        if members['cls'] is None:
            cls_offset = next(
                m.offset for m in category_t_type.structure.members
                if m.name == 'cls'
            )
            cls_name = view.get_symbol_at(address + cls_offset)
            cls_name = cls_name.name if cls_name is not None else members['name']

            class_match = re.match(
                r'_OBJC_(META)?CLASS_\$_(?P<classname>[_A-Za-z0-9=/]+)(@GOT)?',
                cls_name
            )
            if class_match is not None:
                cls_name = class_match.group('classname')
                cls_ = view.session_data['ClassNames'].get(cls_name)
                if cls_ is None:
                    cls_ = Class(None, view, None, None, None, {}, {})
                    cls_.vtable = ClassRO(address, *([None]*11))
                    cls_.vtable.name = cls_name
                    view.session_data['ClassNames'][cls_name] = cls_

                members['cls'] = cls_
        else:
            cls_name = members['cls'].vtable.name

        members['instanceMethods'] = MethodList.from_address(
            members['instanceMethods'], cls_name, view
        )

        if members['cls'] is not None and not members['cls'].methods:
            if members['instanceMethods'] is None:
                members['cls']._methods = {}
            else:
                members['cls']._methods = members['instanceMethods'].methods
        elif members['cls'] is not None and members['instanceMethods']:
            members['cls']._methods.update(members['instanceMethods'].methods)

        members['protocols'] = ProtocolList.from_address(
            members['protocols'], view
        )

        return cls(address, **members)