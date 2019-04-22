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
from .ivar_t import IvarList
from .method_t import MethodList
from .property_t import PropertyList
from .protocol_t import ProtocolList

class Class:
    def __init__(self, address: int, view: BinaryView, isa: Class, superclass: Class, vtable: ClassRO):
        self._address = address
        self._view = view
        self._isa = isa
        self._superclass = superclass
        self._vtable = vtable
        self._methods = {}
        self._protocols = None

    @classmethod
    def from_address(cls, address: int, view: BinaryView) -> Class:
        if address == 0:
            return None
        elif address in view.session_data['ClassList']:
            return view.session_data['ClassList'][address]
        else:
            new_class = cls(address, view, None, None, None)
            view.session_data['ClassList'][address] = new_class

        from_bytes = get_from_bytes(view)

        members = get_structure_members(address, view.types['class_t'], view)

        isa = Class.from_address(
            members['isa'],
            view
        )

        superclass = Class.from_address(
            members['superclass'],
            view
        )

        vtable = ClassRO.from_address(
            members['vtable'],
            view
        )

        new_class._isa = isa
        new_class._superclass = superclass
        new_class._vtable = vtable

        class_t = Type.named_type_from_type(
            'class_t', view.types['class_t'])

        view.define_user_data_var(address, class_t)

        if not new_class.is_meta:
            view.session_data['ClassNames'][vtable.name] = new_class
        else:
            view.session_data['ClassNames'][f"{vtable.name}_meta"] = new_class

        if not new_class.is_meta:
            new_class.define_type()
            symbol_name = f'_OBJC_CLASS_$_{vtable.name}'
        else:
            symbol_name = f'_OBJC_METACLASS_$_{vtable.name}'        

        view.define_user_symbol(
            Symbol(SymbolType.DataSymbol, address, symbol_name)
        )

        if vtable and vtable.baseMethods is not None:
            new_class._methods = vtable.baseMethods.methods

        return new_class

    def __hash__(self):
        return hash((self._address, self._isa, self._superclass, self._vtable))

    def __repr__(self):
        print(self._vtable, self._address, self.is_meta)
        return (
            f"<Class name={self._vtable.name} "
            f"{' (meta)' if self.is_meta else ''}, "
            f"address={self._address}>"
        )

    @property
    def isa(self) -> Class:
        return self._isa

    @property
    def superclass(self) -> Class:
        return self._superclass

    @property
    def vtable(self) -> ClassRO:
        return self._vtable

    @property
    def is_meta(self) -> bool:
        return self._isa is None

    @property
    def methods(self) -> dict:
        return dict(self._methods)

    @property
    def protocols(self) -> ProtocolList:
        return self._protocols

    def _define_ivars(self):
        if not self.vtable.ivars:
            return 0, 0

        log_debug(f"_define_ivars(view, {self.vtable.ivars:x})")
        ivar_list_t_type = self._view.types['ivar_list_t']

        count = next(
            m for m in ivar_list_t_type.structure.members if m.name == 'count')

        ivar_count = int.from_bytes(
            self._view.read(self.vtable.ivars +
                            count.offset, count.type.width),
            "little"
        )

        ivar_list_t = Type.named_type_from_type(
            'ivar_list_t', ivar_list_t_type)

        self._view.define_user_data_var(self.vtable.ivars, ivar_list_t)
        self._view.define_user_symbol(
            Symbol(SymbolType.DataSymbol, self.vtable.ivars,
                   f'{self.vtable.name}_IVARS')
        )

        ivars_start = self.vtable.ivars + ivar_list_t_type.width

        ivar_t = Type.named_type_from_type(
            'ivar_t',
            self._view.types['ivar_t']
        )

        self._view.define_user_data_var(
            ivars_start,
            Type.array(
                ivar_t,
                ivar_count
            )
        )

        ivar_offset_type = Type.int(self._view.address_size, False)
        ivar_offset_type.const = True

        for ivar in range(ivars_start, ivars_start + ivar_count * ivar_t.width, ivar_t.width):
            members = {
                m.name: int.from_bytes(
                    self._view.read(ivar + m.offset, m.type.width),
                    "little" if self._view.endianness is Endianness.LittleEndian else "big"
                )
                for m in self._view.types['ivar_t'].structure.members
            }

            name = self._view.get_ascii_string_at(members['name'], 1).value

            self._view.define_user_symbol(
                Symbol(
                    SymbolType.DataSymbol,
                    members['offset'],
                    f'{name}_offset',
                    namespace=self.vtable.name
                )
            )

            self._view.define_user_data_var(
                members['offset'], ivar_offset_type)

        return ivars_start, ivar_count

    def define_type(self):
        structure = Structure()
        structure.type = StructureType.ClassStructureType
        structure.width = self.vtable.instanceSize

        structure.insert(0, Type.pointer(self._view.arch, Type.void()), 'isa')

        classes = [self]
        current_superclass = self.superclass
        while current_superclass:
            classes.append(current_superclass)
            current_superclass = current_superclass.superclass

        while classes:
            current_class = classes.pop()
            if current_class.vtable.ivars is None:
                continue

            ivar_list = current_class.vtable.ivars
            for name, ivar in ivar_list.ivars.items():
                structure.insert(ivar.offset, ivar.type, name)

        self._view.define_user_type(
            self.vtable.name, Type.structure_type(structure))

    def define_properties(self):
        log_debug(f"define_properties(view, {self.vtable.baseProperties:x})")
        property_list_t_type = self._view.types['property_list_t']

        count = next(
            m for m in property_list_t_type.structure.members if m.name == 'count')

        property_count = int.from_bytes(
            self._view.read(self.vtable.baseProperties +
                            count.offset, count.type.width),
            "little"
        )

        property_list_t = Type.named_type_from_type(
            'property_list_t', property_list_t_type)

        self._view.define_user_data_var(
            self.vtable.baseProperties, property_list_t)

        properties_start = self.vtable.baseProperties + property_list_t_type.width

        property_t = Type.named_type_from_type(
            'property_t',
            self._view.types['property_t']
        )

        self._view.define_user_data_var(
            properties_start,
            Type.array(
                property_t,
                property_count
            )
        )

    def define_protocols(self):
        log_debug(f"define_protocols(0x{self.vtable.baseProtocols:x})")

        self._protocols = ProtocolList.from_address(
            self.vtable.baseProtocols, self._view)


def _get_ivars(view, ivars_start, ivar_count):
    ivars = []

    ivar_t_type = view.types['ivar_t']

    ivar_members = {m.name: m for m in ivar_t_type.structure.members}

    for addr in range(ivars_start, ivars_start + ivar_count * ivar_t_type.width, ivar_t_type.width):
        offset = ivar_members['offset']
        name = ivar_members['name']
        type_ = ivar_members['type']

        offset_target = int.from_bytes(
            view.read(addr + offset.offset, offset.type.width),
            "little"
        )

        offset_value = int.from_bytes(
            view.read(offset_target, offset.type.target.width),
            "little"
        )

        name_target = int.from_bytes(
            view.read(addr + name.offset, name.type.width),
            "little"
        )

        name_value = view.get_ascii_string_at(name_target, 2).value

        type_target = int.from_bytes(
            view.read(addr + type_.offset, type_.type.width),
            "little"
        )

        type_value = view.get_ascii_string_at(type_target, 1).value

        ivars.append((name_value, offset_value, type_value))

    return ivars

@dataclass
class ClassRO:
    address: int
    flags: int
    instanceStart: int
    instanceSize: int
    reserved: int
    ivarLayout: str
    name: str
    baseMethods: MethodLIst
    baseProtocols: ProtocolList
    ivars: IvarList
    weakIvarLayout: object
    baseProperties: PropertyList

    @classmethod
    def from_address(cls, address: int, view: BinaryView):
        if address == 0:
            return None

        elif address in view.session_data['ClassROList']:
            return view.session_data['ClassROList']

        from_bytes = partial(
            int.from_bytes,
            byteorder=(
                "little"
                if view.endianness == Endianness.LittleEndian
                else "big"
            )
        )

        class_ro_t = Type.named_type_from_type(
            'class_ro_t', view.types['class_ro_t']
        )

        if view.get_data_var_at(address) is None:
            view.define_user_data_var(
                address, class_ro_t
            )

        members = {
            m.name: from_bytes(view.read(address + m.offset, m.type.width))
            for m in view.types['class_ro_t'].structure.members
        }

        members['name'] = (
            view.get_ascii_string_at(members['name'], 1).value
            if members['name'] != 0 else ''
        )

        members['ivarLayout'] = (
            view.get_ascii_string_at(members['ivarLayout'], 1).value
            if members['ivarLayout'] != 0 else ''
        )

        members['ivars'] = IvarList.from_address(
            members['ivars'], members['name'], view
        )

        members['baseMethods'] = MethodList.from_address(
            members['baseMethods'], members['name'], view
        )

        members['baseProtocols'] = ProtocolList.from_address(
            members['baseProtocols'], view
        )

        members['baseProperties'] = PropertyList.from_address(
            members['baseProperties'], view
        )

        new_class_ro = cls(address, **members)

        view.session_data['ClassROList'][address] = new_class_ro
        return new_class_ro
