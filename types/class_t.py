from __future__ import annotations

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

@dataclass
class Class:
    address: int
    _view: BinaryView
    isa: Class
    superclass: Class
    vtable: ClassRO
    _methods: dict
    _protocols: dict

    @classmethod
    def from_address(cls, address: int, view: BinaryView) -> Class:
        if address == 0:
            return None
        elif address in view.session_data['ClassList']:
            return view.session_data['ClassList'][address]
        else:
            new_class = cls(address, view, None, None, None, {}, {})
            view.session_data['ClassList'][address] = new_class

        from_bytes = get_from_bytes(view)

        members = get_structure_members(address, view.types['class_t'], view)

        isa = Class.from_address(
            members['isa'],
            view
        )
        new_class.isa = isa

        superclass = Class.from_address(
            members['superclass'],
            view
        )
        new_class.superclass = superclass

        vtable = ClassRO.from_address(
            members['vtable'],
            view,
            new_class.is_meta
        )
        new_class.vtable = vtable

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
        
        if vtable and vtable.baseProtocols is not None:
            new_class._protocols = vtable.baseProtocols.protocols

        return new_class

    def __hash__(self):
        return hash((self.address, self.isa, self.superclass, self.vtable))

    def __repr__(self):
        return (
            f"<Class name={self.vtable.name} "
            f"{' (meta)' if self.is_meta else ''}, "
            f"address={self.address}>"
        )

    @property
    def is_meta(self) -> bool:
        return self.isa is None

    @property
    def methods(self) -> dict:
        return dict(self._methods)

    @property
    def protocols(self) -> ProtocolList:
        return dict(self._protocols)

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

@dataclass
class ClassRO:
    address: int
    flags: int
    instanceStart: int
    instanceSize: int
    reserved: int
    ivarLayout: str
    name: str
    baseMethods: MethodList
    baseProtocols: ProtocolList
    ivars: IvarList
    weakIvarLayout: object
    baseProperties: PropertyList

    @classmethod
    def from_address(cls, address: int, view: BinaryView, is_meta=False):
        from .protocol_t import ProtocolList
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
            members['baseMethods'], members['name'], view, is_meta
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
