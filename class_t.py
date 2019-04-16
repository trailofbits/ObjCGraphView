from __future__ import annotations
from dataclasses import dataclass, InitVar

from binaryninja import BinaryView, Endianness, Type, Symbol, SymbolType, Function, Type, log_info, Structure, StructureType, FunctionParameter
from functools import partial
from itertools import takewhile
from .types import basic_types


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

        from_bytes = partial(
            int.from_bytes,
            byteorder=(
                "little"
                if view.endianness == Endianness.LittleEndian
                else "big"
            )
        )

        members = {
            m.name: m
            for m in view.types['class_t'].structure.members
        }

        m_isa = members['isa']
        m_superclass = members['superclass']
        m_vtable = members['vtable']

        isa = Class.from_address(
            from_bytes(
                view.read(
                    address + m_isa.offset,
                    m_isa.type.width
                )
            ),
            view
        )

        superclass = Class.from_address(
            from_bytes(
                view.read(
                    address + m_superclass.offset,
                    m_superclass.type.width
                )
            ),
            view
        )

        vtable = ClassRO.from_address(
            from_bytes(
                view.read(
                    address + m_vtable.offset,
                    m_vtable.type.width
                )
            ),
            view
        )

        new_class._isa = isa
        new_class._superclass = superclass
        new_class._vtable = vtable

        view.session_data['ClassNames'][vtable.name] = new_class

        return new_class

    def __hash__(self):
        return hash((self._address, self._isa, self._superclass, self._vtable))

    def __repr__(self):
        return f"<Class {self._vtable.name}{' (meta)' if self.is_meta else ''} @ {self._address:x}>"

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

    def define_class_members(self):
        class_ro_t = Type.named_type_from_type(
            'class_ro_t', self._view.types['class_ro_t'])

        if self.vtable.address:
            self._view.define_user_data_var(self.vtable.address, class_ro_t)

            ivar_list = None
            if isinstance(self.vtable.ivars, int) and self.vtable.ivars:
                ivars_start, ivar_count = self._define_ivars()
                self.vtable.ivars = _get_ivars(
                    self._view, ivars_start, ivar_count)

            if not self.is_meta:
                self.define_type()

            if self.vtable.baseMethods:
                self.define_methods()

            if self.vtable.baseProperties:
                self.define_properties()

            if self.vtable.baseProtocols:
                self.define_protocols()

    def define_class_var(self):
        class_t = Type.named_type_from_type(
            'class_t', self._view.types['class_t'])

        self._view.define_user_data_var(self._address, class_t)

    def define_methods(self):
        method_list_t_type = self._view.types['method_list_t']

        count = next(
            m for m in method_list_t_type.structure.members if m.name == 'count')

        method_count = int.from_bytes(
            self._view.read(self.vtable.baseMethods +
                            count.offset, count.type.width),
            "little" if self._view.endianness == Endianness.LittleEndian else "big"
        )

        method_list_t = Type.named_type_from_type(
            'method_list_t', method_list_t_type
        )

        self._view.define_user_data_var(self.vtable.baseMethods, method_list_t)

        methods_start = self.vtable.baseMethods + method_list_t_type.width

        method_t_type = self._view.types['method_t']

        method_t = Type.named_type_from_type(
            'method_t',
            method_t_type
        )

        method_t_members = {m.name: m for m in method_t_type.structure.members}

        name = method_t_members['name']
        imp = method_t_members['imp']
        types = method_t_members['types']

        start = methods_start
        end = methods_start + method_count * method_t_type.width
        step = method_t_type.width
        for method_addr in range(start, end, step):
            self._view.define_user_data_var(method_addr, method_t)
            imp_ptr = int.from_bytes(
                self._view.read(method_addr+imp.offset,
                                self._view.address_size),
                "little" if self._view.endianness == Endianness.LittleEndian else "big"
            )

            name_ptr = int.from_bytes(
                self._view.read(method_addr + name.offset,
                                self._view.address_size),
                "little" if self._view.endianness == Endianness.LittleEndian else "big"
            )

            method_name = self._view.get_ascii_string_at(name_ptr, 2)
            if method_name is not None:
                method_name = f'-[{self.vtable.name} {method_name.value}]'

                self._view.define_user_symbol(
                    Symbol(SymbolType.FunctionSymbol, imp_ptr, method_name)
                )
            else:
                method_name = f'sub_{imp_ptr:x}'

            method = self._view.get_function_at(imp_ptr)

            self._methods[name_ptr] = method

            types_ptr = int.from_bytes(
                self._view.read(method_addr + types.offset, types.type.width),
                "little" if self._view.endianness == Endianness.LittleEndian else "big"
            )

            types_string = self._view.get_ascii_string_at(types_ptr, 2).value
            function_type = parse_function_type(
                types_string, self.vtable.name, self._view
            )

            method.function_type = function_type

    def define_symbol(self):
        if not self.vtable.name:
            return

        if self.is_meta:
            symbol_name = f'_OBJC_METACLASS_$_{self.vtable.name}'
        else:
            symbol_name = f'_OBJC_CLASS_$_{self.vtable.name}'

        self._view.define_user_symbol(
            Symbol(SymbolType.DataSymbol, self._address, symbol_name)
        )

    def _define_ivars(self):
        if not self.vtable.ivars:
            return 0, 0

        log_info(f"_define_ivars(view, {self.vtable.ivars:x})")
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
        # log_info(f"Class.define_type()")

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
            if current_class.vtable.ivars == 0:
                continue

            for ivar in current_class.vtable.ivars:
                type_ = _lookup_type(ivar[2], self._view)
                if type_ is None:
                    type_ = Type.pointer(self._view.arch, Type.void())
                structure.insert(ivar[1], type_, ivar[0])

        self._view.define_user_type(
            self.vtable.name, Type.structure_type(structure))

    def define_properties(self):
        log_info(f"define_properties(view, {self.vtable.baseProperties:x})")
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
        log_info(f"define_protocols(0x{self.vtable.baseProtocols:x})")

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
    baseMethods: object
    baseProtocols: object
    ivars: object
    weakIvarLayout: object
    baseProperties: object

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

        members = {
            m.name: from_bytes(view.read(address + m.offset, m.type.width))
            for m in view.types['class_ro_t'].structure.members
        }

        members['name'] = (
            view.get_ascii_string_at(members['name'], 1).value
            if members['name'] != 0 else ''
        )

        new_class_ro = cls(address, **members)

        view.session_data['ClassROList'][address] = new_class_ro
        return new_class_ro


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

        return cls(address, **members)


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

        return cls(address, **members)


def get_from_bytes(view: BinaryView):
    return partial(
        int.from_bytes,
        byteorder=(
            "little" if view.endianness == Endianness.LittleEndian
            else "big"
        )
    )


def get_structure_members(address: int, t: Type, view: BinaryView) -> dict:
    from_bytes = get_from_bytes(view)

    return {
        m.name: from_bytes(view.read(address + m.offset, m.type.width))
        for m in t.structure.members
    }


def _lookup_type(type_string: str, view: BinaryView):
    if type_string in basic_types:
        return basic_types[type_string]
    elif type_string == '*':
        return Type.pointer(view.arch, Type.char())
    elif type_string.startswith('@'):
        if type_string[2:-1] in view.types:
            return Type.pointer(
                view.arch,
                Type.named_type_from_type(
                    type_string[2:-1],
                    view.types[type_string[2:-1]]
                )
            )
        elif type_string != '@?' and type_string != '@':
            print(type_string)
            print(f"{type_string[2:-1]} not found")
            if type_string[2:-1]:
                new_type = Type.named_type_from_type(
                    type_string[2:-1], Type.structure_type(Structure()))
                view.define_user_type(type_string[2:-1], new_type)
            else:
                new_type = Type.void()
            return Type.pointer(view.arch, new_type)
        else:
            return Type.pointer(view.arch, Type.void())
    elif type_string.startswith('#'):
        return Type.pointer(view.arch, Type.void())
    elif type_string == ':':
        return view.types['SEL']
    else:
        return Type.pointer(view.arch, Type.void())


def parse_function_type(type_string: str, self_name: str, view: BinaryView) -> Type:
    ret_type_str = type_string[0]

    # TODO: this clearly won't work. Need to do much better parsing of
    # complex types.
    if ret_type_str in '[{(':
        ret_type_str += ''.join(
            takewhile(lambda i: not str.isdigit(i), type_string)
        )

    type_string = type_string[len(ret_type_str):]

    stack_size = ''.join(takewhile(str.isdigit, type_string))
    type_string = type_string[len(stack_size):]
    stack_size = int(stack_size) if stack_size else None

    args = []
    while type_string:
        # TODO: does not handle structures passed by value on stack
        arg_type = ''.join(
            takewhile(lambda i: not str.isdigit(i), type_string))
        type_string = type_string[len(arg_type):]

        arg_stack_offset = ''.join(takewhile(str.isdigit, type_string))
        type_string = type_string[len(arg_stack_offset):]

        args.append(_lookup_type(arg_type, view))

    # we know that the first parameter is the 'self' parameter
    args[0] = FunctionParameter(
        Type.pointer(
            view.arch,
            Type.named_type_from_type(
                self_name, view.types[self_name]
            )
        ),
        'self'
    )

    function_type = Type.function(_lookup_type(ret_type_str, view), args)

    return function_type
