from __future__ import annotations
from dataclasses import dataclass, InitVar

from binaryninja import BinaryView, Endianness, Type, Symbol, SymbolType, Type, log_info, Structure, StructureType, FunctionParameter
from functools import partial
from itertools import takewhile
from .types import basic_types

class Class:
    list = {}
    classes = {}

    def __init__(self, address: int, view: BinaryView, isa: Class, superclass: Class, vtable: ClassRO):
        self._address = address
        self._view = view
        self._isa = isa
        self._superclass = superclass
        self._vtable = vtable
        self._methods = {}

    @classmethod
    def from_address(cls, address: int, view: BinaryView) -> Class:
        if address == 0:
            return None
        elif address in Class.list:
            return cls.list[address]
        else:
            new_class = cls(address, view, None, None, None)
            cls.list[address] = new_class


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

        cls.classes[vtable.name] = new_class

        return new_class

    def __hash__(self):
        return hash((self._address, self._isa, self._superclass, self._vtable))

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

    def define_class_var(self):
        class_t = Type.named_type_from_type('class_t', self._view.types['class_t'])

        self._view.define_user_data_var(self._address, class_t)

    def define_methods(self):
        method_list_t_type = self._view.types['method_list_t']

        count = next(
            m for m in method_list_t_type.structure.members if m.name == 'count')

        method_count = int.from_bytes(
            self._view.read(self.vtable.baseMethods + count.offset, count.type.width),
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
                self._view.read(method_addr+imp.offset, self._view.address_size),
                "little" if self._view.endianness == Endianness.LittleEndian else "big"
            )

            name_ptr = int.from_bytes(
                self._view.read(method_addr + name.offset, self._view.address_size),
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
            function_type = self._parse_function_type(types_string)

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

    def define_class_members(self):

        class_ro_t = Type.named_type_from_type('class_ro_t', self._view.types['class_ro_t'])

        if self.vtable.address:
            self._view.define_user_data_var(self.vtable.address, class_ro_t)

            ivar_list = None
            if self.vtable.ivars:
                ivars_start, ivar_count = self._define_ivars()
                self.vtable.ivars = _get_ivars(self._view, ivars_start, ivar_count)

            if not self.is_meta:
                self.define_type()

            if self.vtable.baseMethods:
                self.define_methods()

            # if property_list_addr:
            #     _define_properties(view, property_list_addr)

    def _define_ivars(self):
        # log_info(f"_define_ivars(view, {self.vtable.ivars:x})")
        ivar_list_t_type = self._view.types['ivar_list_t']

        count = next(
            m for m in ivar_list_t_type.structure.members if m.name == 'count')

        ivar_count = int.from_bytes(
            self._view.read(self.vtable.ivars + count.offset, count.type.width),
            "little"
        )

        ivar_list_t = Type.named_type_from_type('ivar_list_t', ivar_list_t_type)

        self._view.define_user_data_var(self.vtable.ivars, ivar_list_t)
        self._view.define_user_symbol(
            Symbol(SymbolType.DataSymbol, self.vtable.ivars, f'{self.vtable.name}_IVARS')
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

            self._view.define_user_data_var(members['offset'], ivar_offset_type)

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
                type_ = self._lookup_type(ivar[2])
                if type_ is None:
                    type_ = Type.pointer(self._view.arch, Type.void())
                structure.insert(ivar[1], type_, ivar[0])

        self._view.define_user_type(self.vtable.name, Type.structure_type(structure))

    def _lookup_type(self, type_string):
        if type_string in basic_types:
            return basic_types[type_string]
        elif type_string == '*':
            return Type.pointer(self._view.arch, Type.char())
        elif type_string.startswith('@'):
            if type_string[2:-1] in self._view.types:
                return Type.pointer(
                    self._view.arch, 
                    Type.named_type_from_type(
                        type_string[2:-1],
                        self._view.types[type_string[2:-1]]
                    )
                )
            elif type_string != '@?' and type_string != '@':
                print(type_string)
                print(f"{type_string[2:-1]} not found")
                new_type = Type.named_type_from_type(type_string[2:-1], Type.structure_type(Structure()))
                self._view.define_user_type(type_string[2:-1], new_type)
                return Type.pointer(self._view.arch, new_type)
            else:
                return Type.pointer(self._view.arch, Type.void())
        elif type_string.startswith('#'):
            return Type.pointer(self._view.arch, Type.void())
        elif type_string == ':':
            return self._view.types['SEL']
        else:
            return Type.pointer(self._view.arch, Type.void())

    def _parse_function_type(self, type_string):
        ret_type_str = type_string[0]
        
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
            arg_type = ''.join(takewhile(lambda i: not str.isdigit(i), type_string))
            type_string = type_string[len(arg_type):]

            arg_stack_offset = ''.join(takewhile(str.isdigit, type_string))
            type_string = type_string[len(arg_stack_offset):]

            args.append(self._lookup_type(arg_type))

        # we know that the first parameter is the 'self' parameter
        args[0] = FunctionParameter(
            Type.pointer(
                self._view.arch,
                Type.named_type_from_type(
                    self.vtable.name, self._view.types[self.vtable.name]
                )
            ),
            'self'
        )

        function_type = Type.function(self._lookup_type(ret_type_str), args)

        return function_type

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

def _define_properties(view, property_list_addr):
    # log_info(f"_define_properties(view, {property_list_addr:x})")
    property_list_t_type = view.types['property_list_t']

    count = next(
        m for m in property_list_t_type.structure.members if m.name == 'count')

    property_count = int.from_bytes(
        view.read(property_list_addr + count.offset, count.type.width),
        "little"
    )

    property_list_t = Type.named_type_from_type(
        'property_list_t', property_list_t_type)

    view.define_user_data_var(property_list_addr, property_list_t)

    properties_start = property_list_addr + property_list_t_type.width

    property_t = Type.named_type_from_type(
        'property_t',
        view.types['property_t']
    )

    view.define_user_data_var(
        properties_start,
        Type.array(
            property_t,
            property_count
        )
    )

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

    list = {}

    @classmethod
    def from_address(cls, address: int, view: BinaryView):
        if address == 0:
            return None

        elif address in cls.list:
            return cls[address]

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

        cls.list[address] = new_class_ro
        return new_class_ro