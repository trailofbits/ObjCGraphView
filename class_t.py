from __future__ import annotations
from dataclasses import dataclass, InitVar

from binaryninja import BinaryView, Endianness, Type, Symbol, SymbolType
from functools import partial
from itertools import takewhile

class _ClassMeta(type):

    _class_list = {}

    @property
    def list(self):
        return dict(_class_list)

    def __call__(cls, address, *args, **kwargs):
        if address not in cls._class_list:
            instance = super().__call__(address, *args, **kwargs)
            cls._class_list[address] = instance
            return instance
        else:
            return cls._class_list[address]

class Class:
    __metaclass__ = _ClassMeta

    list = {}
    classes = {}

    def __init__(self, address: int, view: BinaryView, isa: Class, superclass: Class, vtable: ClassRO):
        self._address = address
        self._view = view
        self._isa = isa
        self._superclass = superclass
        self._vtable = vtable

    @classmethod
    def from_address(cls, address: int, view: BinaryView) -> Class:
        if address == 0:
            return None
        elif address in Class.list:
            return cls.list[address]

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

        new_class = cls(address, view, isa, superclass, vtable)

        cls.classes[vtable.name] = new_class
        cls.list[address] = new_class

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

    def define_type(self):
        class_t = Type.named_type_from_type('class_t', self._view.types['class_t'])

        self._view.define_user_data_var(self._address, class_t)

    def define_methods(self):
        print(f"_define_methods(view, {self.vtable.baseMethods:x})")
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

        self._view.define_user_data_var(
            methods_start,
            Type.array(
                method_t,
                method_count
            )
        )

        start = methods_start
        end = methods_start + method_count * method_t_type.width
        step = method_t_type.width
        for method_addr in range(start, end, step):
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

            method = self._view.get_function_at(imp_ptr)
            print(f"{method_name} {method.function_type}")

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

    def _lookup_type(self, type_string):
        if type_string in basic_types:
            return basic_types[type_string]
        elif type_string == '*':
            return Type.pointer(self._view.arch, Type.char())
        elif type_string.startswith('@'):
            return Type.pointer(self._view.arch, Type.void())
        elif type_string.startswith('#'):
            return Type.pointer(self._view.arch, Type.void())
        elif type_string == ':':
            return self._view.types['SEL']
        else:
            return Type.pointer(self._view.arch, Type.void())

    def _parse_function_type(self, type_string):
        print(type_string)
        # assuming for now that methods don't return an object somehow
        ret_type_str = type_string[0]
        
        if ret_type_str in '[{(':
            ret_type_str += ''.join(
                takewhile(lambda i: not str.isdigit(i), type_string)
            )
        
        type_string = type_string[len(ret_type_str):]

        stack_size = ''.join(takewhile(str.isdigit, type_string))
        type_string = type_string[len(stack_size):]
        stack_size = int(stack_size)
        
        args = []
        while type_string:
            arg_type = ''.join(takewhile(lambda i: not str.isdigit(i), type_string))
            type_string = type_string[len(arg_type):]

            arg_stack_offset = ''.join(takewhile(str.isdigit, type_string))
            type_string = type_string[len(arg_stack_offset):]

            args.append(self._lookup_type(arg_type))

        # we know that the first parameter is the 'self' parameter
        args[0] = Type.pointer(
            self._view.arch,
            Type.named_type_from_type(
                self.vtable.name, self._view.types[self.vtable.name]
            )
        )

        print(args)

        function_type = Type.function(self._lookup_type(ret_type_str), args)

        return function_type

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

basic_types = {
    'c': Type.char(),
    'i': Type.int(4, True),
    's': Type.int(2, True),
    'l': Type.int(4, True),
    'q': Type.int(8, True),
    'C': Type.int(1, False),
    'I': Type.int(4, False),
    'S': Type.int(2, False),
    'L': Type.int(4, False),
    'Q': Type.int(4, False),
    'f': Type.float(4),
    'd': Type.float(8),
    'B': Type.bool(),
    'v': Type.void()
}