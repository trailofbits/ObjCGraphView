from .types import define_types_plugin

from binaryninja import log_info, log_error, Type, BinaryView, Symbol, SymbolType, Structure, StructureType


def define_classes_plugin(view):
    log_info("define_classes_plugin")

    class_t = view.types.get('class_t')

    if class_t is None:
        define_types_plugin(view)

    class_t = Type.named_type_from_type('class_t', view.types.get('class_t'))

    # Try it one more time...
    if class_t is None:
        log_error("class_t is not defined!")
        return

    try:
        _define_classes(view, class_t)
    except Exception as e:
        log_error(f'{e!s}')
        return


def _define_classes(view, class_t):
    log_info("_define_classes")
    __objc_classrefs = view.sections.get('__objc_classrefs')

    if __objc_classrefs is None:
        raise KeyError('This binary has no __objc_classrefs section')

    for addr in range(__objc_classrefs.start, __objc_classrefs.end, view.address_size):
        view.define_user_data_var(addr, Type.pointer(view.arch, class_t))


    __objc_data = view.sections.get('__objc_data')

    if __objc_data is None:
        raise KeyError('This binary has no __objc_data section')

    class_t_members = {m.name: m for m in view.types[class_t.named_type_reference.name].structure.members}

    isa = class_t_members['isa']

    vtable = class_t_members['vtable']

    p_class_ro_t = vtable.type
    class_ro_t_type = view.types[vtable.type.target.named_type_reference.name]
    class_ro_t = Type.named_type_from_type('class_ro_t', class_ro_t_type)

    class_ro_t_members = {m.name: m for m in class_ro_t_type.structure.members}

    for addr in range(__objc_data.start, __objc_data.end, class_t.width):
        log_info(f"defining {addr:x}")
        view.define_user_data_var(addr, class_t)

        isa_ptr = int.from_bytes(
            view.read(addr + isa.offset, view.address_size),
            "little"
        )

        name = _define_class_members(view, addr, vtable, isa_ptr, class_ro_t, **class_ro_t_members)

        log_info(f"name is {name}")

        if name:
            view.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, name))


def _define_class_members(view: BinaryView, addr, vtable, isa_ptr, class_ro_t, **class_ro_t_members):
    instance_size = class_ro_t_members['instanceSize']
    base_methods = class_ro_t_members['baseMethods']
    ivars = class_ro_t_members['ivars']
    base_properties = class_ro_t_members['baseProperties']
    name = class_ro_t_members['name']

    vtable_ptr = int.from_bytes(
        view.read(addr + vtable.offset, view.address_size),
        "little"
    )

    if vtable_ptr:
        view.define_user_data_var(vtable_ptr, class_ro_t)

        name_ptr = int.from_bytes(
            view.read(vtable_ptr + name.offset, view.address_size),
            "little"
        )

        if name_ptr:
            class_name = view.get_ascii_string_at(name_ptr, 3)
        else:
            class_name = None

        if isa_ptr and class_name is not None:
            name = f'_OBJC_CLASS_$_{class_name.value}'
        elif not isa_ptr and class_name is not None:
            name = f'_OBJC_METACLASS_$_{class_name.value}'
        else:
            name = None

        method_list_addr = int.from_bytes(
            view.read(
                vtable_ptr + base_methods.offset,
                base_methods.type.width
            ),
            "little"
        )

        ivar_list_addr = int.from_bytes(
            view.read(
                vtable_ptr + ivars.offset,
                ivars.type.width
            ),
            "little"
        )

        property_list_addr = int.from_bytes(
            view.read(
                vtable_ptr + base_properties.offset,
                base_properties.type.width
            ),
            "little"
        )

        instance_size = int.from_bytes(
            view.read(
                vtable_ptr + instance_size.offset,
                instance_size.type.width
            ),
            "little"
        )

        if method_list_addr:
            _define_methods(view, class_name.value, method_list_addr)

        ivar_list = None
        if ivar_list_addr:
            ivars_start, ivar_count = _define_ivars(view, ivar_list_addr, name)
            ivar_list = _get_ivars(view, ivars_start, ivar_count)

        if property_list_addr:
            _define_properties(view, property_list_addr)

        if ivar_list:
            _define_type(view, class_name.value, instance_size, ivar_list)

        return name


def _define_methods(view, class_name, method_list_addr):
    log_info(f"_define_methods(view, {method_list_addr:x})")
    method_list_t_type = view.types['method_list_t']

    count = next(
        m for m in method_list_t_type.structure.members if m.name == 'count')

    method_count = int.from_bytes(
        view.read(method_list_addr + count.offset, count.type.width),
        "little"
    )

    method_list_t = Type.named_type_from_type(
        'method_list_t', method_list_t_type)

    view.define_user_data_var(method_list_addr, method_list_t)

    methods_start = method_list_addr + method_list_t_type.width

    method_t_type = view.types['method_t']

    method_t = Type.named_type_from_type(
        'method_t',
        method_t_type
    )

    method_t_members = {m.name: m for m in method_t_type.structure.members}

    name = method_t_members['name']
    imp = method_t_members['imp']

    view.define_user_data_var(
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
            view.read(method_addr+imp.offset, view.address_size),
            "little"
        )

        name_ptr = int.from_bytes(
            view.read(method_addr + name.offset, view.address_size),
            "little"
        )

        method_name = view.get_ascii_string_at(name_ptr, 2)
        if method_name is not None:
            method_name = f'-[{class_name} {method_name.value}]'

            view.define_user_symbol(Symbol(SymbolType.FunctionSymbol, imp_ptr, method_name))

def _define_ivars(view, ivar_list_addr, name):
    log_info(f"_define_ivars(view, {ivar_list_addr:x})")
    ivar_list_t_type = view.types['ivar_list_t']

    count = next(
        m for m in ivar_list_t_type.structure.members if m.name == 'count')

    ivar_count = int.from_bytes(
        view.read(ivar_list_addr + count.offset, count.type.width),
        "little"
    )

    ivar_list_t = Type.named_type_from_type('ivar_list_t', ivar_list_t_type)

    view.define_user_data_var(ivar_list_addr, ivar_list_t)
    view.define_user_symbol(Symbol(SymbolType.DataSymbol, ivar_list_addr, f'{name}_IVARS'))

    ivars_start = ivar_list_addr + ivar_list_t_type.width

    ivar_t = Type.named_type_from_type(
        'ivar_t',
        view.types['ivar_t']
    )

    view.define_user_data_var(
        ivars_start,
        Type.array(
            ivar_t,
            ivar_count
        )
    )

    return ivars_start, ivar_count

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
    log_info(f"_define_properties(view, {property_list_addr:x})")
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

def _define_type(view: BinaryView, name, size, ivars):
    log_info(f"_define_type(view, {name}, {size}, {len(ivars)})")

    structure = Structure()
    structure.type = StructureType.ClassStructureType

    structure.insert(0, Type.pointer(view.arch, Type.void()), 'isa')

    for ivar in ivars:
        type_ = _lookup_type(ivar[2])
        if type_ is None:
            type_ = Type.pointer(view.arch, Type.void())
        structure.insert(ivar[1], type_, ivar[0])

    view.define_user_type(name, Type.structure_type(structure))

basic_types = {
    'c': Type.char(),
    'Q': Type.int(8, False)
}

def _lookup_type(type_string):
    print(type_string)
    if type_string in basic_types:
        return basic_types[type_string]

    elif type_string.startswith('@'):
        print(type_string.replace('@', '').replace('"', ''))