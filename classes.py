from .types import define_types_plugin
from .class_t import Class

from binaryninja import log_info, log_error, Type, BinaryView, Symbol, SymbolType, Structure, StructureType, Endianness


def define_classes_plugin(view):
    log_info("define_classes_plugin")

    define_types_plugin(view)

    class_t = Type.named_type_from_type('class_t', view.types.get('class_t'))

    _define_classes(view, class_t)

    if class_t is None:
        log_error("class_t is not defined!")
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
        current_class = Class.from_address(addr, view)
        current_class.define_type()
        current_class.define_symbol()

        _define_class_members(view, current_class)

        log_info(f"name is {current_class.vtable.name}")


def _define_class_members(view: BinaryView, class_: Class):

    class_ro_t = Type.named_type_from_type('class_ro_t', view.types['class_ro_t'])

    if class_.vtable.address:
        view.define_user_data_var(class_.vtable.address, class_ro_t)

        ivar_list = None
        if class_.vtable.ivars:
            ivars_start, ivar_count = _define_ivars(
                view, class_
            )
            class_.vtable.ivars = _get_ivars(view, ivars_start, ivar_count)

        if not class_.is_meta:
            _define_type(view, class_)

        if class_.vtable.baseMethods:
            class_.define_methods()

        # if property_list_addr:
        #     _define_properties(view, property_list_addr)
            

def _define_ivars(view, class_):
    log_info(f"_define_ivars(view, {class_.vtable.ivars:x})")
    ivar_list_t_type = view.types['ivar_list_t']

    count = next(
        m for m in ivar_list_t_type.structure.members if m.name == 'count')

    ivar_count = int.from_bytes(
        view.read(class_.vtable.ivars + count.offset, count.type.width),
        "little"
    )

    ivar_list_t = Type.named_type_from_type('ivar_list_t', ivar_list_t_type)

    view.define_user_data_var(class_.vtable.ivars, ivar_list_t)
    view.define_user_symbol(
        Symbol(SymbolType.DataSymbol, class_.vtable.ivars, f'{class_.vtable.name}_IVARS')
    )

    ivars_start = class_.vtable.ivars + ivar_list_t_type.width

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

    ivar_offset_type = Type.int(view.address_size, False)
    ivar_offset_type.const = True

    for ivar in range(ivars_start, ivars_start + ivar_count * ivar_t.width, ivar_t.width):
        members = { 
            m.name: int.from_bytes(
                view.read(ivar + m.offset, m.type.width),
                "little" if view.endianness is Endianness.LittleEndian else "big"
            )
            for m in view.types['ivar_t'].structure.members
        }

        name = view.get_ascii_string_at(members['name'], 1).value

        view.define_user_symbol(
            Symbol(
                SymbolType.DataSymbol,
                members['offset'],
                f'{name}_offset',
                namespace=class_.vtable.name
            )
        )

        view.define_user_data_var(members['offset'], ivar_offset_type)

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

def _define_type(view: BinaryView, class_: Class):
    log_info(f"_define_type(view, {class_.vtable.name})")

    structure = Structure()
    structure.type = StructureType.ClassStructureType
    structure.width = class_.vtable.instanceSize

    print(f'instanceStart: {class_.vtable.instanceStart:x} instanceSize: {class_.vtable.instanceSize:x}')

    structure.insert(0, Type.pointer(view.arch, Type.void()), 'isa')

    classes = [class_]
    current_superclass = class_.superclass
    while current_superclass:
        classes.append(current_superclass)
        current_superclass = current_superclass.superclass

    while classes:
        current_class = classes.pop()
        if current_class.vtable.ivars == 0:
            continue

        for ivar in current_class.vtable.ivars:
            type_ = _lookup_type(ivar[2])
            if type_ is None:
                type_ = Type.pointer(view.arch, Type.void())
            structure.insert(ivar[1], type_, ivar[0])

    view.define_user_type(class_.vtable.name, Type.structure_type(structure))

basic_types = {
    'c': Type.char(),
    'Q': Type.int(8, False)
}

def _lookup_type(type_string):
    # print(type_string)
    if type_string in basic_types:
        return basic_types[type_string]

    # elif type_string.startswith('@'):
    #     pass
    #     # print(type_string.replace('@', '').replace('"', ''))