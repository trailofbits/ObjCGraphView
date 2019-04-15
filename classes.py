from .types import define_types_plugin, basic_types
from .class_t import Class

from binaryninja import log_info, log_error, Type, BinaryView, Symbol, SymbolType, Structure, StructureType, Endianness

def define_classes_plugin(view):
    # log_info("define_classes_plugin")

    define_types_plugin(view)

    class_t = Type.named_type_from_type('class_t', view.types.get('class_t'))

    _define_classes(view, class_t)

    if class_t is None:
        log_error("class_t is not defined!")
        return


def _define_classes(view, class_t):
    # log_info("_define_classes")
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
        # log_info(f"defining {addr:x}")
        current_class = Class.from_address(addr, view)
        current_class.define_class_var()
        current_class.define_symbol()

        current_class.define_class_members()

        # log_info(f"name is {current_class.vtable.name}")