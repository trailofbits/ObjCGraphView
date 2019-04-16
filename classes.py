from .types import define_types_plugin, basic_types
from .class_t import Class

from binaryninja import log_info, log_error, Type, BinaryView, Symbol, SymbolType, Structure, StructureType, Endianness

def define_classes_plugin(view):
    # log_info("define_classes_plugin")

    define_types_plugin(view)

    view.session_data['ClassList'] = {}
    view.session_data['ClassNames'] = {}
    view.session_data['ClassROList'] = {}

    class_t = Type.named_type_from_type('class_t', view.types.get('class_t'))

    _define_classes(view, class_t)

    if class_t is None:
        log_error("class_t is not defined!")
        return


def _define_classes(view: BinaryView, class_t: Type):
    __objc_data = view.sections.get('__objc_data')

    if __objc_data is None:
        raise KeyError('This binary has no __objc_data section')

    for addr in range(__objc_data.start, __objc_data.end, class_t.width):
        # log_info(f"defining {addr:x}")
        current_class = Class.from_address(addr, view)
        current_class.define_class_var()
        current_class.define_symbol()

        current_class.define_class_members()

        print(f"Created {current_class}")

    __objc_classrefs = view.sections.get('__objc_classrefs')

    if __objc_classrefs is None:
        raise KeyError('This binary has no __objc_classrefs section')

    for addr in range(__objc_classrefs.start, __objc_classrefs.end, view.address_size):
        view.define_user_data_var(addr, Type.pointer(view.arch, class_t))

        class_addr = int.from_bytes(
            view.read(addr, view.address_size),
            "little" if view.endianness is Endianness.LittleEndian else "big"
        )

        class_ = view.session_data['ClassList'].get(class_addr) if class_addr else None

        if class_ is not None:
            print(f"{addr:x} points to {class_!r}")
            view.define_user_symbol(
                Symbol(
                    SymbolType.DataSymbol,
                    addr,
                    f"_OBJC_CLASS_$_{class_.vtable.name}@GOT"
                )
            )