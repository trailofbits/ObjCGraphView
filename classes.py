from binaryninja import (BinaryView, Endianness, Structure, StructureType,
                         Symbol, SymbolType, Type, log_debug, log_error)

from .types import Category, Class, Protocol, basic_types, define_types_plugin


def define_classes_plugin(view):
    log_debug("define_classes_plugin")

    define_types_plugin(view)

    view.session_data['ClassList'] = {}
    view.session_data['ClassNames'] = {}
    view.session_data['ClassROList'] = {}
    view.session_data['Protocols'] = {}

    class_t = Type.named_type_from_type('class_t', view.types.get('class_t'))

    if class_t is None:
        log_error("class_t is not defined!")
        return

    _define_classes(view, class_t)
    _define_protocols(view)
    _define_categories(view)


def _define_classes(view: BinaryView, class_t: Type):
    __objc_data = view.sections.get('__objc_data')

    if __objc_data is None:
        raise KeyError('This binary has no __objc_data section')

    for addr in range(__objc_data.start, __objc_data.end, class_t.width):
        current_class = Class.from_address(addr, view)

        log_debug(f"Created {current_class}")

    __objc_classrefs = view.sections.get('__objc_classrefs')

    if __objc_classrefs is None:
        raise KeyError('This binary has no __objc_classrefs section')

    for addr in range(__objc_classrefs.start, __objc_classrefs.end, view.address_size):
        view.define_user_data_var(addr, Type.pointer(view.arch, class_t))

        class_addr = int.from_bytes(
            view.read(addr, view.address_size),
            "little" if view.endianness is Endianness.LittleEndian else "big"
        )

        class_ = view.session_data['ClassList'].get(
            class_addr) if class_addr else None

        if class_ is not None:
            log_debug(f"{addr:x} points to {class_!r}")
            view.define_user_symbol(
                Symbol(
                    SymbolType.DataSymbol,
                    addr,
                    f"_OBJC_CLASS_$_{class_.vtable.name}@GOT"
                )
            )


def _define_protocols(view: BinaryView):
    __objc_protorefs = view.sections.get('__objc_protorefs')

    if __objc_protorefs is None:
        return

    protocol_t = Type.named_type_from_type(
        'protocol_t', view.types['protocol_t']
    )

    for address in range(__objc_protorefs.start, __objc_protorefs.end, view.address_size):
        view.define_user_data_var(address, Type.pointer(view.arch, protocol_t))

        protocol_ptr = int.from_bytes(
            view.read(address, view.address_size),
            "little" if view.endianness is Endianness.LittleEndian else "big"
        )

        new_protocol = Protocol.from_address(protocol_ptr, view)


def _define_categories(view: BinaryView):
    __objc_catlist = view.sections.get('__objc_catlist')

    if __objc_catlist is None:
        return

    category_t = Type.named_type_from_type(
        'category_t', view.types['category_t']
    )

    for address in range(__objc_catlist.start, __objc_catlist.end, view.address_size):
        view.define_user_data_var(address, Type.pointer(view.arch, category_t))

        category_ptr = int.from_bytes(
            view.read(address, view.address_size),
            "little" if view.endianness is Endianness.LittleEndian else "big"
        )

        new_category = Category.from_address(category_ptr, view)
