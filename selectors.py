from binaryninja import PluginCommand, Type, BinaryView, log_debug, log_error

_selector_sections = (
    '__objc_methname',
    '__objc_classname',
    '__objc_methtype'
)

_string_sections = (
    '__cstring'
)


def define_selectors_plugin(view):
    log_debug("define_selectors_plugin")
    _define_strings_in_sections(_selector_sections, view)
    _define_selectors(view)


def define_strings_plugin(view):
    _define_strings_in_sections(_string_sections, view)


def _define_strings_in_sections(sections, view):
    for section_name in sections:
        section = view.sections[section_name]

        for s in view.get_strings(section.start, len(section)):
            view.define_user_data_var(
                s.start, Type.array(Type.char(), s.length+1))


def _define_selectors(view: BinaryView):
    __objc_selrefs = view.sections.get('__objc_selrefs')

    if __objc_selrefs is None:
        raise KeyError('This binary has no __objc_selrefs section')

    SEL = view.get_type_by_name('SEL')
    if SEL is None:
        raise TypeError('The SEL type is not defined!')

    for addr in range(__objc_selrefs.start, __objc_selrefs.end, SEL.width):
        view.define_user_data_var(addr, SEL)
        selector = int.from_bytes(view.read(addr, SEL.width), "little")
        if selector != 0:
            name = view.get_ascii_string_at(selector, 3)
            if name is not None:
                view.define_user_data_var(name.start, Type.array(Type.char(), name.length+1))
