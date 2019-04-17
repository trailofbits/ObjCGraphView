from binaryninja import (DataRenderer, DisassemblyTextLine,
                         InstructionTextToken, InstructionTextTokenType,
                         log_debug, Type, BinaryView)

_cfstring_definition = '''
struct CFString
{
    void* isa;
    int32_t info;
    void* buffer;
    int64_t length;
};
'''


def define_cfstrings_plugin(view: BinaryView):
    log_debug("define_cfstrings_plugin")
    cfstring_type = view.types.get('CFString')
    if cfstring_type is None:
        cfstring_type = view.platform.parse_types_from_source(
            _cfstring_definition
        ).types['CFString']
        
        view.define_user_type('CFString', cfstring_type)
    
    cfstring = Type.named_type_from_type('CFString', cfstring_type)

    __cfstring = view.sections['__cfstring']

    buffer = next(m for m in cfstring_type.structure.members if m.name == 'buffer')
    length = next(m for m in cfstring_type.structure.members if m.name == 'length')

    for addr in range(__cfstring.start, __cfstring.end, cfstring_type.width):
        view.define_user_data_var(addr, cfstring)

        for xref in view.get_data_refs(addr):
            view.define_user_data_var(xref, Type.pointer(view.arch, cfstring))
        
        string_pointer = int.from_bytes(
            view.read(addr + buffer.offset, buffer.type.width),
            "little"
        )

        string_length = int.from_bytes(
            view.read(addr + length.offset, length.type.width),
            "little"
        )

        view.define_user_data_var(
            string_pointer,
            Type.array(Type.char(), string_length+1)
        )


class CFStringDataRenderer(DataRenderer):
    def __init__(self):
        DataRenderer.__init__(self)

    def perform_is_valid_for_data(self, ctxt, view, addr, type, context):
        return DataRenderer.is_type_of_struct_name(type, "CFString", context)

    def perform_get_lines_for_data(self, ctxt, view, addr, type, prefix, width, context):
        prefix.append(InstructionTextToken(
            InstructionTextTokenType.TextToken, "I'm in ur CFString"))
        log_debug(f'{addr:08x} {prefix!r}')
        return [DisassemblyTextLine(prefix, addr)]

    def __del__(self):
        pass


# CFStringDataRenderer().register_type_specific()
