from functools import partial

from binaryninja import (BinaryView, DataRenderer, DisassemblyTextLine,
                         Endianness, InstructionTextToken,
                         InstructionTextTokenType, Type, log_debug)


def _get_from_bytes(view: BinaryView):
    return partial(
        int.from_bytes,
        byteorder=(
            "little" if view.endianness == Endianness.LittleEndian
            else "big"
        )
    )


_cfstring_definition = '''
struct CFString
{
    void* isa;
    int32_t info;
    void* buffer;
    size_t length;
};
'''


def define_cfstrings_plugin(view: BinaryView):
    log_debug("define_cfstrings_plugin")

    from_bytes = _get_from_bytes(view)

    cfstring_type = view.types.get('CFString')
    if cfstring_type is None:
        cfstring_type = view.platform.parse_types_from_source(
            _cfstring_definition
        ).types['CFString']

        view.define_user_type('CFString', cfstring_type)

    cfstring = Type.named_type_from_type('CFString', cfstring_type)

    __cfstring = view.sections['__cfstring']

    buffer = cfstring_type.structure['buffer']
    length = cfstring_type.structure['length']

    for addr in range(__cfstring.start, __cfstring.end, cfstring_type.width):
        view.define_user_data_var(addr, cfstring)

        for xref in view.get_data_refs(addr):
            view.define_user_data_var(xref, Type.pointer(view.arch, cfstring))

        string_pointer = from_bytes(
            view.read(addr + buffer.offset, buffer.type.width)
        )

        string_length = from_bytes(
            view.read(addr + length.offset, length.type.width),
        )

        view.define_user_data_var(
            string_pointer,
            Type.array(Type.char(), string_length+1)
        )

_cfstring_allocator_properties = {
    0: 'inline',
    1: 'noinline,default',
    2: "noinline,nofree",
    3: 'noinline,custom'
}

class CFStringDataRenderer(DataRenderer):
    def __init__(self):
        DataRenderer.__init__(self)

    def perform_is_valid_for_data(self, ctxt, view: BinaryView, addr: int, type_: Type, context):
        return DataRenderer.is_type_of_struct_name(type_, "CFString", context)

    def perform_get_lines_for_data(self, ctxt, view: BinaryView, addr: int, type_: Type, prefix: list, width: int, context):
        from_bytes = _get_from_bytes(view)

        symbol: Symbol = view.get_symbol_at(addr)

        cfstring = view.types.get('CFString')

        if cfstring is None:
            log_debug('CFString is not defined; how did we even get here?')
            return [DisassemblyTextLine(prefix, addr)]

        cfstring = cfstring.structure

        buffer = from_bytes(
            view.read(addr + cfstring['buffer'].offset, view.address_size)
        )

        info = from_bytes(
            view.read(
                addr + cfstring['info'].offset,
                cfstring['info'].type.width)
        )

        if info & 0xff == 0xc8:
            info_string = 'noinline,default,nofree,NI'
        elif info & 0xff == 0xd0:
            info_string = 'noinline,default,nofree,EUI'
        else:
            info_string = (
                f'{_cfstring_allocator_properties[(info >> 5) & 0x3]},'
                f'{"U" if info & 16 else ""}'
                f'{"N" if info & 8 else ""}'
                f'{"L" if info & 4 else ""}'
                f'{"I" if info & 1 else ""}'
            )

        string = view.get_ascii_string_at(buffer, 1)

        if string is None:
            log_debug('string returned None; how did we even get here?')
            return [DisassemblyTextLine(prefix, addr)]

        string = string.value

        if symbol is None:
            name = f'data_{addr:x}'
        else:
            name = symbol.short_name

        prefix = [
            InstructionTextToken(
                InstructionTextTokenType.TypeNameToken,
                'CFString'
            ),
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                ' '
            ),
            InstructionTextToken(
                InstructionTextTokenType.AnnotationToken,
                f'{{{info_string}}}'
            ),
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                ' '
            ),
            InstructionTextToken(
                InstructionTextTokenType.DataSymbolToken,
                name,
                addr
            ),
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                ' = '
            ),
            InstructionTextToken(
                InstructionTextTokenType.StringToken,
                f'"{string}"',
                buffer
            ),
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                ' '
            )
        ]
        return [DisassemblyTextLine(prefix, addr)]

    def __del__(self):
        pass


CFStringDataRenderer().register_type_specific()
