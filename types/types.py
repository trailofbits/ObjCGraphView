from functools import partial
from itertools import takewhile

from binaryninja import (BinaryView, Endianness, FunctionParameter, Structure,
                         Type, log_debug)

_objc_types = '''
struct CFString
{
    void* isa;
    int32_t info;
    void* buffer;
    int64_t length;
};

struct NSNumber
{
    void* isa;
};

typedef char* SEL;

struct ivar_list_t
{
    uint32_t entsize;
    uint32_t count;
};

struct ivar_t
{
    uint32_t* offset;
    char const* name;
    char const* type;
    uint32_t alignment;
    uint32_t size;
};

struct method_t
{
    SEL name;
    char const* types;
    void* imp;
};

struct method_list_t
{
    uint32_t entsize;
    uint32_t count;
    struct method_t first[0];
};

struct property_list_t
{
    uint32_t entsize;
    uint32_t count;
};

struct property_t
{
    char const* name;
    char const* attributes;
};

struct protocol_list_t
{
    uint64_t count;
};

typedef uint64_t protocol_ref_t;

struct protocol_t
{
    void* isa;
    char const* name;
    struct protocol_list_t* protocols;
    struct method_list_t* instanceMethods;
    struct method_list_t* classMethods;
    struct method_list_t* optionalInstanceMethods;
    struct method_list_t* optionalClassMethods;
    struct property_list_t* instanceProperties;
    uint32_t size;
    uint32_t flags;
    char const** extendedMethodTypes;
};

struct class_ro_t
{
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
    uint32_t reserved;
    uint8_t const* ivarLayout;
    char const* name;
    struct method_list_t const* baseMethods;
    struct protocol_list_t* baseProtocols;
    struct ivar_list_t* ivars;
    uint8_t const* weakIvarLayout;
    struct property_list_t* baseProperties;
};

struct class_t
{
    struct class_t* isa;
    struct class_t* superclass;
    struct 
    {
        void* field0;
        void* field8;
    } cache;
    struct class_ro_t* vtable;
};

struct category_t {
    const char *name;
    class_t *cls;
    struct method_list_t *instanceMethods;
    struct method_list_t *classMethods;
    struct protocol_list_t *protocols;
    struct property_list_t *instanceProperties;
};
'''

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
    'Q': Type.int(8, False),
    'f': Type.float(4),
    'd': Type.float(8),
    'B': Type.bool(),
    'v': Type.void()
}


def define_types_plugin(view):
    log_debug("define_types_plugin")
    objc_types = view.platform.parse_types_from_source(_objc_types)

    for objc_type in objc_types.types.items():
        view.define_user_type(*objc_type)


def _get_from_bytes(view: BinaryView):
    return partial(
        int.from_bytes,
        byteorder=(
            "little" if view.endianness == Endianness.LittleEndian
            else "big"
        )
    )


def _lookup_type(type_string: str, view: BinaryView):
    if type_string in basic_types:
        return basic_types[type_string]
    elif type_string == '*':
        return Type.pointer(view.arch, Type.char())
    elif type_string.startswith('@'):
        if type_string[2:-1] in view.types:
            return Type.pointer(
                view.arch,
                Type.named_type_from_type(
                    type_string[2:-1],
                    view.types[type_string[2:-1]]
                )
            )
        elif type_string != '@?' and type_string != '@':
            if type_string[2:-1]:
                new_type = Type.named_type_from_type(
                    type_string[2:-1], Type.structure_type(Structure()))
                view.define_user_type(type_string[2:-1], new_type)
            else:
                new_type = Type.void()
            return Type.pointer(view.arch, new_type)
        else:
            return Type.pointer(view.arch, Type.void())
    elif type_string.startswith('#'):
        return Type.pointer(view.arch, Type.void())
    elif type_string == ':':
        return view.types['SEL']
    else:
        return Type.pointer(view.arch, Type.void())


def _get_structure_members(address: int, t: Type, view: BinaryView) -> dict:
    from_bytes = _get_from_bytes(view)

    return {
        m.name: from_bytes(view.read(address + m.offset, m.type.width))
        for m in t.structure.members
    }


def _parse_function_type(type_string: str, self_name: str, view: BinaryView) -> Type:
    ret_type_str = type_string[0]

    # TODO: this clearly won't work. Need to do much better parsing of
    # complex types.
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
        # TODO: does not handle structures passed by value on stack
        arg_type = ''.join(
            takewhile(lambda i: not str.isdigit(i), type_string))
        type_string = type_string[len(arg_type):]

        arg_stack_offset = ''.join(takewhile(str.isdigit, type_string))
        type_string = type_string[len(arg_stack_offset):]

        args.append(_lookup_type(arg_type, view))

    # we know that the first parameter is the 'self' parameter
    args[0] = FunctionParameter(
        Type.pointer(
            view.arch,
            Type.named_type_from_type(
                self_name, view.types[self_name]
            )
        ),
        'self'
    )

    function_type = Type.function(_lookup_type(ret_type_str, view), args)

    return function_type
