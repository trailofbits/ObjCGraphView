from functools import partial
from itertools import takewhile

from binaryninja import (BackgroundTaskThread, BinaryView, Endianness,
                         FunctionParameter, MediumLevelILOperation, Structure,
                         Type, TypeClass, log_debug)

_objc_types = '''
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

def _parse_structure(type_string: str, view: BinaryView) -> Type:
    type_name = ''.join(
        takewhile(lambda i: i != '=', type_string)
    )

    type_string = type_string[len(type_name)+1:]

    fields = []
    while type_string:
        if type_string[0] == '{':
            field_type, type_string = _parse_structure(type_string[1:], view)
            fields.append(field_type)

        elif type_string[0] == '}':
            type_string = type_string[1:]
            break

        elif type_string[0] == '[':
            array_size = ''.join(takewhile(str.isdigit, type_string[1:]))
            array_type = ''.join(
                takewhile(lambda i: i != ']', type_string[1:])
            )
            type_string = type_string[len(array_size)+len(array_type)+2:]

            fields.append(
                Type.array(_lookup_type(array_type, view), int(array_size))
            )

        elif type_string[0] == ']':
            type_string = type_string[1:]
            continue

        elif _lookup_type(type_string[0], view):
            fields.append(_lookup_type(type_string[0], view))
            type_string = type_string[1:]

        else:
            log_debug(f"Not sure what is going on with this type: {type_string!r}")
            raise NotImplementedError(f"{type_string!r}")

    parsed_struct = Structure()

    for field in fields:
        parsed_struct.append(field)

    log_debug(f"Created {type_name}={parsed_struct}")
        
    view.define_user_type(type_name, Type.structure_type(parsed_struct))

    return (
        Type.named_type_from_type(
            type_name,
            view.types.get(type_name)
        ),
        type_string
    )

def _parse_function_type(type_string: str, self_name: str, view: BinaryView, is_class=False) -> Type:
    log_debug(f'_parse_function_type {type_string}')
    ret_type_str = type_string[0]

    # Handle structures defined in the function types
    if ret_type_str == '{':
        ret_type, type_string = _parse_structure(type_string[1:], view)
    else:
        ret_type = _lookup_type(ret_type_str, view)
        type_string = type_string[1:]

    stack_size = ''.join(takewhile(str.isdigit, type_string))
    type_string = type_string[len(stack_size):]
    stack_size = int(stack_size) if stack_size else None

    args = []
    while type_string:
        if type_string[0] == '{':
            arg_type, type_string = _parse_structure(type_string[1:], view)
            args.append(Type.pointer(view.arch, arg_type))
        else:
            arg_type = ''.join(
                takewhile(lambda i: not str.isdigit(i), type_string))
            type_string = type_string[len(arg_type):]
            args.append(_lookup_type(arg_type, view))

        arg_stack_offset = ''.join(takewhile(str.isdigit, type_string))
        type_string = type_string[len(arg_stack_offset):]

    # we know that the first parameter is the 'self' parameter if it's not
    # an objc_msgSend_stret or objc_msgSendSuper_stret. Otherwise it's the
    # second one.
    if ret_type.type_class == TypeClass.NamedTypeReferenceClass:
        log_debug(f'return value is {ret_type}')
        ret_type = Type.pointer(view.arch, ret_type)
        args.insert(
            0, 
            FunctionParameter(
                ret_type,
                'ret_value'
            )
        )

        if len(args) < 2:
            args.append(None)

        args[1] = FunctionParameter(
            Type.pointer(
                view.arch,
                (
                    Type.named_type_from_type(
                        self_name, view.types[self_name]
                    )
                    if not is_class
                    else Type.named_type_from_type(
                        'class_t', view.types['class_t']
                    )
                )

            ),
            'self'
        )
    else:
        args[0] = FunctionParameter(
            Type.pointer(
                view.arch,
                (
                    Type.named_type_from_type(
                        self_name, view.types[self_name]
                    )
                    if not is_class
                    else Type.named_type_from_type(
                        'class_t', view.types['class_t']
                    )
                )
            ),
            'self'
        )

    function_type = Type.function(ret_type, args)

    return function_type
