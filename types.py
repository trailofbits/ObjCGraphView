from binaryninja import Type

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
    uint64_t* offset;
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
    objc_types = view.platform.parse_types_from_source(_objc_types)

    for objc_type in objc_types.types.items():
        view.define_user_type(*objc_type)