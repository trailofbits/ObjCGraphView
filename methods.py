import re

from binaryninja import (BackgroundTaskThread, BinaryView, Endianness,
                         MediumLevelILOperation, RegisterValueType, Structure,
                         Symbol, SymbolType, Type, TypeClass, log_debug)

from .types import basic_types, parse_function_type
from .bnilvisitor import BNILVisitor


def define_methods(view):
    log_debug('define_methods')
    view.update_analysis_and_wait()

    objc_getClass = view.symbols.get('_objc_getClass')
    class_addMethod = view.symbols.get('_class_addMethod')
    class_replaceMethod = view.symbols.get('_class_replaceMethod')

    if isinstance(objc_getClass, list):
        objc_getClass = next(
            (
                s
                for s in objc_getClass
                if s.type == SymbolType.ImportedFunctionSymbol
            ),
            None
        )

    if isinstance(class_addMethod, list):
        class_addMethod = next(
            (
                s
                for s in class_addMethod
                if s.type == SymbolType.ImportedFunctionSymbol
            ),
            None
        )

    if isinstance(class_replaceMethod, list):
        class_replaceMethod = next(
            (
                s
                for s in class_replaceMethod
                if s.type == SymbolType.ImportedFunctionSymbol
            ),
            None
        )

    if objc_getClass is not None:
        parse_get_class(view, objc_getClass.address)

    view.update_analysis_and_wait()

    if class_addMethod is not None:
        parse_added_methods(view, class_addMethod.address)

    if class_replaceMethod is not None:
        parse_added_methods(view, class_replaceMethod.address)

    _propagate_types(view)


def parse_get_class(view: BinaryView, objc_getClass: int):
    log_debug(f"parse_get_class(view, {objc_getClass:x})")
    xrefs = view.get_code_refs(objc_getClass)

    for xref in xrefs:
        mlil = xref.function.mlil
        get_class_call = xref.function.get_low_level_il_at(xref.address).mlil

        if not get_class_call.params:
            continue

        class_param = get_class_call.params[0]
        log_debug(f"class_param is {class_param.operation!r}")

        if class_param.operation in (
                MediumLevelILOperation.MLIL_CONST,
                MediumLevelILOperation.MLIL_CONST_PTR):
            class_name_ptr = view.get_ascii_string_at(class_param.constant, 1)
            if class_name_ptr is None:
                continue

            class_name = class_name_ptr.value

            cls_ = Type.named_type_from_type(
                class_name,
                view.types.get(class_name)
            )

            if cls_ is None:
                continue

            cls_ptr = Type.pointer(view.arch, cls_)

            output = get_class_call.output[0] if get_class_call.output else None

            if output is None:
                continue

            log_debug(f"Updating {output!r} to {cls_ptr}")
            xref.function.create_user_var(output, cls_ptr, output.name)
            log_debug(f"Now {output!r}")

            # Update any variable that is directly set to this variable (but not if
            # the variable just happened to be used in the expression)
            for use in mlil.get_ssa_var_uses(get_class_call.ssa_form.output.dest[0]):
                log_debug(f"Checking {use!r}")
                if use.operation != MediumLevelILOperation.MLIL_SET_VAR:
                    continue

                if use.src.operation != MediumLevelILOperation.MLIL_VAR:
                    continue

                log_debug(f"Updating {use.dest!r} to {cls_ptr}")
                xref.function.create_user_var(use.dest, cls_ptr, use.dest.name)
                log_debug(f"Now {use.dest!r}")


def parse_added_methods(view: BinaryView, class_addMethod: int):
    log_debug(f"parse_added_methods(view, {class_addMethod:x})")
    xrefs = view.get_code_refs(class_addMethod)

    for xref in xrefs:
        mlil = xref.function.mlil
        log_debug(f"{xref.address:x} Getting add_method_call")
        add_method_call = xref.function.get_low_level_il_at(xref.address).mlil

        log_debug(f"{xref.address:x} {add_method_call.operation!r}")
        if add_method_call.operation not in (
                MediumLevelILOperation.MLIL_CALL,
                MediumLevelILOperation.MLIL_CALL_UNTYPED):
            continue

        class_param = add_method_call.params[0]
        if class_param.operation != MediumLevelILOperation.MLIL_VAR:
            log_debug(f"class_param is {class_param.operation!r}")
            continue

        cls_ = class_param.src.type

        log_debug(f"Checking {cls_!r}")
        if cls_.target is not None and cls_.target.named_type_reference is not None:
            class_name = cls_.target.named_type_reference.name
        else:
            log_debug(f"cls_ is {cls_}->{cls_.target}")
            continue

        log_debug("Getting selector_param")
        selector_param = add_method_call.params[1]
        if selector_param.operation == MediumLevelILOperation.MLIL_CONST:
            selector_ptr = selector_param
        elif selector_param.operation != MediumLevelILOperation.MLIL_VAR:
            log_debug(f"selector_param {selector_param.operation!r}")
            continue
        else:
            selector_ptr = None

            log_debug("Getting get_method_call")
            get_method_call = mlil.get_ssa_var_definition(
                selector_param.ssa_form.src)

            while get_method_call.operation != MediumLevelILOperation.MLIL_CALL:
                if get_method_call.operation != MediumLevelILOperation.MLIL_SET_VAR:
                    log_debug(f"get_method_call {get_method_call.operation!r}")
                    break

                if get_method_call.src.operation != MediumLevelILOperation.MLIL_VAR:
                    log_debug(f"get_method_call.src {get_method_call.src!r}")
                    break

                get_method_call = mlil.get_ssa_var_definition(
                    get_method_call.ssa_form.src.src
                )
                log_debug(f"{get_method_call!r}")
            else:
                log_debug(f"Found {get_method_call!r}")
                selector_ptr = get_method_call.params[1]

        if selector_ptr is None:
            log_debug("selector_ptr is None")
            continue

        if selector_ptr.operation not in (
                MediumLevelILOperation.MLIL_CONST,
                MediumLevelILOperation.MLIL_CONST_PTR):
            log_debug(f"selector_ptr {selector_ptr.operation!r}")
            continue

        selector_str = view.get_ascii_string_at(selector_ptr.constant, 1)

        if selector_str is None:
            log_debug("selector_str is None")
            continue

        selector = selector_str.value

        method_string = f"-[{class_name} {selector}]"

        log_debug(f"method_string is {method_string}")

        method_ptr = add_method_call.params[2]

        if method_ptr.operation not in (
                MediumLevelILOperation.MLIL_CONST,
                MediumLevelILOperation.MLIL_CONST_PTR):
            log_debug(f"method_ptr.operation {method_ptr.operation!r}")
            continue

        log_debug("Defining {method_string} @ {method_ptr.constant}")
        view.define_user_symbol(
            Symbol(
                SymbolType.FunctionSymbol,
                method_ptr.constant,
                method_string
            )
        )

class TypePropagationVisitor(BNILVisitor):
    def visit_MLIL_SET_VAR(self, expr):
        return self.visit(expr.src)

    def visit_MLIL_CALL(self, expr):
        return expr.output[0].type

    def visit_MLIL_LOAD(self, expr):
        return self.visit(expr.src)

    def visit_MLIL_VAR(self, expr):
        return self.visit(
            expr.function.get_ssa_var_definition(expr.ssa_form.src)
        )

    def visit_MLIL_CONST(self, expr):
        view = expr.function.source_function.view
        class_symbol = view.get_symbol_at(expr.constant)

        if class_symbol is None:
            return

        log_debug(class_symbol.name)

        class_match = re.match(
            r'_OBJC_(META)?CLASS_\$_(?P<classname>[_A-Za-z0-9=/]+)(@GOT)?',
            class_symbol.name
        )

        class_name = class_match.group('classname')

        class_type = view.types.get(class_name)

        if class_type is None:
            view.define_user_type(class_name, Type.structure_type(Structure()))
            class_type = view.types.get(class_name)

        return Type.pointer(
            view.arch,
            Type.named_type_from_type(class_name, class_type)
        )

    visit_MLIL_IMPORT = visit_MLIL_CONST
    visit_MLIL_CONST_PTR = visit_MLIL_CONST

def _propagate_types(view):
    log_debug('_propagate_types')
    objc_msgSend = view.symbols.get('_objc_msgSend@PLT')

    for xref in view.get_code_refs(objc_msgSend.address):
        xref_mlil = xref.function.get_low_level_il_at(xref.address).mlil

        if xref_mlil is None:
            continue

        if xref_mlil.operation != MediumLevelILOperation.MLIL_CALL:
            continue

        selector_ptr = xref_mlil.params[1]

        if not selector_ptr.value.is_constant or selector_ptr.value.value == 0:
            continue

        selector = view.get_ascii_string_at(selector_ptr.value.value, 1)

        if selector is None:
            selector_ptr = int.from_bytes(
                view.read(selector_ptr.value.value, view.address_size),
                "little" if view.endianness is Endianness.LittleEndian else "big"
            )
            log_debug(f'{selector_ptr:x}')
            selector = view.get_ascii_string_at(selector_ptr)

        if selector is None or selector.value not in ("alloc", "init"):
            continue

        self_ = xref_mlil.params[0]
        if self_.operation != MediumLevelILOperation.MLIL_VAR:
            continue

        self_var = self_.src

        self_type = self_.src.type

        if self_type.type_class != TypeClass.PointerTypeClass:
            continue

        self_struct = self_type.target

        if self_struct.type_class != TypeClass.NamedTypeReferenceClass:
            continue

        log_debug(f'{xref.address:x} -> {selector.value}')

        class_type = TypePropagationVisitor().visit(self_)

        log_debug(f'{class_type!r}')

        if class_type is None:
            return

        return_var = xref_mlil.output[0]

        xref.function.create_user_var(
            return_var,
            class_type,
            return_var.name
        )

        view.update_analysis_and_wait()
