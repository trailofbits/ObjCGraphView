import re
from itertools import takewhile

from binaryninja import (DisassemblySettings, DisassemblyTextRenderer,
                         FlowGraph, FlowGraphNode, Function,
                         InstructionTextToken, InstructionTextTokenType,
                         MediumLevelILInstruction, MediumLevelILOperation,
                         TypeClass, Variable, log_debug, Endianness, RegisterValueType)
from binaryninjaui import FlowGraphWidget, ViewType

from .types import Class


def lookup_selector(i: MediumLevelILInstruction, id_, class_name: str, class_: Class, selector: str):
    mlil = i.function
    view = mlil.source_function.view

    if class_ is not None and selector in class_.methods:
            return id_, selector, class_.methods[selector]
    elif class_ is not None:
        log_debug(f"Didn't find {selector} in {class_name}")
        superclass = class_.superclass
        while superclass is not None:
            log_debug(f"Checking for {selector} in {superclass.vtable.name}")
            if selector in superclass.methods:
                return id_, selector, superclass.methods[selector]
            else:
                superclass = superclass.superclass
        else:
            log_debug(f"Checking for {selector} in NSObject")
            NSObject = view.session_data['ClassNames'].get('NSObject')
            if NSObject and selector in NSObject.methods:
                return id_, selector, NSObject.methods[selector]

    method_string = selector if isinstance(
        selector, str) else ''
    method_ptr = None
    if class_name == 'class_t':
        class_def = mlil.get_ssa_var_definition(
            i.ssa_form.params[0].src)
        src = mlil[class_def].src

        if src.operation in (
            MediumLevelILOperation.MLIL_CONST,
            MediumLevelILOperation.MLIL_CONST_PTR,
            MediumLevelILOperation.MLIL_IMPORT
        ):
            class_symbol = mlil.source_function.view.get_symbol_at(src.constant)
        elif (src.operation == MediumLevelILOperation.MLIL_LOAD and
                src.src.value.type == RegisterValueType.ConstantPointerValue):
            class_symbol = mlil.source_function.view.get_symbol_at(src.src.value.value)
        else:
            class_symbol = None

        if class_symbol is not None:
            class_match = re.match(
                r'_OBJC_(META)?CLASS_\$_(?P<classname>[_A-Za-z0-9=/]+)(@GOT)?',
                class_symbol.name
            )
            if class_match:
                id_ = class_match.group('classname')

    return id_, method_string, method_ptr


class ObjcFlowgraph(FlowGraph):
    def __init__(self, function):
        super().__init__()
        self.function = function
        self.view = function.view
        self.mlil = function.mlil
        self._objc_msgSend = function.view.symbols.get('_objc_msgSend@PLT')
        self._objc_retain = function.view.symbols.get('_objc_retain@PLT')
        self._objc_release = function.view.symbols.get('_objc_release@PLT')

        self.uses_block_highlights = True
        self.uses_instruction_highlights = True
        self.includes_user_comments = True
        self.shows_secondary_reg_highlighting = True

    def populate_nodes(self):
        func = self.function
        mlil = self.mlil

        method_t = self.view.types['method_t']

        settings = DisassemblySettings()
        settings.set_option('ShowVariableTypesWhenAssigned')
        renderer = DisassemblyTextRenderer(mlil, settings)

        nodes = {}
        for block in mlil:
            node = FlowGraphNode(self)
            node.basic_block = block
            nodes[block.start] = node
            self.append(node)

        # Construct graph
        for block in mlil:
            renderer.basic_block = block

            # Add outgoing edges for the node
            for edge in block.outgoing_edges:
                nodes[block.start].add_outgoing_edge(
                    edge.type, nodes[edge.target.start])

            # Get instruction starts for assembly instructions in the block
            start_addr = mlil[block.start].address

            # Iterate through instructions in this block and add disassembly lines
            lines = []
            for i in block:
                # Display IL instruction
                il_lines, length = renderer.get_disassembly_text(i.instr_index)
                if (
                    i.operation in (
                        MediumLevelILOperation.MLIL_CALL,
                        MediumLevelILOperation.MLIL_TAILCALL,
                        MediumLevelILOperation.MLIL_TAILCALL_UNTYPED
                    ) and
                    i.dest.operation in (
                        MediumLevelILOperation.MLIL_CONST,
                        MediumLevelILOperation.MLIL_CONST_PTR,
                        MediumLevelILOperation.MLIL_IMPORT
                    )
                ):
                    if self._objc_retain and i.dest.constant == self._objc_retain.address:
                        self.render_retain(i, il_lines)

                    elif self._objc_release and i.dest.constant == self._objc_release.address:
                        self.render_release(i, il_lines)

                    elif self._objc_msgSend and i.dest.constant == self._objc_msgSend.address:
                        self.render_msgSend(i, il_lines, renderer)

                lines += il_lines

            nodes[block.start].lines = lines

    def render_msgSend(self, i, il_lines, renderer):
        call_line = next(
            line for line in il_lines
            if any('objc_msgSend' in t.text for t in line.tokens)
        )

        type_ = (
            i.params[0].src.type
            if i.params[0].operation == MediumLevelILOperation.MLIL_VAR
            else None
        )
        if type_ is None:
            raise NotImplementedError(f'i.params[0] was {i.params[0]}')
        if type_.type_class == TypeClass.NamedTypeReferenceClass:
            class_name = type_.named_type_reference.name
        elif type_.type_class == TypeClass.PointerTypeClass:
            if type_.target.type_class == TypeClass.NamedTypeReferenceClass:
                class_name = type_.target.named_type_reference.name
            else:
                class_name = None
        else:
            class_name = None

        class_ = self.view.session_data['ClassNames'].get(class_name)

        if (i.params[1].operation in
                (
                    MediumLevelILOperation.MLIL_CONST,
                    MediumLevelILOperation.MLIL_CONST_PTR
                )
        ):
            selector = i.params[1].constant
            selector_value = self.view.get_ascii_string_at(selector, 2).value
        elif i.params[1].operation == MediumLevelILOperation.MLIL_VAR:
            selector_value = i.params[1].src

        id_ = i.params[0].src

        id_, method_string, method_ptr = lookup_selector(
            i, id_, class_name, class_, selector_value
        )

        if ':' in method_string:
            params = i.params[2:]
            method_params = method_string.split(':')
            if len(method_params) > method_string.count(':'):
                method_params = method_params[:method_string.count(':')]

            if len(params) > len(method_params):
                # some parameters are on the stack instead of registers
                log_debug(
                    f"len(params) > len(method_params) for {method_ptr} at {i}")

            for p in range(min(len(params), len(method_params))):
                if params[p].operation == MediumLevelILOperation.MLIL_VAR:
                    method_params[p] = (
                        method_params[p],
                        InstructionTextToken(
                            InstructionTextTokenType.LocalVariableToken,
                            params[p].src.name,
                            params[p].src.identifier
                        )
                    )                   
                else:
                    token = None
                    data_var = self.view.get_data_var_at(params[p].constant)
                    log_debug(f"params[{p}] is {data_var}")
                    if (data_var is not None and 
                            data_var.type.named_type_reference is not None and
                            data_var.type.named_type_reference.name == 'CFString'):
                        token = self.get_cfstring_token(data_var.address)
                        log_debug(f"params[{p}] token is {token}")
                    if token is not None:
                        method_params[p] = (
                            method_params[p],
                            token
                        )
                    else:
                        tokens = []
                        renderer.add_integer_token(
                            tokens, params[p].tokens[0], i.address)
                        method_params[p] = (
                            method_params[p],
                            tokens[0]
                        )

            if len(params) < len(method_params):
                # the calling convention didn't pick up one or more parameters
                if len(method_params) <= len(self.mlil.source_function.parameter_vars):
                    log_debug(
                        f"method_params: {method_params} params: {params}")
                    for p in range(len(params), len(method_params)):
                        if p+2 >= len(self.mlil.source_function.parameter_vars):
                            param_token = InstructionTextToken(
                                InstructionTextTokenType.TextToken,
                                '<Unknown Parameter>'
                            )
                        else:
                            param_token = InstructionTextToken(
                                InstructionTextTokenType.LocalVariableToken,
                                str(
                                    self.mlil.source_function.parameter_vars[p+2]),
                                self.mlil.source_function.parameter_vars[p+2].identifier
                            )

                        method_params[p] = (
                            method_params[p],
                            param_token
                        )
                else:
                    raise NotImplementedError('too many args for now')
        else:
            method_params = []

        if i.operation in (MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_CALL_UNTYPED):
            if i.output:
                call_line.tokens = list(
                    takewhile(lambda t: '=' not in t.text, call_line.tokens))
                call_line.tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        ' = '
                    )
                )
            else:
                call_line.tokens = []
        else:
            call_line.tokens = [
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    'return '
                )
            ]

        call_line.tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.CodeSymbolToken if method_ptr is not None else InstructionTextTokenType.ImportToken,
                '+[' if isinstance(id_, str) else '[',
                method_ptr.imp.start if method_ptr is not None else 0
            )
        )

        call_line.tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.LocalVariableToken if isinstance(
                    id_, Variable) else InstructionTextTokenType.ImportToken,
                id_.name if isinstance(id_, Variable) else id_,
                id_.identifier if isinstance(id_, Variable) else 0
            )
        )

        call_line.tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                ' '
            )
        )

        if not method_params:
            if isinstance(selector_value, str):
                call_line.tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.CodeSymbolToken if method_ptr is not None else InstructionTextTokenType.ImportToken,
                        selector_value,
                        method_ptr.imp.start if method_ptr is not None else 0
                    )
                )
            else:
                call_line.tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.LocalVariableToken,
                        selector_value.name,
                        selector_value.identifier
                    )
                )
        else:
            for p, v in method_params:
                call_line.tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.CodeSymbolToken if method_ptr is not None else InstructionTextTokenType.ImportToken,
                        f"{p}:",
                        method_ptr.imp.start if method_ptr is not None else 0
                    )
                )
                call_line.tokens.append(v)
                if (p, v) != method_params[-1]:
                    call_line.tokens.append(
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken,
                            ' '
                        )
                    )

        call_line.tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.CodeSymbolToken if method_ptr is not None else InstructionTextTokenType.ImportToken,
                ']',
                method_ptr.imp.start if method_ptr is not None else 0
            )
        )

    def render_retain(self, i, il_lines):
        objc_retain = self.view.symbols['_objc_retain@PLT'].address

        call_line = next(
            line for line in il_lines
            if any('objc_retain' in t.text for t in line.tokens)
        )

        if i.operation in (MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_CALL_UNTYPED):
            if i.output:
                call_line.tokens = list(
                    takewhile(lambda t: '=' not in t.text, call_line.tokens))
                call_line.tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken,
                        ' = '
                    )
                )
            else:
                call_line.tokens = []
        else:
            call_line.tokens = [
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    'return '
                )
            ]

        call_line.tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.ImportToken,
                '[',
                objc_retain
            )
        )

        call_line.tokens += i.params[0].tokens

        call_line.tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                " "
            )
        )

        call_line.tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.ImportToken,
                'retain]',
                objc_retain
            )
        )

    def render_release(self, i, il_lines):
        call_line = next(
            line for line in il_lines
            if any('objc_release' in t.text for t in line.tokens)
        )

        call_line.tokens = []

        call_line.tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.ImportToken,
                '['
            )
        )

        call_line.tokens += i.params[0].tokens

        call_line.tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.TextToken,
                " "
            )
        )

        call_line.tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.ImportToken,
                'release]'
            )
        )

    def get_cfstring_token(self, cfstring_address):
        CFString = self.view.types['CFString']
        buffer_ptr = int.from_bytes(
            self.view.read(
                cfstring_address + CFString.structure['buffer'].offset,
                self.view.address_size
            ),
            "little" if self.view.endianness == Endianness.LittleEndian else "big"
        )

        log_debug(f"buffer_ptr is {buffer_ptr}")

        buffer = self.view.get_ascii_string_at(buffer_ptr, 0)
        log_debug(f"buffer is {buffer}")
        if buffer is not None:
            buffer = buffer.value
        else:
            return

        return InstructionTextToken(
            InstructionTextTokenType.StringToken,
            f'@"{buffer}"',
            cfstring_address
        )

    def update(self):
        return ObjcFlowgraph(self.function)


# Flow graph widget subclass that displays the graphs described above
class ObjcFlowGraphView(FlowGraphWidget):
    def __init__(self, parent, data):
        # Start view with entry function
        self.data = data
        self.function = data.entry_function
        if self.function is None:
            graph = None
        else:
            graph = ObjcFlowgraph(self.function)
        super().__init__(parent, data, graph)

    def navigate(self, addr):
        # Find correct function based on most recent use
        block = self.data.get_recent_basic_block_at(addr)
        if block is None:
            # If function isn't done analyzing yet, it may have a function start but no basic blocks
            func = self.data.get_recent_function_at(addr)
        else:
            func = block.function

        if func is None:
            # No function contains this address, fail navigation in this view
            return False

        return self.navigateToFunction(func, addr)

    def navigateToFunction(self, func, addr):
        if func == self.function:
            # Address is within current function, go directly there
            self.showAddress(addr, True)
            return True

        # Navigate to the correct function
        self.function = func
        graph = ObjcFlowgraph(func)
        self.setGraph(graph, addr)
        return True


# View type for the new view
class ObjcFlowGraphViewType(ViewType):
    def __init__(self):
        super().__init__("Objc Graph", "Objective-C Graph View")

    def getPriority(self, data, filename):
        if data.executable and 'class_t' in data.types:
                        # Use low priority so that this view is not picked by default
            return 1
        return 0

    def create(self, data, view_frame):
        return ObjcFlowGraphView(view_frame, data)
