from binaryninja import FlowGraph, FlowGraphNode, DisassemblyTextRenderer, Function, InstructionTextToken, InstructionTextTokenType, MediumLevelILOperation, TypeClass, Variable
from binaryninjaui import FlowGraphWidget, ViewType
from .class_t import Class
import re

class ObjcFlowgraph(FlowGraph):
    def __init__(self, function):
        super().__init__()
        self.function = function
        self.view = function.view
        self.mlil = function.mlil
        self._objc_msgSend = function.view.symbols.get('_objc_msgSend@PLT')

        self.uses_block_highlights = True
        self.uses_instruction_highlights = True
        self.includes_user_comments = True
        self.shows_secondary_reg_highlighting = True

    def populate_nodes(self):
        func = self.function
        mlil = self.mlil

        method_t = self.view.types['method_t']
        
        renderer = DisassemblyTextRenderer(mlil)

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
                nodes[block.start].add_outgoing_edge(edge.type, nodes[edge.target.start])

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
                    if i.dest.constant == self._objc_msgSend.address:
                        call_line = next(
                            line for line in il_lines
                            if any('objc_msgSend' in t.text for t in line.tokens)
                        )

                        type_ = i.params[0].src.type if i.params[0].operation == MediumLevelILOperation.MLIL_VAR else None
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

                        class_ = Class.classes.get(class_name)
                        if class_:
                            print(f"{class_.vtable.baseMethods:x}")

                        if i.params[1].operation in (MediumLevelILOperation.MLIL_CONST, MediumLevelILOperation.MLIL_CONST_PTR):
                            selector = i.params[1].constant
                            selector_value = self.view.get_ascii_string_at(selector, 2).value
                        elif i.params[1].operation == MediumLevelILOperation.MLIL_VAR:
                            selector_value = i.params[1].src

                        id_ = i.params[0].src
                        if class_ and selector in class_.methods:
                            method_string = selector_value
                            method_ptr = class_.methods[selector]
                        else:
                            id_ = i.params[0].src
                            method_string = selector_value if isinstance(selector_value, str) else ''
                            method_ptr = 0
                            if class_name == 'class_t':
                                class_def = self.mlil.get_ssa_var_definition(i.ssa_form.params[0].src)
                                src = self.mlil[class_def].src
                                if src.operation in (MediumLevelILOperation.MLIL_CONST, MediumLevelILOperation.MLIL_CONST_PTR, MediumLevelILOperation.MLIL_IMPORT):
                                    class_symbol = self.view.get_symbol_at(src.constant)
                                    if class_symbol is not None:                                        
                                        class_match = re.match(r'_OBJC_(META)?CLASS_\$_(?P<classname>[_A-Za-z0-9=/]+)(@GOT)?', class_symbol.name)
                                        if class_match:
                                            id_ = class_match.group('classname')

                        if ':' in method_string:
                            params = i.params[2:]
                            method_params = [x for x in method_string.split(':') if x]

                            if len(params) > len(method_params):
                                # some parameters are on the stack instead of registers
                                pass

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
                                    method_params[p] = (
                                        method_params[p],
                                        InstructionTextToken(
                                            InstructionTextTokenType.PossibleAddressToken,
                                            hex(params[p].constant),
                                            params[p].constant
                                        )
                                    )
                                
                            if len(params) < len(method_params):
                                # the calling convention didn't pick up one or more parameters
                                if len(method_params) <= len(self.mlil.source_function.parameter_vars):
                                    print(f"method_params: {method_params} params: {params}")
                                    for p in range(len(params), len(method_params)):
                                        if p+2 >= len(self.mlil.source_function.parameter_vars):
                                            param_token = InstructionTextToken(
                                                InstructionTextTokenType.TextToken,
                                                '<Unknown Parameter>'
                                            )
                                        else:
                                            param_token = InstructionTextToken(
                                                InstructionTextTokenType.LocalVariableToken,
                                                str(self.mlil.source_function.parameter_vars[p+2]),
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
                            
                        call_line.tokens = []

                        if i.operation in (MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_CALL_UNTYPED):
                            if i.output:
                                for v in i.output:
                                    call_line.tokens += [
                                        InstructionTextToken(
                                            InstructionTextTokenType.LocalVariableToken,
                                            v.name,
                                            v.identifier
                                        ),
                                        InstructionTextToken(
                                            InstructionTextTokenType.TextToken,
                                            ", "
                                        ) if v != i.output[-1] else
                                        InstructionTextToken(
                                            InstructionTextTokenType.TextToken,
                                            " = "
                                        )
                                    ]
                        else:
                            call_line.tokens.append(
                                InstructionTextToken(
                                    InstructionTextTokenType.TextToken,
                                    'return '
                                )
                            )

                        call_line.tokens.append(
                            InstructionTextToken(
                                InstructionTextTokenType.CodeSymbolToken if method_ptr else InstructionTextTokenType.ImportToken,
                                '+[' if isinstance(id_, str) else '-[',
                                method_ptr.start if method_ptr else 0
                            )
                        )

                        call_line.tokens.append(
                            InstructionTextToken(
                                InstructionTextTokenType.LocalVariableToken if isinstance(id_, Variable) else InstructionTextTokenType.ImportToken,
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
                                        InstructionTextTokenType.CodeSymbolToken if method_ptr else InstructionTextTokenType.ImportToken,
                                        selector_value,
                                        method_ptr.start if method_ptr else 0
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
                            for p,v in method_params:
                                call_line.tokens.append(
                                    InstructionTextToken(
                                        InstructionTextTokenType.CodeSymbolToken if method_ptr else InstructionTextTokenType.ImportToken,
                                        f"{p}:"
                                    )
                                )
                                call_line.tokens.append(v)
                                if (p,v) != method_params[-1]:
                                    call_line.tokens.append(
                                        InstructionTextToken(
                                            InstructionTextTokenType.TextToken,
                                            ' '
                                        )
                                    )

                        call_line.tokens.append(
                            InstructionTextToken(
                                InstructionTextTokenType.CodeSymbolToken if method_ptr else InstructionTextTokenType.ImportToken,
                                ']',
                                method_ptr.start if method_ptr else 0
                            )
                        )

                lines += il_lines

            nodes[block.start].lines = lines

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