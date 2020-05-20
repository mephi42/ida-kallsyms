# Add or rename symbols based on kallsyms
import jarray
import json

from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.program.model.data import VoidDataType, Undefined1DataType
from ghidra.program.model.listing import Function, ParameterImpl, \
    ReturnParameterImpl
from ghidra.program.model.symbol import SourceType, SymbolType

from find_kallsyms import find_kallsyms_in_rodata


def load_like_json(program, symbols, functions, types):
    like_json_path = program.getExecutablePath() + '.like.json'
    try:
        fp = open(like_json_path)
    except FileNotFoundError:
        return
    try:
        like_json = json.load(fp)
    finally:
        fp.close()
    for return_type, name, parameters, has_varargs in \
            like_json['subprograms'].values():
        wtf = False
        existing_label = None
        existing_function = None
        for existing_symbol in symbols.getGlobalSymbols(name):
            symbol_type = existing_symbol.getSymbolType()
            if symbol_type == SymbolType.LABEL:
                if existing_label is not None:
                    wtf = True
                    break
                existing_label = existing_symbol
            elif symbol_type == SymbolType.FUNCTION:
                if existing_function is not None:
                    wtf = True
                    break
                existing_function = existing_symbol
        if wtf:
            continue
        if existing_function is None:
            if existing_label is None:
                continue
            try:
                function = functions.createFunction(
                    name,
                    existing_label.getAddress(),
                    CreateFunctionCmd.getFunctionBody(
                        program, existing_label.getAddress()),
                    SourceType.ANALYSIS,
                )
            except:  # noqa: E722
                # E.g. OverlappingFunctionException.
                continue
        else:
            function = functions.getFunction(existing_function.getID())
        if return_type is None:
            return_var = ReturnParameterImpl(VoidDataType.dataType, program)
        else:
            return_var = function.getReturn()
        new_params = []
        for i, (_, param_name) in enumerate(parameters):
            param_type = Undefined1DataType.dataType
            existing_param = function.getParameter(i)
            if existing_param is not None:
                param_type = existing_param.getDataType()
            new_params.append(ParameterImpl(param_name, param_type, program))
        function.updateFunction(
            function.getCallingConventionName(),
            return_var,
            new_params,
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            True,
            SourceType.ANALYSIS,
        )
        function.setVarArgs(has_varargs)


program = currentProgram  # noqa: F821
memory = program.getMemory()
rodata_block = memory.getBlock('.rodata')
if rodata_block is None:
    rodata_block = memory.getBlock('.text')
rodata = jarray.zeros(rodata_block.getSize(), 'b')
rodata_block.getBytes(rodata_block.getStart(), rodata)
rodata = b''.join([chr(x & 0xff) for x in rodata])  # it's py2
ram = program.getAddressFactory().getDefaultAddressSpace()
symbols = program.getSymbolTable()
for address, name in find_kallsyms_in_rodata(rodata):
    if name[0] != 'A':
        address = ram.getAddress(address)
        existing = list(symbols.getSymbols(address))
        if len(existing) == 0:
            symbols.createLabel(address, name[1:], SourceType.ANALYSIS)
        elif len(existing) == 1:
            existing[0].setName(name[1:], SourceType.ANALYSIS)
        else:
            pass
load_like_json(
    program=program,
    symbols=symbols,
    functions=program.getFunctionManager(),
    types=program.getDataTypeManager(),
)
