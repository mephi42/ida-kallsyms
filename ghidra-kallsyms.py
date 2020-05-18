# Add or rename symbols based on kallsyms
import jarray

from ghidra.program.model.symbol import SourceType

from find_kallsyms import find_kallsyms_in_rodata

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
