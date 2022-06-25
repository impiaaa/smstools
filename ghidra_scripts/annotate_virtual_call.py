#
#@keybinding
#@menupath Tools.annotate_virtual_call
#@toolbar

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import ClangOpToken
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.program.model.pcode import HighFunctionDBUtil

options = DecompileOptions()
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(currentProgram)

startingFunc = getFunctionContaining(currentAddress)
res = ifc.decompileFunction(startingFunc, 60, monitor)

inst = getInstructionAt(currentAddress)
while not any([pcode.opcode == pcode.CALLIND for pcode in inst.pcode]): inst = inst.getNext()
callAddr = inst.address

#callOp = [pcode for pcode in inst.pcode if pcode.opcode == pcode.CALLIND][0]
callOp = [pcode for pcode in res.highFunction.getPcodeOps(callAddr) if pcode.opcode == pcode.CALLIND][0]
castToCode = callOp.getInput(0).getDef()
if castToCode.opcode == castToCode.CAST:
    loadFnPtr = castToCode.getInput(0).getDef()
else:
    loadFnPtr = castToCode
assert loadFnPtr.opcode == loadFnPtr.LOAD, "expected input 0 to cast to be load, not %s"%loadFnPtr.opcode
indexVt = loadFnPtr.getInput(1).getDef()
assert indexVt.opcode == indexVt.PTRADD, "expected input 1 to load to be ptradd, not %s"%indexVt.opcode
vtableIndex = indexVt.getInput(1).getAddress().offset
pointerSize = indexVt.getInput(1).size
loadVt = indexVt.getInput(0).getDef()
assert loadVt.opcode == loadVt.LOAD, "expected input 0 to ptradd to be load, not %s"%loadVt.opcode
getVt = loadVt.getInput(1).getDef()
assert getVt.opcode == getVt.PTRSUB, "expected input 1 to load to be ptrsub, not %s"%getVt.opcode
assert getVt.getInput(1).isConstant()
assert getVt.getInput(1).getAddress().offset == 0, "expected vtable to be at offset 0, not %s"%(getVt.getInput(1).getAddress().offset)
theVariable = getVt.getInput(0)
classNames = [theVariable.high.dataType.dataType.name]
defTheVariable = theVariable.getDef()
while defTheVariable is not None and defTheVariable.opcode == defTheVariable.PTRSUB:
    if defTheVariable.getInput(1).getAddress().offset != 0: raise ValueError("multiple inheritance not currently supported")
    theVariable = defTheVariable.getInput(0)
    classNames.insert(0, theVariable.high.dataType.dataType.name)
    defTheVariable = theVariable.getDef()

symdb = currentProgram.symbolTable
vtableSymbols = []
for className in classNames:
    for sym in symdb.getSymbols(className):
        if sym.symbolType == SymbolType.NAMESPACE:
            vtableSymbols.extend(symdb.getSymbols("__vt", sym.getObject()))

listing = currentProgram.listing
for vtableSymbol in vtableSymbols:
    vtableAddr = vtableSymbol.address
    funcPointer = listing.getDataAt(vtableAddr.add(vtableIndex*pointerSize))
    if funcPointer is not None:
        funcAddr = funcPointer.value
        if funcAddr.offset != 0:
            calledFunc = getFunctionAt(funcAddr)
            if calledFunc is not None and vtableSymbol.parentNamespace.name == calledFunc.parentNamespace.name:
                print calledFunc
                funcDef = FunctionDefinitionDataType(calledFunc.signature)
                HighFunctionDBUtil.writeOverride(startingFunc, callAddr, funcDef)
                listing.setComment(callAddr, funcPointer.PRE_COMMENT, "{@symbol %s}"%calledFunc.symbol.getName(True))
                break

