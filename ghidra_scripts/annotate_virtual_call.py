#Deduce the virtual function being called at the current selected location
#@keybinding
#@menupath Tools.annotate_virtual_call
#@toolbar

from ghidra.app.decompiler import ClangOpToken, DecompileOptions, DecompInterface
from ghidra.program.model.address import Address
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.util.exception import CancelledException
from ghidra.util.task import ConsoleTaskMonitor

VTABLE_LABEL = "__vt"

options = DecompileOptions()
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(currentProgram)

startingFunc = getFunctionContaining(currentAddress)
res = ifc.decompileFunction(startingFunc, 60, monitor)

# Get the indirect-call instruction nearest to the user's selection
inst = getInstructionAt(currentAddress)
while not any([pcode.opcode == pcode.CALLIND for pcode in inst.pcode]): inst = inst.getNext()
callAddr = inst.address

# Need to use decompiled Pcode to get AST access
callOp = [pcode for pcode in res.highFunction.getPcodeOps(callAddr) if pcode.opcode == pcode.CALLIND][0]

# Travel AST to get the object that's being called
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

# Follow parent-class reference chains and memorize the ancestry
superClassNames = [theVariable.high.dataType.dataType.name]
overrideClass = theVariable.high.dataType
defTheVariable = theVariable.getDef()
while defTheVariable is not None and defTheVariable.opcode == defTheVariable.PTRSUB:
    if defTheVariable.getInput(1).getAddress().offset != 0: raise ValueError("multiple inheritance not currently supported")
    theVariable = defTheVariable.getInput(0)
    superClassNames.insert(0, theVariable.high.dataType.dataType.name)
    defTheVariable = theVariable.getDef()


def getVtableSymbolsForClassName(className):
    symdb = currentProgram.symbolTable
    vtableSymbols = []
    for sym in symdb.getSymbols(className):
        if sym.symbolType == SymbolType.NAMESPACE:
            vtableSymbols.extend(symdb.getSymbols(VTABLE_LABEL, sym.getObject()))
    return vtableSymbols

def getVFunc(vtableSymbols, vtableIndex, pointerSize):
    listing = currentProgram.listing
    for vtableSymbol in vtableSymbols:
        vtableAddr = vtableSymbol.address
        vtableData = listing.getDataAt(vtableAddr)
        if vtableData is None:
            print vtableSymbol.getName(True), "has no data defined"
            continue
        funcPointer = vtableData.getComponent(vtableIndex)
        if funcPointer is None:
            funcPointer = listing.getDataAt(vtableAddr.add(vtableIndex*pointerSize))
        if funcPointer is None:
            print vtableSymbol.getName(True), "has no data defined at index", vtableIndex
            continue
        funcAddr = funcPointer.value
        if not isinstance(funcAddr, Address):
            print "The function pointer at", vtableIndex, "in", vtableSymbol.getName(True), "is not an address"
            continue
        if funcAddr.offset == 0:
            print "The function pointer at", vtableIndex, "in", vtableSymbol.getName(True), "is NULL"
            continue
        calledFunc = getFunctionAt(funcAddr)
        if calledFunc is None:
            print "No function defined at", funcAddr
            continue
        if vtableSymbol.parentNamespace.name == calledFunc.parentNamespace.name:
            return calledFunc

def annotateVirtualCall(calledFunc, startingFunc, callAddr, thisOverride=None):
    print calledFunc
    funcDef = FunctionDefinitionDataType(calledFunc.signature)
    if thisOverride is not None:
        originalThis = funcDef.arguments[0]
        funcDef.replaceArgument(0, originalThis.name, thisOverride, originalThis.comment, SourceType.DEFAULT)
    try: HighFunctionDBUtil.writeOverride(startingFunc, callAddr, funcDef)
    except: print startingFunc, callAddr, funcDef
    currentProgram.listing.setComment(callAddr, CodeUnit.PRE_COMMENT, "{@symbol %s}"%calledFunc.symbol.getName(True))

# Look through the vtables of the primary class and any superclasses for a function pointer at the called index
calledFunc = None
for className in superClassNames:
    calledFunc = getVFunc(getVtableSymbolsForClassName(className), vtableIndex, pointerSize)
    if calledFunc is not None:
        annotateVirtualCall(calledFunc, startingFunc, callAddr)
        break

# If we didn't find any, offer to the user a subclass implementation instead
if calledFunc is None:
    dataDb = currentProgram.getDataTypeManager()
    calledFuncs = []
    subClassNames = []
    while len(calledFuncs) == 0 and len(superClassNames) > 0:
        superClass = superClassNames.pop(0)
        for struct in dataDb.getAllStructures():
            if struct.numComponents > 0 and struct.getComponent(0).dataType.name == superClass:
                subClassNames.append(struct.name)
                calledFunc = getVFunc(getVtableSymbolsForClassName(struct.name), vtableIndex, pointerSize)
                if calledFunc is not None:
                    calledFuncs.append(calledFunc)
        if len(superClassNames) == 0:
            superClassNames = subClassNames
            subClassNames = []

    if len(calledFuncs) > 0:
        try:
            choice = askChoice("Pure-virtual call", # title
                               "I can't find an implementation for this fuction table for this type. Should I use one from a concrete subclass?", # message
                               calledFuncs, # choices
                               None) # defaultValue
        except CancelledException:
            choice = None
        
        if choice is not None:
            annotateVirtualCall(choice, startingFunc, callAddr, overrideClass)

