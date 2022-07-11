#
#@keybinding
#@menupath Tools.vt
#@toolbar

from ghidra.program.model.data import *
from ghidra.program.model.address import AddressSet

symdb = currentProgram.symbolTable
listing = currentProgram.getListing()
namespaceSymbols = list(symdb.getChildren(currentProgram.getNamespaceManager().getGlobalNamespace().getSymbol()))
done = 0
while len(namespaceSymbols) > 0:
    namespaceSymbol = namespaceSymbols.pop(0)
    namespace = symdb.getNamespace(namespaceSymbol.name, namespaceSymbol.getParentNamespace())
    if namespace is None: continue
    namespaceSymbols.extend(symdb.getChildren(namespaceSymbol))
    for sym in symdb.getSymbols(namespace):
        if sym.name != u'__vt': continue
        
        addr = sym.address.next()
        if addr is None: continue
        while len(symdb.getSymbols(addr)) == 0:
            addr = addr.next()
        
        while addr.subtract(sym.address)%4 != 0:
            addr = addr.previous()
        
        length = addr.subtract(sym.address)
        startAddr = sym.address
        endAddr = addr.previous()
        print namespace, sym, startAddr, length
        
        adt = ArrayDataType(PointerDataType.dataType, length/4, 4, currentProgram.getDataTypeManager())
        assert length == adt.getLength()
        adset = AddressSet(startAddr, endAddr)
        if listing.getInstructions(adset, True).hasNext():
            print "Can't create data because the current selection contains instructions"
            continue
        listing.clearCodeUnits(startAddr, endAddr, False)
        listing.createData(startAddr, adt, length)

