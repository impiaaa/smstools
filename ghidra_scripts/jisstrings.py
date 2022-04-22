#
#@keybinding
#@menupath Tools.jisstrings
#@toolbar

from jarray import *
from ghidra.program.model.data import *

symdb = currentProgram.symbolTable
listing = currentProgram.getListing()
namespaceSymbols = list(symdb.getChildren(currentProgram.getNamespaceManager().getGlobalNamespace().getSymbol()))
while len(namespaceSymbols) > 0:
    namespaceSymbol = namespaceSymbols.pop(0)
    namespace = symdb.getNamespace(namespaceSymbol.name, namespaceSymbol.getParentNamespace())
    if namespace is None: continue
    print namespace
    namespaceSymbols.extend(symdb.getChildren(namespaceSymbol))
    for sym in symdb.getSymbols(namespace):
        if not sym.name.startswith(u'@'): continue
        
        addr = sym.address.next()
        if addr is None: continue

        while len(symdb.getSymbols(addr)) == 0:
            addr = addr.next()
        length = addr.subtract(sym.address)

        #if isinstance(sym.object.getDataType(), TerminatedStringDataType):
        #    listing.clearCodeUnits(sym.address, addr.previous(), False)
        #
        #continue
    
        if sym.object.isDefined(): continue
        arr = zeros(length, 'b')
        try:
            currentProgram.memory.getBytes(sym.address, arr)
        except:
            continue
        l = arr.tolist()
        if len(l) < 2 or all([x == 0 for x in l]) or any([x > 0 and x < 32 for x in l]): continue
        s = arr.tostring()
        try:
            u = s.decode('shift-jis')
        except UnicodeDecodeError:
            continue
        if not u.endswith(u'\0'): continue
        u = u.rstrip(u'\0')
        if len(u) < 2: continue
        print u
        newData = listing.createData(sym.address, StringDataType.dataType, l.index(0)+1)
        newData.setComment(newData.PLATE_COMMENT, "Found via jisstrings")
