#
#@author 
#@category 
#@keybinding
#@menupath
#@toolbar

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

currentFunction = getFunctionContaining(currentAddress)
baseParamConstructor = currentProgram.getListing().getFunctions("TBaseParam", "TBaseParam")[0]

thisType = currentFunction.parameters[0].dataType.dataType
#thisType = currentProgram.getDataTypeManager().getDataType("boot.dol/EnemyMarioPadSettingParams")
if thisType:
    inst = getInstructionAt(currentAddress)
    while inst.address < currentFunction.body.maxAddress:
        if inst.mnemonicString == u'stw' and inst.numOperands == 2:
            offset, reg = inst.getOpObjects(1)
            if reg.name == u'r31':
                refs = getReferencesFrom(inst.address)
                if len(refs) > 0:
                    sym = getDataAt(refs[0].toAddress).symbols[0]
                    if sym.name == u'__vt' and sym.parentNamespace.name.startswith(u'TParamT'):
                        newTypeName = sym.parentNamespace.getName(True)
                        newTypeName = newTypeName[:newTypeName.find('<')].replace(u'::', u'/')+newTypeName[newTypeName.find('<'):]
                        newType = currentProgram.getDataTypeManager().getDataType("boot.dol/Demangler/"+newTypeName)
                        print offset, newTypeName, newType
                        thisType.replaceAtOffset(offset.value, newType, 0, None, None)
        inst = inst.next

options = DecompileOptions()
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(currentFunction.program)
res = ifc.decompileFunction(currentFunction, 60, monitor)
high_func = res.getHighFunction()

inst = getInstructionAt(currentAddress)
while inst.address < currentFunction.body.maxAddress:
    callConstructor = None
    if inst.getFlowType().isCall() and \
       inst.getFlows()[0] == baseParamConstructor.entryPoint:
        callConstructor = inst
        print "Constructor is called at", callConstructor.address
    
    fieldOffset = None
    if callConstructor is not None:
        call = list(high_func.getPcodeOps(callConstructor.address))[0]
        thisDef = call.inputs[1].getDef().inputs[0].getDef()
        if thisDef is None:
            thisDef = call.inputs[1].getDef()
        thisType = thisDef.inputs[0].getHigh().dataType.dataType
        fieldOffset = thisDef.inputs[1].getHigh().scalar.value
        try:
            paramName = bytearray(getDataAt(getAddressFactory().getDefaultAddressSpace().getAddress(call.inputs[4].getDef().inputs[0].getHigh().scalar.value)).bytes).decode('shift-jis').rstrip(u'\0')
        except AttributeError:
            fieldOffset = None
    
    if fieldOffset is not None:
        print fieldOffset, paramName
        thisType.getComponentAt(fieldOffset).fieldName = paramName
        
    inst = inst.next
