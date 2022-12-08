def getType(name):
    name = name.split("::")[-1]
    if name.startswith("unsigned "): name = "u"+name[9:]
    if name.endswith(" *"):
        ptr = True
        name = name[:-2]
    else:
        ptr = False
    l = []; dtm.findDataTypes(name, l)
    if len(l) != 0:
        if ptr:
            return dtm.getPointer(l[0])
        else:
            return l[0]
    else:
        return None

dtm = currentProgram.dataTypeManager
voidp = dtm.getPointer(dtm.getDataType("/void"))
for sym in currentProgram.symbolTable.getSymbols("JSUConvertOffsetToPtr"):
    f = getFunctionAt(sym.address)
    tempParam = f.comment[f.comment.find("<")+1:f.comment.find(">")]
    sig = f.signature.copy(dtm)
    returnType = getType(tempParam)
    if returnType is not None:
        sig.returnType = dtm.getPointer(returnType)
    else:
        sig.returnType = voidp
    argsDef = f.comment[f.comment.find("(")+1:f.comment.find(")")]
    args = []
    for i, a in enumerate(argsDef.split(',')):
        argType = getType(a.strip())
        if argType is None: argType = voidp
        args.append(ghidra.program.model.data.ParameterDefinitionImpl("param_"+str(i+1), argType, ""))
    sig.setArguments(args)
    sig.genericCallingConvention = ghidra.program.model.data.GenericCallingConvention.stdcall
    runCommand(ghidra.app.cmd.function.ApplyFunctionSignatureCmd(f.entryPoint, sig, f.signatureSource))

