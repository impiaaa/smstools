#
#@author 
#@category 
#@keybinding
#@menupath
#@toolbar
from ghidra.program.model.symbol import FlowType

glb = currentProgram.getNamespaceManager().getGlobalNamespace()
symdb = currentProgram.symbolTable

nameRef = getNamespace(getNamespace(glb, "JDrama"), "TNameRef")

namespacesToExplore = [nameRef]
exploredNamespaces = set()
classesPotentialParents = {}

while len(namespacesToExplore) > 0:
    classNamespace = namespacesToExplore.pop(0)
    exploredNamespaces.add(classNamespace)
    destructors = symdb.getSymbols(u"~"+classNamespace.name, classNamespace)
    vts = symdb.getSymbols(u"__vt", classNamespace)
    for sym in destructors+vts:
        for ref in getReferencesTo(sym.address):
            func = getFunctionContaining(ref.fromAddress)
            if func is None: continue
            derivedClassNamespace = func.parentNamespace
            if derivedClassNamespace == classNamespace: continue
            if func.name != u"~"+derivedClassNamespace.name: continue
            
            fullDerivedName = derivedClassNamespace.getName(True)
            fullParentName = classNamespace.getName(True)
            
            if fullDerivedName in classesPotentialParents:
                classesPotentialParents[fullDerivedName].add(fullParentName)
            else:
                classesPotentialParents[fullDerivedName] = set([fullParentName])
            
            if derivedClassNamespace not in exploredNamespaces:
                namespacesToExplore.append(derivedClassNamespace)

classParents = {}
action = True
while action:
    action = False
    for k in list(classesPotentialParents.keys()):
        if len(classesPotentialParents[k]) == 1:
            classParents[k] = list(classesPotentialParents[k])[0]
            del classesPotentialParents[k]
            action = True
            
        else:
            potentialParents = classesPotentialParents[k]
            for potentialParent in list(potentialParents):
                if potentialParent not in classParents:
                    break
                if classParents[potentialParent] in potentialParents:
                    potentialParents.remove(classParents[potentialParent])
                    action  = True

from pprint import pprint
pprint(classesPotentialParents)

jsystem = getNamespace(glb, "JSystem")
operatorNew = symdb.getSymbol("operator_new", jsystem)
libc = getNamespace(glb, "MSL_C.PPCEABI.bare.H")
strcmp = symdb.getSymbol("strcmp", libc)

sizes = {}
names = {}
for classNamespace in exploredNamespaces:
    constructors = symdb.getSymbols(classNamespace.name, classNamespace)
    vts = symdb.getSymbols(u"__vt", classNamespace)
    for sym in constructors+vts:
        for ref in getReferencesTo(sym.address):
            #if ref.referenceType != FlowType.UNCONDITIONAL_CALL: continue
            callConstructorInst = getInstructionAt(ref.fromAddress)
            
            inst = callConstructorInst.getPrevious()
            for i in range(10):
                if inst.getFlowType().isCall() and inst.getNumOperands() == 1 and inst.getOpObjects(0)[0] == operatorNew.address:
                    break
                inst = inst.getPrevious()
            if not inst.getFlowType().isCall() or inst.getNumOperands() != 1 or inst.getOpObjects(0)[0] != operatorNew.address:
                continue
            callNewInst = inst
            
            inst = callNewInst.getPrevious()
            for i in range(2):
                if inst.mnemonicString == u'li': break
                inst = inst.getPrevious()
            if inst.mnemonicString != u'li': continue
            mallocSizeInst = inst
            
            name = classNamespace.getName(True)
            size = int(mallocSizeInst.getScalar(1).value)
            assert size is not None
            if name in sizes:
                sizes[name] = min(size, sizes[name])
            else:
                sizes[name] = size
            
            
            inst = mallocSizeInst.getPrevious()
            for i in range(6):
                if inst.getFlowType().isCall():
                    break
                inst = inst.getPrevious()
            if not inst.getFlowType().isCall() or inst.getNumOperands() != 1 or inst.getOpObjects(0)[0] != strcmp.address:
                continue
            callStrcmpInst = inst
            
            inst = callStrcmpInst.getPrevious()
            for i in range(4):
                refs = getReferencesFrom(inst.address)
                if len(refs) == 1:
                    break
                inst = inst.getPrevious()
            if len(refs) != 1:
                print "Couldn't find refs starting from", callStrcmpInst.address
                continue
            ref = refs[0]
            #if ref.referenceType != FlowType.DATA:
            #    print "Ref not data at", ref
            #    continue
            data = getDataAt(ref.getToAddress())
            if data is None or data.dataType.name != u'string':
                print "data not string at", data
                continue
            instName = data.getValue()
            if name in names:
                names[name].add(instName)
            else:
                names[name] = set([instName])

import weakref

class ClassObj:
    def __init__(self, name):
        self.name = name
        self.children = set()
        self.size = sizes.get(name, None)
        self.names = names.get(name, set())
    def get(self, name):
        if self.name == name:
            return self
        else:
            for child in self.children:
                o = child.get(name)
                if o: return o
    def p(self, indent=0, parent=None, doPrint=False):
        if self.name == u'TMapObjBase': doPrint = True
        #print '  '*indent+self.name, '' if self.size is None else hex(self.size), u', '.join(self.names)
        if doPrint:
            for n in self.names:
                print "    case "+repr(str(n))+":"
        #if len(self.names):
        #    print "@register(%s)"%(", ".join(map(repr, map(str, self.names))))
        #print "class", self.name,
        #if parent:
        #    print "("+parent.name+")",
        #    if self.size != parent.size:
        #        print ":"
        #    else:
        #        print ": pass"
        #print
        for child in sorted(self.children, cmp=lambda x,y: cmp(x.name, y.name) if len(x.children) == len(y.children) else cmp(len(x.children), len(y.children))):
            child.p(indent+1, self, doPrint)
        #print
    def __repr__(self):
        return '%s(%d)'%(self.name, self.size)
    def cleanNames(self):
        for child in self.children:
            self.names.difference_update(child.names)
            child.cleanNames()

root = ClassObj(nameRef.getName(True))

action = True
while action:#len(classParents) > 0:
    action = False
    for derivedName, parentName in classParents.items():
        parent = root.get(parentName)
        if parent is not None:
            o = ClassObj(derivedName)
            if o.size is not None and parent.size is not None: parent.size = min(o.size, parent.size)
            parent.children.add(o)
            del classParents[derivedName]
            action = True

root.cleanNames()
pprint(classParents)
root.p()

def setupStructs(k, parentDt=None):
    dt = currentProgram.getDataTypeManager().getDataType("boot.dol/Demangler/"+k.name.replace("::", "/"))
    if dt is not None and dt.isNotYetDefined() and k.size is not None and (parentDt is None or parentDt.getLength() <= k.size):
        dt.setDescription("generated from classes.py")
        if parentDt is not None:
            dt.add(parentDt, 0, "_base", "")
        assert dt.getLength() == parentDt.getLength()
        assert dt.getLength() > 0
        dt.growStructure(k.size-dt.getLength())
        assert dt.getLength() == k.size
        print "Set up", k.name
    for child in k.children:
        setupStructs(child, dt)

#setupStructs(root)
