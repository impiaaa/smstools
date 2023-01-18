from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import ArrayDataType

listing = currentProgram.listing

def getField(data, name):
    for i in range(data.numComponents):
        c = data.getComponent(i)
        if c.fieldName == name:
            return c

defined = set()

def toString(data, dataType=None, arrayCount=None):
    if dataType is not None and (not data.defined or (arrayCount is not None and (not data.pointer) and (not data.array or data.numComponents != arrayCount)) or (arrayCount is None and data.dataType != dataType)):
        if arrayCount is not None:
            dataType = ArrayDataType(dataType, arrayCount, dataType.length, currentProgram.getDataTypeManager())
        startAddr = data.address
        endAddr = startAddr.add(dataType.length).previous()
        print "Defining data", dataType, "at", startAddr, endAddr
        adset = AddressSet(startAddr, endAddr)
        if listing.getInstructions(adset, True).hasNext():
            raise RuntimeError("Can't create data because %s contains instructions"%adset)
        listing.clearCodeUnits(startAddr, endAddr, False)
        data = listing.createData(startAddr, dataType, dataType.length)
    
    if data.array:
        #print data.fieldName or data.label, "is an array, each type is", data.dataType.dataType
        return "["+(", ".join(toString(data.getComponent(i), data.dataType.dataType) for i in range(data.numComponents)))+"]"
    elif data.structure:
        #print data.fieldName or data.label, "is a structure", data.dataType.name
        if data.dataType.name == 'AnimInfo':
            countField = 'dataCount'
            arrayField = 'animData'
        elif data.dataType.name == 'ObjHitInfo':
            countField = 'hitDataCount'
            arrayField = 'hitDataTable'
        elif data.dataType.name == 'MapCollisionInfo':
            countField = 'collisionDataCount'
            assert getField(data, 'collisionDataCount').value.value == getField(data, 'colliderCount').value.value, data
            arrayField = 'collisionData'
        elif data.dataType.name == 'SoundInfo':
            countField = 'soundKeyCount'
            arrayField = 'soundKeys'
        elif data.dataType.name == 'PhysicalInfo':
            countField = 'physicalDataCount'
            arrayField = 'physicalData'
        else:
            countField = None
            arrayField = None
        s = "{"
        for i in range(data.numComponents):
            c = data.getComponent(i)
            if not c.defined and c.value.value == 0:
                continue
            if c.fieldName == countField:
                dataCount = c.value.value
                continue
            s += repr(c.fieldName)
            s += ': '
            if c.fieldName == arrayField:
                #print data.dataType.name, 'has array', arrayField, 'length', dataCount
                arrayCount = dataCount
            else:
                arrayCount = None
            if c.defined:
                fieldType = data.dataType.getComponent(i).dataType
            else:
                fieldType = None
            #print 'Field', c.fieldName, 'has type', fieldType
            s += toString(c, fieldType, arrayCount)
            s += ', '
        s += "}"
        return s
    elif data.pointer:
        #print data.fieldName or data.label, "is a pointer to", data.dataType.dataType
        deref = listing.getDataAt(data.value)
        if deref is None:
            return repr(deref)
        elif deref.hasStringValue():
            return toString(deref)
        else:
            if deref.label not in defined:
                fout.write(deref.label+' = '+toString(deref, data.dataType.dataType, arrayCount)+'\n')
                defined.add(deref.label)
            return deref.label
    else:
        #print data.fieldName or data.label, "is a scalar or string"
        return repr(data.value)

d = listing.getDataAt(currentAddress)
fout = open(getProjectRootFolder().projectLocator.projectDir.toString()+'/'+d.label+".py", 'w')
fout.write(d.label+' = '+toString(d)+'\n')
fout.close()

