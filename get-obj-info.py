from struct import *
from ..common import *
from dolreader.dol import *
import glob

def getString2(f, pos):
    return getString(pos, f)

dolToMemoryOffset = 0x80003000

readCache = {}

class ReadableStruct2(Readable):
    def read(self, fin):
        for i, (field, value) in enumerate(zip(self.fields, self.header.unpack(fin.read(self.header.size)))):
            if isinstance(field, str):
                setattr(self, field, value)
            elif len(field) == 2:
                fieldName, fieldType = field
                if value == 0:
                    setattr(self, fieldName, None)
                else:
                    offset = value
                    if offset in readCache:
                        value = readCache[offset]
                    else:
                        value = fieldType(fin, offset)
                        readCache[offset] = value
                    setattr(self, fieldName, value)
            else:
                fieldName, fieldType, fieldCount = field
                if value == 0:
                    setattr(self, fieldName, None)
                else:
                    offset = value
                    if offset in readCache:
                        value = readCache[offset]
                    else:
                        value = [fieldType(fin, offset+i*fieldType.header.size) for i in range(getattr(self, fieldCount))]
                        readCache[offset] = value
                    setattr(self, fieldName, value)
            
    def print(self, indent=1):
        print(self.__class__.__name__)
        for field in self.fields:
            print('  '*indent, end='')
            if isinstance(field, str):
                fieldName = field
                value = getattr(self, field)
            else:
                fieldName = field[0]
                value = getattr(self, fieldName)
            print(fieldName, "=", end=" ")
            if isinstance(value, ReadableStruct2):
                value.print(indent+1)
            elif isinstance(value, int):
                print(hex(value))
            elif isinstance(value, list):
                for x in value:
                    x.print(indent+1)
            else:
                print(value)

class PhysicalData(ReadableStruct2):
    header = Struct('>fffffffffffff')
    fields = ["field_0x0", "field_0x4", "field_0x8", "field_0xc", "field_0x10", 
        "field_0x14", "field_0x18", "field_0x1c", "field_0x20", "field_0x24", 
        "field_0x28", "field_0x2c", "field_0x30"]

class PhysicalInfo(ReadableStruct2):
    header = Struct('>iIi')
    fields = ["field_0x0", ("physicalData", PhysicalData), "field_0x8"]

class CollisionData(ReadableStruct2):
    header = Struct('>II')
    fields = [("name", getString2), "field_0x4"]

class AnimData(ReadableStruct2):
    header = Struct('>IIB3xII')
    fields = [("modelName", getString2), ("animBaseName", getString2), "animType", ("material", getString2),
        ("basName", getString2)]
    def read(self, fin):
        super().read(fin)

class AnimInfo(ReadableStruct2):
    header = Struct('>HHI')
    fields = ["dataCount", "field_0x2", ("animData", AnimData, "dataCount")]

class HitDataTable(ReadableStruct2):
    header = Struct('>ffff')
    fields = ["zScale1", "yScale1", "zScale2", "yScale2"]

class HitInfo(ReadableStruct2):
    header = Struct('>IIfI')
    fields = ["field_0x0", "flags", "yScale", ("hitDataTable", HitDataTable)]

class CollisionInfo(ReadableStruct2):
    header = Struct('>II')
    fields = ["field_0x0", ("collosionData", CollisionData)]

class ObjSoundInfo(ReadableStruct2):
    header = Struct('>II')
    fields = ["always10", "soundDataOffset"]

class SinkData(ReadableStruct2):
    header = Struct('>ff')
    fields = ["field_0x0", "field_0x4"]

class ModelInfo(ReadableStruct2):
    header = Struct('>IIIII')
    fields = [("filename", getString2), ("jointName", getString2), "modelDataOffset", "modelOffset", "jointOffset"]

class MoveData(ReadableStruct2):
    header = Struct('>III')
    fields = [("bckName", getString2), "animOffset", "frameCtrlOffset"]

class ObjData(ReadableStruct2):
    header = Struct('>IIIIIIIIIIIIfII')
    fields = [("baseName", getString2), "hitFlags", ("managerName", getString2), ("groupName", getString2),
        ("animInfo", AnimInfo), ("hitInfo", HitInfo), ("collisionInfo", CollisionInfo), ("soundInfo", ObjSoundInfo), 
        ("physicalInfo", PhysicalInfo), ("sinkData", SinkData), ("modelInfo", ModelInfo), ("moveData", MoveData), 
        "xScale", "objFlags", "keyCode"]

fin = DolFile(open("dol/boot.dol", 'rb'))
fin.seek(0x803c8580)
objInfoTable = [ObjData(fin, objPtr) for objPtr in unpack('>360I', fin.read(1440))]
materialOverrides = {
0x4000009c: "LeafBoat",
0x20000068: "nozzleBox",
0x20000026: "nozzleItem",
0x40000048: "flower",
0x4000001c: "kibako",
0x4000001b: "ArrowBoard",
0x4000005a: "barrel",
0x400002c2: "BrickBlock",
0x400002c3: "WaterMelon",
0x400000d3: "SandBombBase",
0x400000ce: "mirror",
0x400000cd: "SandBombBase",
0x400000ce: "SandBombBase",
0x400000a5: "LeafBoat",
0x400000a0: "bianco",
0x400000ba: "riccoShip",
0x40000096: "bianco"
}
for o in []:#objInfoTable:
    if o.animInfo is not None:
        print("{ k: '%s'"%o.baseName, end='')
        if o.hitFlags in materialOverrides:
            print(", t: '%s'"%materialOverrides[o.hitFlags], end='')
        if o.animInfo.animData is not None:
            animData = o.animInfo.animData[0]
            print(", m: '%s'"%(animData.modelName), end='')
            if o.hitFlags not in materialOverrides and animData.material is not None:
                print(", t: '%s'"%animData.material, end='')
            if animData.animBaseName is not None:
                print(", n: '%s', u: %d"%(animData.animBaseName, animData.animType), end='')
                if animData.animType != 0:
                    ext = [0, 0, ".bpk", ".btp", ".btk", ".brk"][animData.animType]
                    #assert len(glob.glob("scene/*/mapobj/"+animData.animBaseName+ext)) > 0
        print(" },")
    elif o.hitFlags in materialOverrides:
        print("{ k: '%s', t: '%s'},"%(o.baseName,materialOverrides[o.hitFlags]))

class ActorData(ReadableStruct2):
    header = Struct('>IIIffffIIIIIiIIB3xI')
    fields = [("baseName", getString2), "field_0x4", "field_0x8", "field_0xc",
        "field_0x10", "field_0x14", "field_0x18", ("groupName", getString2),
        ("modelName", getString2), "field_0x24", ("collisionManagerName", getString2),
        "field_0x2c", "field_0x30", ("particle", getString2), "particleId",
        "field_0x3c", "field_0x40"]

actorDataTable = [ActorData(fin, 0x80389654+i*68) for i in range(29)]
for a in actorDataTable:
    a.print()
    continue
    if not a.modelName and not a.particle: continue
    print("{ k: '%s'"%a.baseName, end='')
    if a.modelName:
        print(", m: '%s'"%(a.modelName), end='')
    if a.particle:
        assert a.particle.startswith("/scene/")
        print(", p: '%s'"%(a.particle[7:]), end='')
    print(" },")

