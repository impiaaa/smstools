import sys
from struct import unpack, pack, Struct, error as StructError
from warnings import warn
from array import array
import math
from enum import Enum, IntEnum
from common import *
from texture import *
from mathutils import *
from bti import Image

bbStruct = Struct('>fff')

stringTableHeaderStruct = Struct('>H2x')
stringTableEntryStruct = Struct('>HH')
def readStringTable(pos, f):
    dest = []
    oldPos = f.tell()

    f.seek(pos)

    count, = stringTableHeaderStruct.unpack(f.read(4))

    for i in range(count):
        keyCode, stringOffset = stringTableEntryStruct.unpack(f.read(4))
        s = getString(pos + stringOffset, f)
        dest.append(s)

    f.seek(oldPos)
    return dest

def stringTableSize(strings):
    return stringTableHeaderStruct.size+(len(strings)*stringTableEntryStruct.size)+sum([len(s.encode('shift-jis'))+1 for s in strings])

def writeStringTable(f, strings):
    f.write(stringTableHeaderStruct.pack(len(strings)))
    table = bytes()
    offsets = []
    strings = [s.encode('shift-jis') for s in strings]
    for s in strings:
        offsets.append(len(table)+stringTableHeaderStruct.size)
        table += s+b'\0'
    for s, offset in zip(strings, offsets):
        f.write(stringTableEntryStruct.pack(calcKeyCode(s), offset+len(offsets)*stringTableEntryStruct.size))
    f.write(table)

class DrawBlock(Section):
    header = Struct('>H2xLL')
    fields = [
        'count',
        'offsetToIsWeighted',
        'offsetToData'
    ]
    def read(self, fin, start, size):
        super().read(fin, start, size)
        fin.seek(start+self.offsetToIsWeighted)
        self.offsetToIsWeighted = None
        bisWeighted = array('B')
        bisWeighted.fromfile(fin, self.count)
        if not all([x in (0,1) for x in bisWeighted]):
            raise Exception("unexpected value in isWeighted array: %s", bisWeighted)
        self.isWeighted = list([x == 1 for x in bisWeighted])

        fin.seek(start+self.offsetToData)
        self.offsetToData = None
        self.data = array('H')
        self.data.fromfile(fin, self.count)
        self.count = None
        if sys.byteorder == 'little': self.data.byteswap()
        
    def write(self, fout):
        self.count = len(self.data)
        self.offsetToIsWeighted = self.header.size+8
        self.offsetToData = self.offsetToIsWeighted+self.count
        super().write(fout)
        bisWeighted = array('B', self.isWeighted)
        bisWeighted.tofile(fout)
        swapArray(self.data).tofile(fout)


class EnvelopBlock(Section):
    header = Struct('>H2xIIII')
    fields = [
        'count',
        'boneCountOffset',
        'weightedIndicesOffset',
        'boneWeightsTableOffset',
        'matrixTableOffset'
    ]
    def read(self, fin, start, size):
        super().read(fin, start, size)
        fin.seek(start+self.boneCountOffset)
        self.boneCountOffset = None
        counts = array('B')
        counts.fromfile(fin, self.count)

        fin.seek(start+self.weightedIndicesOffset)
        self.weightedIndicesOffset = None
        self.weightedIndices = [array('H') for i in range(self.count)]
        for i in range(self.count):
            self.weightedIndices[i].fromfile(fin, counts[i])
            if sys.byteorder == 'little': self.weightedIndices[i].byteswap()
        #numMatrices = max(list(map(max, self.weightedIndices)))+1 if self.count > 0 else 0

        fin.seek(start+self.boneWeightsTableOffset)
        self.boneWeightsTableOffset = None
        self.weightedWeights = [array('f') for i in range(self.count)]
        for i in range(self.count):
            self.weightedWeights[i].fromfile(fin, counts[i])
            if sys.byteorder == 'little': self.weightedWeights[i].byteswap()
        self.count = None

        fin.seek(start+self.matrixTableOffset)
        self.matrixTableOffset = None
        self.matrices = []
        while fin.tell() <= start+size-0x30:
            m = Matrix()
            for j in range(3):
                m[j] = unpack('>ffff', fin.read(16))
            self.matrices.append(m)
    
    def write(self, fout):
        self.count = len(self.weightedIndices)
        if self.count != len(self.weightedWeights): raise ValueError()
        self.boneCountOffset = self.header.size+8
        self.weightedIndicesOffset = self.boneCountOffset+self.count
        self.boneWeightsTableOffset = alignOffset(self.weightedIndicesOffset+(2*sum(map(len, self.weightedIndices))))
        self.matrixTableOffset = alignOffset(self.boneWeightsTableOffset+(4*sum(map(len, self.weightedWeights))))
        super().write(fout)
        counts = array('B', map(len, self.weightedIndices))
        counts.tofile(fout)
        for indices in self.weightedIndices:
            swapArray(indices).tofile(fout)
        alignFile(fout)
        for weights in self.weightedWeights:
            swapArray(weights).tofile(fout)
        alignFile(fout)
        for m in self.matrices:
            for row in m[:3]:
                fout.write(pack('>ffff', *row))


class ModelHierarchy(ReadableStruct):
    header = Struct('>HH')
    fields = ["type", "index"]

class ModelInfoBlock(Section):
    header = Struct('>H2xIII')
    fields = [
        'loadFlags',
        'mtxGroupCount',
        'vertexCount',
        'offsetToEntries'
    ]
    def read(self, fin, start, size):
        super().read(fin, start, size)
        fin.seek(start+self.offsetToEntries)
        self.offsetToEntries = None
        self.scenegraph = []
        n = ModelHierarchy()
        n.read(fin)
        while n.type != 0:
            self.scenegraph.append(n)
            n = ModelHierarchy()
            n.read(fin)
    
    def write(self, fout):
        self.offsetToEntries = self.header.size+8
        super().write(fout)
        for n in self.scenegraph:
            n.write(fout)
        fout.write(b'\0\0\0\0')

class SceneGraph(object):
    def __init__(self):
        self.children = []
        self.type = 0
        self.index = 0
    def to_dict(self, bmd=None):
        d = {'children': [c.to_dict(bmd) for c in self.children],
             'type': self.type,
             'index': self.index}
        if bmd is not None:
            if self.type == 0x10:
                # joint
                d['frame'] = bmd.jnt1.frames[self.index]
            elif self.type == 0x11:
                # material
                d['material'] = bmd.mat3.materials[self.index]
            elif self.type == 0x12:
                # shape
                d['batch'] = bmd.shp1.batches[self.index]
        return d
    def copy(self):
        sg = SceneGraph()
        sg.children = [c.copy() for c in self.children]
        sg.type = self.type
        sg.index = self.index
        return sg
    def to_array(self):
        m = ModelHierarchy()
        m.type = self.type
        m.index = self.index
        l = [m]
        if len(self.children) > 0:
            m = ModelHierarchy()
            m.type = 1
            m.index = 0
            l.append(m)
            for c in self.children:
                l.extend(c.to_array())
            m = ModelHierarchy()
            m.type = 2
            m.index = 0
            l.append(m)
        return l

INVALID_INDEX = 0xFFFF

def buildSceneGraph(inf1, sg, j=0):
    i = j
    while i < len(inf1.scenegraph):
        n = inf1.scenegraph[i]

        if n.type == 1:
            i += buildSceneGraph(inf1, sg.children[-1], i + 1)
        elif n.type == 2:
            return i - j + 1
        elif n.type == 0x10 or n.type == 0x11 or n.type == 0x12:
            t = SceneGraph()
            t.type = n.type
            t.index = n.index
            sg.children.append(t)
        else:
            warn("buildSceneGraph(): unexpected node type %d"%n.type)
        
        i += 1

    # remove dummy node at root
    if len(sg.children) == 1:
        sg = sg.children[0]
    else:
        sg.type = sg.index = INVALID_INDEX
        warn("buildSceneGraph(): Unexpected size %d"%len(sg.children))

    return 0



class JointBlock(Section):
    header = Struct('>H2xIII')
    fields = [
        'count',
        'jntEntryOffset',
        'remapTableOffset',
        'stringTableOffset'
    ]
    def read(self, fin, start, size):
        super().read(fin, start, size)
        boneNames = readStringTable(start+self.stringTableOffset, fin)
        if len(boneNames) != self.count: warn("number of strings doesn't match number of joints")

        fin.seek(start+self.jntEntryOffset)
        self.jntEntryOffset = None
        self.matrices = [Matrix() for i in range(self.count)]
        for m in self.matrices:
            m.zero()
        self.isMatrixValid = [False]*self.count
        self.frames = []
        for i in range(self.count):
            f = Jnt1Entry()
            f.read(fin)
            f.name = boneNames[i]
            self.frames.append(f)
        
        fin.seek(start+self.remapTableOffset)
        self.remapTableOffset = None
        self.remapTable = array('H')
        self.remapTable.fromfile(fin, self.count)
        self.count = None
        if sys.byteorder == 'little': self.remapTable.byteswap()
    
    def write(self, fout):
        self.count = len(self.frames)
        if self.count != len(self.matrices): raise ValueError()
        self.jntEntryOffset = self.header.size+8
        self.remapTableOffset = self.jntEntryOffset+(self.count*(Jnt1Entry.header.size+bbStruct.size+bbStruct.size))
        self.stringTableOffset = alignOffset(self.remapTableOffset+len(self.remapTable)*self.remapTable.itemsize)
        super().write(fout)
        for f in self.frames:
            f.write(fout)
        swapArray(self.remapTable).tofile(fout)
        alignFile(fout)
        writeStringTable(fout, [f.name for f in self.frames])

class Jnt1Entry(Readable):
    header = Struct('>HBxfffhhh2xffff')
    def __init__(self, name=None, scale=None, rotation=None, translation=None):
        if name is not None: self.name = name
        if scale is not None: self.scale = scale
        if rotation is not None: self.rotation = rotation
        if translation is not None: self.translation = translation
    
    def read(self, fin):
        self.flags, self.calcFlags, \
            sx, sy, sz, \
            rx, ry, rz, \
            tx, ty, tz, \
            self.boundingSphereRadius = self.header.unpack(fin.read(40))
        self.scale = Vector((sx, sy, sz))
        self.rotation = Euler((rx*math.pi/0x8000, ry*math.pi/0x8000, rz*math.pi/0x8000))
        self.translation = Vector((tx, ty, tz))
        self.bbMin = bbStruct.unpack(fin.read(bbStruct.size))
        self.bbMax = bbStruct.unpack(fin.read(bbStruct.size))
    
    def write(self, fout):
        fout.write(self.header.pack(
            self.flags, self.calcFlags,
            self.scale.x, self.scale.y, self.scale.z,
            round(self.rotation.x*0x8000/math.pi),
            round(self.rotation.y*0x8000/math.pi),
            round(self.rotation.z*0x8000/math.pi),
            self.translation.x, self.translation.y, self.translation.z,
            self.boundingSphereRadius
        ))
        fout.write(bbStruct.pack(*self.bbMin))
        fout.write(bbStruct.pack(*self.bbMax))
    
    def __repr__(self):
        return "{}({}, {}, {}, {})".format(__class__.__name__, repr(self.name), self.scale, self.rotation, self.translation)


class IndTexOrder(ReadableStruct):
    header = Struct('BBxx')
    fields = ["texCoordId", "texture"]

class IndTexMtx(Readable):
    def read(self, fin):
        p = unpack('>6f', fin.read(0x18))
        self.exponent, = unpack('bxxx', fin.read(4))
        scale = 2**self.exponent
        self.m = [
            p[0]*scale, p[1]*scale, p[2]*scale, scale,
            p[3]*scale, p[4]*scale, p[5]*scale, 0.0
        ]
    def write(self, fout):
        scale = 2**self.exponent
        p = [
            self.m[0]/scale, self.m[1]/scale, self.m[2]/scale,
            self.m[4]/scale, self.m[5]/scale, self.m[6]/scale
        ]
        fout.write(pack('>6f', *p))
        fout.write(pack('Bxxx', self.exponent))

class IndTexCoordScale(ReadableStruct):
    header = Struct('BBxx')
    fields = ["scaleS", "scaleT"]

class IndTevStage(ReadableStruct):
    header = Struct('BBBBBBBBBxxx')
    fields = ["indTexId", "format", "bias", "mtxId", "wrapS", "wrapT", "addPrev", ("unmodifiedTexCoordLod", bool), "alphaSel"]

class IndInitData(ReadableStruct):
    header = Struct('BBxx')
    fields = [("hasIndirect", bool), "indTexStageNum"]
    def read(self, fin):
        super().read(fin)
        self.indTexOrder = [IndTexOrder(fin) for i in range(4)]
        self.indTexMtx = [IndTexMtx(fin) for i in range(3)]
        self.indTexCoordScale = [IndTexCoordScale(fin) for i in range(4)]
        self.indTevStage = [IndTevStage(fin) for i in range(16)]
    def write(self, fout):
        super().write(fout)
        for x in self.indTexOrder: x.write(fout)
        for x in self.indTexMtx: x.write(fout)
        for x in self.indTexCoordScale: x.write(fout)
        for x in self.indTevStage: x.write(fout)
    def __eq__(self, other):
        return super().__eq__(other) and \
            self.indTexOrder == other.indTexOrder and \
            self.indTexMtx == other.indTexMtx and \
            self.indTexCoordScale == other.indTexCoordScale and \
            self.indTevStage == other.indTevStage

class CullMode(Enum):
    NONE  = 0 # Do not cull any primitives.
    FRONT = 1 # Cull front-facing primitives.
    BACK  = 2 # Cull back-facing primitives.
    ALL   = 3 # Cull all primitives.

class ColorSrc(Enum):
    REG = 0
    VTX = 1

class DiffuseFunction(Enum):
    NONE = 0
    SIGN = 1
    CLAMP = 2

def _SHIFTL(v, s, w):
    """mask the first w bits of v before lshifting"""
    return (v & ((0x01 << w) - 1)) << s

def _SHIFTR(v, s, w):
    """rshift v and mask the first w bits afterwards"""
    return (v >> s) & ((0x01 << w) - 1)

class ColorChanInfo(ReadableStruct):
    header = Struct('>BBBBBB2x')
    fields = [
        ("lightingEnabled", bool),
        ("matColorSource", ColorSrc),
        "litMask",
        ("diffuseFunction", DiffuseFunction),
        "attenuationFunction",
        ("ambColorSource", ColorSrc)
    ]
    def getId(self):
        difffn = DiffuseFunction.NONE if self.attenuationFunction==0 else self.diffuseFunction
        return (self.matColorSource.value&1)|\
               (_SHIFTL(self.lightingEnabled,1,1))|\
               (_SHIFTL(self.litMask,2,4))|\
               (_SHIFTL(self.ambColorSource.value,6,1))|\
               (_SHIFTL(difffn.value,7,2))|\
               (_SHIFTL(((2-self.attenuationFunction)>0),9,1))|\
               (_SHIFTL((self.attenuationFunction>0),10,1))|\
               (_SHIFTL((_SHIFTR(self.litMask,4,4)),11,4))

class LightInfo(ReadableStruct):
    header = Struct('>ffffffBBBBffffff')
    fields = [
        'x', 'y', 'z',
        'dx', 'dy', 'dz',
        'r', 'g', 'b', 'a',
        'a0', 'a1', 'a2',
        'k0', 'k1', 'k2'
    ]
    def read(self, fin):
        super().read(fin)
        self.pos = (self.x, self.y, self.z)
        self.dir = (self.dx, self.dy, self.dz)
        self.color = (self.r, self.g, self.b, self.a)
    def write(self, fout):
        self.x, self.y, self.z = self.pos
        self.dx, self.dy, self.dz = self.dir
        self.r, self.g, self.b, self.a = self.color
        super().write(fout)

class TexGenType(IntEnum):
    MTX3x4 = 0
    MTX2x4 = 1
    BUMP0 = 2
    BUMP1 = 3
    BUMP2 = 4
    BUMP3 = 5
    BUMP4 = 6
    BUMP5 = 7
    BUMP6 = 8
    BUMP7 = 9
    SRTG = 10

class TexGenSrc(IntEnum):
    POS = 0
    NRM = 1
    BINRM = 2
    TANGENT = 3
    TEX0 = 4
    TEX1 = 5
    TEX2 = 6
    TEX3 = 7
    TEX4 = 8
    TEX5 = 9
    TEX6 = 10
    TEX7 = 11
    TEXCOORD0 = 12
    TEXCOORD1 = 13
    TEXCOORD2 = 14
    TEXCOORD3 = 15
    TEXCOORD4 = 16
    TEXCOORD5 = 17
    TEXCOORD6 = 18
    COLOR0 = 19
    COLOR1 = 20

class TexGenMatrix(IntEnum):
    PNMTX0 = 0
    PNMTX1 = 3
    PNMTX2 = 6
    PNMTX3 = 9
    PNMTX4 = 12
    PNMTX5 = 15
    PNMTX6 = 18
    PNMTX7 = 21
    PNMTX8 = 24
    PNMTX9 = 27
    TEXMTX0 = 30
    TEXMTX1 = 33
    TEXMTX2 = 36
    TEXMTX3 = 39
    TEXMTX4 = 42
    TEXMTX5 = 45
    TEXMTX6 = 48
    TEXMTX7 = 51
    TEXMTX8 = 54
    TEXMTX9 = 57
    IDENTITY = 60
    DTTMTX0 = 64
    DTTMTX1 = 67
    DTTMTX2 = 70
    DTTMTX3 = 73
    DTTMTX4 = 76
    DTTMTX5 = 79
    DTTMTX6 = 82
    DTTMTX7 = 85
    DTTMTX8 = 88
    DTTMTX9 = 91
    DTTMTX10 = 94
    DTTMTX11 = 97
    DTTMTX12 = 100
    DTTMTX13 = 103
    DTTMTX14 = 106
    DTTMTX15 = 109
    DTTMTX16 = 112
    DTTMTX17 = 115
    DTTMTX18 = 118
    DTTMTX19 = 121
    DTTIDENTITY = 125

class TexCoordInfo(ReadableStruct):
    header = Struct('>BBBx')
    fields = [
        ("type", TexGenType),
        ("source", TexGenSrc),
        ("matrix", TexGenMatrix)
    ]

class TexMtxProjection(Enum):
    MTX3x4 = 0
    MTX2x4 = 1

class TexMtxInfo(ReadableStruct):
    header = Struct('>BB2x')
    fields = [
        ("projection", TexMtxProjection),
        "info"
    ]
    def read(self, fin):
        super().read(fin)
        self.center = unpack('>3f', fin.read(12))
        self.scale = unpack('>2f', fin.read(8))
        self.rotation = unpack('>h2x', fin.read(4))[0]/0x7FFF
        self.translation = unpack('>2f', fin.read(8))
        self.effectMatrix = unpack('>16f', fin.read(64))
    
    def write(self, fout):
        super().write(fout)
        fout.write(pack('>3f', *self.center))
        fout.write(pack('>2f', *self.scale))
        fout.write(pack('>h2x', int(self.rotation*0x7FFF)))
        fout.write(pack('>2f', *self.translation))
        fout.write(pack('>16f', *self.effectMatrix))
    
    def __repr__(self):
        return super().__repr__()+", center=%s, scale=%s, rotation=%s, translation=%s, effectMatrix=%s"% \
            (self.center, self.scale, self.rotation, self.translation, self.effectMatrix)

    def __eq__(self, other):
        return super().__eq__(other) and \
            self.center == other.center and \
            self.scale == other.scale and \
            self.rotation == other.rotation and \
            self.translation == other.translation and \
            self.effectMatrix == other.effectMatrix

class ColorChannelID(Enum):
    COLOR0 = 0
    COLOR1 = 1
    ALPHA0 = 2
    ALPHA1 = 3
    COLOR0A0 = 4
    COLOR1A1 = 5
    COLOR_ZERO = 6
    ALPHA_BUMP = 7
    ALPHA_BUMP_N = 8
    COLOR_NULL = 0xFF

class TevOrderInfo(ReadableStruct):
    header = Struct('>BBBx')
    fields = [
        "texCoordId",
        "texMap",
        ("chanId", ColorChannelID)
    ]

class CompareType(Enum):
    NEVER = 0
    LESS = 1
    EQUAL = 2
    LEQUAL = 3
    GREATER = 4
    NEQUAL = 5
    GEQUAL = 6
    ALWAYS = 7

class AlphaOp(Enum):
    AND = 0
    OR = 1
    XOR = 2
    XNOR = 3

class AlphaCompInfo(ReadableStruct):
    header = Struct('>BBBBB3x')
    fields = [
        ("comp0", CompareType),
        "ref0",
        ("op", AlphaOp),
        ("comp1", CompareType),
        "ref1"
    ]

class BlendMode(Enum):
    NONE = 0
    BLEND = 1
    LOGIC = 2
    SUBTRACT = 3

class BlendFactor(Enum):
    ZERO = 0
    ONE = 1
    SRCCLR = 2
    INVSRCCLR = 3
    SRCALPHA = 4
    INVSRCALPHA = 5
    DSTALPHA = 6
    INVDSTALPHA = 7

class LogicOp(Enum):
    CLEAR = 0
    AND = 1
    REVAND = 2
    COPY = 3
    INVAND = 4
    NOOP = 5
    XOR = 6
    OR = 7
    NOR = 8
    EQUIV = 9
    INV = 10
    REVOR = 11
    INVCOPY = 12
    INVOR = 13
    NAND = 14
    SET = 15

class BlendInfo(ReadableStruct):
    header = Struct('>BBBB')
    fields = [
        ("blendMode", BlendMode),
        ("srcFactor", BlendFactor),
        ("dstFactor", BlendFactor),
        ("logicOp", LogicOp)
    ]

class ZModeInfo(ReadableStruct):
    header = Struct('>BBBx')
    fields = [
        ("enable", bool),
        ("func", CompareType),
        ("writeZ", bool)
    ]

class NBTScaleInfo(ReadableStruct):
    header = Struct('>Bxxx3f')
    fields = [("enable", bool), "x", "y", "z"]

class TevColorArg(Enum):
    CPREV = 0 # Use the color value from previous TEV stage
    APREV = 1 # Use the alpha value from previous TEV stage
    C0 = 2 # Use the color value from the color/output register 0
    A0 = 3 # Use the alpha value from the color/output register 0
    C1 = 4 # Use the color value from the color/output register 1
    A1 = 5 # Use the alpha value from the color/output register 1
    C2 = 6 # Use the color value from the color/output register 2
    A2 = 7 # Use the alpha value from the color/output register 2
    TEXC = 8 # Use the color value from texture
    TEXA = 9 # Use the alpha value from texture
    RASC = 10 # Use the color value from rasterizer
    RASA = 11 # Use the alpha value from rasterizer
    ONE = 12
    HALF = 13
    KONST = 14
    ZERO = 15 # Use to pass zero value

class TevOp(Enum):
    ADD = 0
    SUB = 1
    COMP_R8_GT = 8
    COMP_R8_EQ = 9
    COMP_GR16_GT = 10
    COMP_GR16_EQ = 11
    COMP_BGR24_GT = 12
    COMP_BGR24_EQ = 13
    COMP_RGB8_GT = 14
    COMP_RGB8_EQ = 15

class TevBias(Enum):
    ZERO = 0
    ADDHALF = 1
    SUBHALF = 2
    _HWB_COMPARE = 3

class TevScale(Enum):
    SCALE_1 = 0
    SCALE_2 = 1
    SCALE_4 = 2
    DIVIDE_2 = 3

class Register(IntEnum):
    PREV = 0
    REG0 = 1
    REG1 = 2
    REG2 = 3

class TevAlphaArg(Enum):
    APREV = 0 # Use the alpha value from previous TEV stage
    A0 = 1 # Use the alpha value from the color/output register 0
    A1 = 2 # Use the alpha value from the color/output register 1
    A2 = 3 # Use the alpha value from the color/output register 2
    TEXA = 4 # Use the alpha value from texture
    RASA = 5 # Use the alpha value from rasterizer
    KONST = 6
    ZERO = 7 # Use to pass zero value

class TevStageInfo(ReadableStruct):
    header = Struct('>x4BBBBBB4BBBBBBx')
    fields = [
        ("colorInA", TevColorArg),
        ("colorInB", TevColorArg),
        ("colorInC", TevColorArg),
        ("colorInD", TevColorArg),
        ("colorOp", TevOp),
        ("colorBias", TevBias),
        ("colorScale", TevScale),
        ("colorClamp", bool),
        ("colorRegId", Register),

        ("alphaInA", TevAlphaArg),
        ("alphaInB", TevAlphaArg),
        ("alphaInC", TevAlphaArg),
        ("alphaInD", TevAlphaArg),
        ("alphaOp", TevOp),
        ("alphaBias", TevBias),
        ("alphaScale", TevScale),
        ("alphaClamp", bool),
        ("alphaRegId", Register)
    ]

class TevKColorSel(IntEnum):
    CONST_1 = 0x00 # constant 1.0
    CONST_7_8 = 0x01 # constant 7/8
    CONST_3_4 = 0x02 # constant 3/4
    CONST_5_8 = 0x03 # constant 5/8
    CONST_1_2 = 0x04 # constant 1/2
    CONST_3_8 = 0x05 # constant 3/8
    CONST_1_4 = 0x06 # constant 1/4
    CONST_1_8 = 0x07 # constant 1/8
    NONE = 0x09
    K0 = 0x0C # K0[RGB] register
    K1 = 0x0D # K1[RGB] register
    K2 = 0x0E # K2[RGB] register
    K3 = 0x0F # K3[RGB] register
    K0_R = 0x10 # K0[RRR] register
    K1_R = 0x11 # K1[RRR] register
    K2_R = 0x12 # K2[RRR] register
    K3_R = 0x13 # K3[RRR] register
    K0_G = 0x14 # K0[GGG] register
    K1_G = 0x15 # K1[GGG] register
    K2_G = 0x16 # K2[GGG] register
    K3_G = 0x17 # K3[GGG] register
    K0_B = 0x18 # K0[BBB] register
    K1_B = 0x19 # K1[BBB] register
    K2_B = 0x1A # K2[BBB] register
    K3_B = 0x1B # K3[RBB] register
    K0_A = 0x1C # K0[AAA] register
    K1_A = 0x1D # K1[AAA] register
    K2_A = 0x1E # K2[AAA] register
    K3_A = 0x1F # K3[AAA] register

class TevSwapModeInfo(ReadableStruct):
    header = Struct('>BB2x')
    fields = ["rasSel", "texSel"]

class TevSwapModeTableInfo(ReadableStruct):
    header = Struct('>BBBB')
    fields = ["rSel", "gSel", "bSel", "aSel"]

class FogInfo(ReadableStruct):
    header = Struct('>BBHffff')
    fields = ["type", "enable", "center", "startz", "endz", "nearz", "farz"]
    def read(self, fin):
        super().read(fin)
        self.color = unpack('>4B', fin.read(4))
        self.table = unpack('>10H', fin.read(20))
    def write(self, fout):
        super().write(fout)
        fout.write(pack('>4B', *self.color))
        fout.write(pack('>10H', *self.table))
    def __hash__(self):
        return hash(super().as_tuple()+(self.color, self.table))
    def __eq__(self, other):
        return super().__eq__(other) and \
            self.color == other.color and \
            self.table == other.table

def safeGet(arr, idx):
    if idx >= 0 and idx < len(arr):
        return arr[idx]
    else:
        return None

def safeIndex(arr, val):
    try:
        return arr.index(val)
    except ValueError:
        return 0xFFFF

class Material(ReadableStruct):
    header = Struct('>BBBBBBBB')
    fields = ["materialMode", "cullModeIndex", "colorChanNumIndex", "texGenNumIndex",
        "tevStageNumIndex", "zCompLocIndex", "zModeIndex", "ditherIndex"]
    def read(self, fin):
        super().read(fin)
        # 0x08
        self.matColorIndices = unpack('>2H', fin.read(4))
        # 0x0C
        self.colorChanIndices = unpack('>4H', fin.read(8))
        # 0x14
        self.ambColorIndices = unpack('>2H', fin.read(4))
        # 0x18
        self.lightInfoIndices = unpack('>8H', fin.read(16))
        # 0x28
        self.texCoordIndices = unpack('>8H', fin.read(16))
        # 0x38
        self.postTexGenIndices = unpack('>8H', fin.read(16))
        # 0x48
        self.texMtxIndices = unpack('>10H', fin.read(20))
        # 0x5C
        self.postTexMtxIndices = unpack('>20H', fin.read(40))
        # 0x84
        self.texNoIndices = unpack('>8H', fin.read(16))
        # 0x94
        self.tevKColorIndices = unpack('>4H', fin.read(8))
        # 0x9C
        self.tevKColorSels = [TevKColorSel(x) if x < 0x20 else x for x in unpack('>16B', fin.read(16))]
        # 0xAC
        self.tevKAlphaSels = [TevKColorSel(x) if x < 0x20 else x for x in unpack('>16B', fin.read(16))]
        # 0xBC
        self.tevOrderIndices = unpack('>16H', fin.read(32))
        # 0xDC
        self.tevColorIndices = unpack('>4H', fin.read(8))
        # 0xE4
        self.tevStageIndices = unpack('>16H', fin.read(32))
        # 0x104
        self.tevSwapModeIndices = unpack('>16H', fin.read(32))
        # 0x124
        self.tevSwapModeTableIndices = unpack('>4H', fin.read(8))
        # 0x12C
        self.unknownIndices6 = unpack('>12H', fin.read(24))
        # 0x144
        self.fogIndex, self.alphaCompIndex, self.blendIndex, self.nbtScaleIndex = unpack('>HHHH', fin.read(8))
    
    def resolve(self, mat3):
        self.cullMode = safeGet(mat3.cullModeArray, self.cullModeIndex)
        self.cullModeIndex = None
        self.colorChanNum = safeGet(mat3.colorChanNumArray, self.colorChanNumIndex)
        self.colorChanNumIndex = None
        self.texGenNum = safeGet(mat3.texGenNumArray, self.texGenNumIndex)
        self.texGenNumIndex = None
        self.tevStageNum = safeGet(mat3.tevStageNumArray, self.tevStageNumIndex)
        self.tevStageNumIndex = None
        self.zCompLoc = safeGet(mat3.zCompLocArray, self.zCompLocIndex)
        self.zCompLocIndex = None
        self.zMode = safeGet(mat3.zModeArray, self.zModeIndex)
        self.zModeIndex = None
        self.dither = safeGet(mat3.ditherArray, self.ditherIndex)
        self.ditherIndex = None
        self.matColors = [safeGet(mat3.matColorArray, i) for i in self.matColorIndices]
        self.matColorIndices = None
        self.colorChans = [safeGet(mat3.colorChanArray, i) for i in self.colorChanIndices]
        self.colorChanIndices = None
        self.ambColors = [safeGet(mat3.ambColorArray, i) for i in self.ambColorIndices]
        self.ambColorIndices = None
        self.lightInfos = [safeGet(mat3.lightInfoArray, i) for i in self.lightInfoIndices]
        self.lightInfoIndices = None
        self.texCoords = [safeGet(mat3.texCoordArray, i) for i in self.texCoordIndices]
        self.texCoordIndices = None
        self.postTexGens = [safeGet(mat3.postTexGenArray, i) for i in self.postTexGenIndices]
        self.postTexGenIndices = None
        self.texMtxs = [safeGet(mat3.texMtxArray, i) for i in self.texMtxIndices]
        self.texMtxIndices = None
        self.postTexMtxs = [safeGet(mat3.postTexMtxArray, i) for i in self.postTexMtxIndices]
        self.postTexMtxIndices = None
        self.texNos = [safeGet(mat3.texNoArray, i) for i in self.texNoIndices]
        self.texNoIndices = None
        self.tevKColors = [safeGet(mat3.tevKColorArray, i) for i in self.tevKColorIndices]
        self.tevKColorIndices = None
        self.tevOrders = [safeGet(mat3.tevOrderArray, i) for i in self.tevOrderIndices]
        self.tevOrderIndices = None
        self.tevColors = [safeGet(mat3.tevColorArray, i) for i in self.tevColorIndices]
        self.tevColorIndices = None
        self.tevStages = [safeGet(mat3.tevStageArray, i) for i in self.tevStageIndices]
        self.tevStageIndices = None
        self.tevSwapModes = [safeGet(mat3.tevSwapModeArray, i) for i in self.tevSwapModeIndices]
        self.tevSwapModeIndices = None
        self.tevSwapModeTables = [safeGet(mat3.tevSwapModeTableArray, i) for i in self.tevSwapModeTableIndices]
        self.tevSwapModeTableIndices = None
        self.fog = safeGet(mat3.fogArray, self.fogIndex)
        self.fogIndex = None
        self.alphaComp = safeGet(mat3.alphaCompArray, self.alphaCompIndex)
        self.alphaCompIndex = None
        self.blend = safeGet(mat3.blendArray, self.blendIndex)
        self.blendIndex = None
        self.nbtScale = safeGet(mat3.nbtScaleArray, self.nbtScaleIndex)
        self.nbtScaleIndex = None

    def write(self, fout):
        super().write(fout)
        fout.write(pack('>2H', *self.matColorIndices))
        fout.write(pack('>4H', *self.colorChanIndices))
        fout.write(pack('>2H', *self.ambColorIndices))
        fout.write(pack('>8H', *self.lightInfoIndices))
        fout.write(pack('>8H', *self.texCoordIndices))
        fout.write(pack('>8H', *self.postTexGenIndices))
        fout.write(pack('>10H', *self.texMtxIndices))
        fout.write(pack('>20H', *self.postTexMtxIndices))
        fout.write(pack('>8H', *self.texNoIndices))
        fout.write(pack('>4H', *self.tevKColorIndices))
        fout.write(pack('>16B', *self.tevKColorSels))
        fout.write(pack('>16B', *self.tevKAlphaSels))
        fout.write(pack('>16H', *self.tevOrderIndices))
        fout.write(pack('>4H', *self.tevColorIndices))
        fout.write(pack('>16H', *self.tevStageIndices))
        fout.write(pack('>16H', *self.tevSwapModeIndices))
        fout.write(pack('>4H', *self.tevSwapModeTableIndices))
        fout.write(pack('>12H', *self.unknownIndices6))
        fout.write(pack('>HHHH', self.fogIndex, self.alphaCompIndex, self.blendIndex, self.nbtScaleIndex))
    
    def index(self, mat3):
        self.cullModeIndex = safeIndex(mat3.cullModeArray, self.cullMode.value)
        self.colorChanNumIndex = safeIndex(mat3.colorChanNumArray, self.colorChanNum)
        self.texGenNumIndex = safeIndex(mat3.texGenNumArray, self.texGenNum)
        self.tevStageNumIndex = safeIndex(mat3.tevStageNumArray, self.tevStageNum)
        self.zCompLocIndex = safeIndex(mat3.zCompLocArray, self.zCompLoc)
        self.zModeIndex = safeIndex(mat3.zModeArray, self.zMode)
        self.ditherIndex = safeIndex(mat3.ditherArray, self.dither)
        self.matColorIndices = [safeIndex(mat3.matColorArray, x) for x in self.matColors]
        self.colorChanIndices = [safeIndex(mat3.colorChanArray, x) for x in self.colorChans]
        self.ambColorIndices = [safeIndex(mat3.ambColorArray, x) for x in self.ambColors]
        self.lightInfoIndices = [safeIndex(mat3.lightInfoArray, x) for x in self.lightInfos]
        self.texCoordIndices = [safeIndex(mat3.texCoordArray, x) for x in self.texCoords]
        self.postTexGenIndices = [safeIndex(mat3.postTexGenArray, x) for x in self.postTexGens]
        self.texMtxIndices = [safeIndex(mat3.texMtxArray, x) for x in self.texMtxs]
        self.postTexMtxIndices = [safeIndex(mat3.postTexMtxArray, x) for x in self.postTexMtxs]
        self.texNoIndices = [safeIndex(mat3.texNoArray, x) for x in self.texNos]
        self.tevKColorIndices = [safeIndex(mat3.tevKColorArray, x) for x in self.tevKColors]
        self.tevOrderIndices = [safeIndex(mat3.tevOrderArray, x) for x in self.tevOrders]
        self.tevColorIndices = [safeIndex(mat3.tevColorArray, x) for x in self.tevColors]
        self.tevStageIndices = [safeIndex(mat3.tevStageArray, x) for x in self.tevStages]
        self.tevSwapModeIndices = [safeIndex(mat3.tevSwapModeArray, x) for x in self.tevSwapModes]
        self.tevSwapModeTableIndices = [safeIndex(mat3.tevSwapModeTableArray, x) for x in self.tevSwapModeTables]
        self.fogIndex = safeIndex(mat3.fogArray, self.fog)
        self.alphaCompIndex = safeIndex(mat3.alphaCompArray, self.alphaComp)
        self.blendIndex = safeIndex(mat3.blendArray, self.blend)
        self.nbtScaleIndex = safeIndex(mat3.nbtScaleArray, self.nbtScale)

    def debug(self):
        print(self.name)
        print("materialMode =", self.materialMode)
        print("cullMode =", self.cullMode)
        print("colorChanNum =", self.colorChanNum)
        print("texGenNum =", self.texGenNum)
        print("tevStageNum =", self.tevStageNum)
        print("zCompLoc =", self.zCompLoc)
        print("zMode =", self.zMode)
        print("dither =", self.dither)
        print("matColors =", self.matColors)
        print("colorChans =", self.colorChans)
        print("ambColors =", self.ambColors)
        print("lightInfos =", self.lightInfos)
        print("texCoords =", self.texCoords)
        print("postTexGens =", self.postTexGens)
        print("texMtxs =", self.texMtxs)
        print("postTexMtxs =", self.postTexMtxs)
        print("texNos =", self.texNos)
        print("tevKColors =", self.tevKColors)
        print("tevKColorSels =", self.tevKColorSels)
        print("tevKAlphaSels =", self.tevKAlphaSels)
        print("tevOrders =", self.tevOrders)
        print("tevColors =", self.tevColors)
        print("tevStages =", self.tevStages)
        print("tevSwapModes =", self.tevSwapModes)
        print("tevSwapModeTables =", self.tevSwapModeTables)
        print("fog =", self.fog)
        print("alphaComp =", self.alphaComp)
        print("blend =", self.blend)
        print("nbtScale =", self.nbtScale)
    
    def __hash__(self):
        return hash((
            self.name,
            self.materialMode,
            self.cullMode,
            self.colorChanNum,
            self.texGenNum,
            self.tevStageNum,
            self.zCompLoc,
            self.zMode,
            self.dither,
            tuple(self.matColors),
            tuple(self.colorChans),
            tuple(self.ambColors),
            tuple(self.lightInfos),
            tuple(self.texCoords),
            tuple(self.postTexGens),
            tuple(self.texMtxs),
            tuple(self.postTexMtxs),
            tuple(self.texNos),
            tuple(self.tevKColors),
            tuple(self.tevKColorSels),
            tuple(self.tevKAlphaSels),
            tuple(self.tevOrders),
            tuple(self.tevColors),
            tuple(self.tevStages),
            tuple(self.tevSwapModes),
            tuple(self.tevSwapModeTables),
            self.fog,
            self.alphaComp,
            self.blend,
            self.nbtScale
        ))

    def __eq__(self, other):
        return isinstance(other, __class__) and \
            self.name == other.name and \
            self.materialMode == other.materialMode and \
            self.cullMode == other.cullMode and \
            self.colorChanNum == other.colorChanNum and \
            self.texGenNum == other.texGenNum and \
            self.tevStageNum == other.tevStageNum and \
            self.zCompLoc == other.zCompLoc and \
            self.zMode == other.zMode and \
            self.dither == other.dither and \
            self.matColors == other.matColors and \
            self.colorChans == other.colorChans and \
            self.ambColors == other.ambColors and \
            self.lightInfos == other.lightInfos and \
            self.texCoords == other.texCoords and \
            self.postTexGens == other.postTexGens and \
            self.texMtxs == other.texMtxs and \
            self.postTexMtxs == other.postTexMtxs and \
            self.texNos == other.texNos and \
            self.tevKColors == other.tevKColors and \
            self.tevKColorSels == other.tevKColorSels and \
            self.tevKAlphaSels == other.tevKAlphaSels and \
            self.tevOrders == other.tevOrders and \
            self.tevColors == other.tevColors and \
            self.tevStages == other.tevStages and \
            self.tevSwapModes == other.tevSwapModes and \
            self.tevSwapModeTables == other.tevSwapModeTables and \
            self.fog == other.fog and \
            self.alphaComp == other.alphaComp and \
            self.blend == other.blend and \
            self.nbtScale == other.nbtScale

class MaterialBlock(Section):
    header = Struct('>H2x')
    fields = ['count']
    def read(self, fin, start, size):
        super().read(fin, start, size)
        offsets = unpack('>30L', fin.read(120))

        lengths = computeSectionLengths(offsets, size)

        fin.seek(start+offsets[0])
        self.materials = [None]*self.count
        for i in range(self.count):
            m = Material()
            m.read(fin)
            self.materials[i] = m
        
        fin.seek(start+offsets[1])
        self.remapTable = array('H')
        self.remapTable.fromfile(fin, self.count)
        if sys.byteorder == 'little': self.remapTable.byteswap()
        
        #self.materials = [None]*self.count
        #for i in range(self.count):
        #    self.materials[i] = orderedMaterials[self.remapTable[i]]
        
        self.materialNames = readStringTable(start+offsets[2], fin)
        if self.count != len(self.materialNames):
            warn("mat3: number of strings (%d) doesn't match number of elements (%d)"%len(self.materialNames), self.count)
        for m, n in zip(self.materials, self.materialNames):
            m.name = n
        self.count = None
        
        fin.seek(start+offsets[3])
        self.indirectArray = [IndInitData.try_make(fin) for i in range(lengths[3]//0x138)]

        fin.seek(start+offsets[4])
        self.cullModeArray = array('I')
        self.cullModeArray.fromfile(fin, lengths[4]//4)
        if sys.byteorder == 'little': self.cullModeArray.byteswap()
        self.cullModeArray = list(map(CullMode, self.cullModeArray))

        fin.seek(start+offsets[5])
        self.matColorArray = [unpack('>BBBB', fin.read(4)) for i in range(lengths[5]//4)]

        fin.seek(start+offsets[6])
        self.colorChanNumArray = array('B')
        self.colorChanNumArray.fromfile(fin, lengths[6])

        fin.seek(start+offsets[7])
        self.colorChanArray = [ColorChanInfo.try_make(fin) for i in range(lengths[7]//ColorChanInfo.header.size)]

        fin.seek(start+offsets[8])
        self.ambColorArray = [unpack('>BBBB', fin.read(4)) for i in range(lengths[8]//4)]

        fin.seek(start+offsets[9])
        self.lightInfoArray = [LightInfo.try_make(fin) for i in range(lengths[9]//LightInfo.header.size)]
        
        fin.seek(start+offsets[10])
        self.texGenNumArray = array('B')
        self.texGenNumArray.fromfile(fin, lengths[10])

        fin.seek(start+offsets[11])
        self.texCoordArray = [TexCoordInfo.try_make(fin) for i in range(lengths[11]//TexCoordInfo.header.size)]
        
        fin.seek(start+offsets[12])
        self.postTexGenArray = [TexCoordInfo.try_make(fin) for i in range(lengths[12]//TexCoordInfo.header.size)]
        
        fin.seek(start+offsets[13])
        self.texMtxArray = [TexMtxInfo.try_make(fin) for i in range(lengths[13]//100)]
        
        fin.seek(start+offsets[14])
        self.postTexMtxArray = [TexMtxInfo.try_make(fin) for i in range(lengths[14]//100)]
        
        fin.seek(start+offsets[15])
        self.texNoArray = array('H')
        self.texNoArray.fromfile(fin, lengths[15]//2)
        if sys.byteorder == 'little': self.texNoArray.byteswap()

        fin.seek(start+offsets[16])
        self.tevOrderArray = [TevOrderInfo.try_make(fin) for i in range(lengths[16]//TevOrderInfo.header.size)]
        
        fin.seek(start+offsets[17])
        self.tevColorArray = [unpack('>hhhh', fin.read(8)) for i in range(lengths[17]//8)]
        
        fin.seek(start+offsets[18])
        self.tevKColorArray = [unpack('>BBBB', fin.read(4)) for i in range(lengths[18]//4)]

        fin.seek(start+offsets[19])
        self.tevStageNumArray = array('B')
        self.tevStageNumArray.fromfile(fin, lengths[19])

        fin.seek(start+offsets[20])
        self.tevStageArray = [TevStageInfo.try_make(fin) for i in range(lengths[20]//TevStageInfo.header.size)]
        
        fin.seek(start+offsets[21])
        self.tevSwapModeArray = [TevSwapModeInfo.try_make(fin) for i in range(lengths[21]//TevSwapModeInfo.header.size)]
        
        fin.seek(start+offsets[22])
        self.tevSwapModeTableArray = [TevSwapModeTableInfo.try_make(fin) for i in range(lengths[22]//TevSwapModeTableInfo.header.size)]

        fin.seek(start+offsets[22])
        self.fogArray = [FogInfo.try_make(fin) for i in range(lengths[23]//44)]
        
        fin.seek(start+offsets[24])
        self.alphaCompArray = [AlphaCompInfo.try_make(fin) for i in range(lengths[24]//AlphaCompInfo.header.size)]

        fin.seek(start+offsets[25])
        self.blendArray = [BlendInfo.try_make(fin) for i in range(lengths[25]//BlendInfo.header.size)]

        fin.seek(start+offsets[26])
        self.zModeArray = [ZModeInfo.try_make(fin) for i in range(lengths[26]//ZModeInfo.header.size)]
        
        fin.seek(start+offsets[27])
        self.zCompLocArray = array('B')
        self.zCompLocArray.fromfile(fin, lengths[27])
        self.zCompLocArray = list(map(bool, self.zCompLocArray))

        fin.seek(start+offsets[28])
        self.ditherArray = array('B')
        self.ditherArray.fromfile(fin, lengths[28])
        self.ditherArray = list(map(bool, self.ditherArray))

        fin.seek(start+offsets[29])
        self.nbtScaleArray = [NBTScaleInfo.try_make(fin) for i in range(lengths[29]//NBTScaleInfo.header.size)]
        
        for m in self.materials:
            m.resolve(self)
    
    def write(self, fout):
        self.count = len(self.materials)
        offsets = [0]*30
        offsets[0] = 8+self.header.size+120
        offsets[1] = offsets[0]+len(self.materials)*0x14C
        #self.remapTable = array('H', range(len(self.materials)))
        offsets[2] = alignOffset(offsets[1]+len(self.remapTable)*self.remapTable.itemsize)
        self.materialNames = list({m.name for m in self.materials if m.name is not None})
        offsets[3] = alignOffset(offsets[2]+stringTableSize(self.materialNames))
        offsets[4] = offsets[3]+len(self.indirectArray)*0x138
        self.cullModeArray = array('I', {m.cullMode.value for m in self.materials if m.cullMode is not None})
        offsets[5] = offsets[4]+len(self.cullModeArray)*self.cullModeArray.itemsize
        self.matColorArray = list({x for m in self.materials for x in m.matColors if x is not None})
        offsets[6] = offsets[5]+len(self.matColorArray)*4
        self.colorChanNumArray = array('B', {m.colorChanNum for m in self.materials if m.colorChanNum is not None})
        offsets[7] = alignOffset(offsets[6]+len(self.colorChanNumArray)*self.colorChanNumArray.itemsize)
        self.colorChanArray = list({x for m in self.materials for x in m.colorChans if x is not None})
        offsets[8] = offsets[7]+len(self.colorChanArray)*ColorChanInfo.header.size
        self.ambColorArray = list({x for m in self.materials for x in m.ambColors if x is not None})
        offsets[9] = offsets[8]+len(self.ambColorArray)*4
        self.lightInfoArray = list({x for m in self.materials for x in m.lightInfos if x is not None})
        offsets[10] = offsets[9]+len(self.lightInfoArray)*LightInfo.header.size
        self.texGenNumArray = array('B', {m.texGenNum for m in self.materials if m.texGenNum is not None})
        offsets[11] = alignOffset(offsets[10]+len(self.texGenNumArray)*self.texGenNumArray.itemsize)
        self.texCoordArray = list({x for m in self.materials for x in m.texCoords if x is not None})
        offsets[12] = offsets[11]+len(self.texCoordArray)*TexCoordInfo.header.size
        self.postTexGenArray = list({x for m in self.materials for x in m.postTexGens if x is not None})
        offsets[13] = offsets[12]+len(self.postTexGenArray)*TexCoordInfo.header.size
        self.texMtxArray = list({x for m in self.materials for x in m.texMtxs if x is not None})
        offsets[14] = offsets[13]+len(self.texMtxArray)*0x64
        self.postTexMtxArray = list({x for m in self.materials for x in m.postTexMtxs if x is not None})
        offsets[15] = offsets[14]+len(self.postTexMtxArray)*0x64
        self.texNoArray = array('H', {x for m in self.materials for x in m.texNos if x is not None})
        offsets[16] = offsets[15]+len(self.texNoArray)*self.texNoArray.itemsize
        self.tevOrderArray = list({x for m in self.materials for x in m.tevOrders if x is not None})
        offsets[17] = offsets[16]+len(self.tevOrderArray)*TevOrderInfo.header.size
        self.tevColorArray = list({x for m in self.materials for x in m.tevColors if x is not None})
        offsets[18] = offsets[17]+len(self.tevColorArray)*8
        self.tevKColorArray = list({x for m in self.materials for x in m.tevKColors if x is not None})
        offsets[19] = offsets[18]+len(self.tevKColorArray)*4
        self.tevStageNumArray = array('B', {m.tevStageNum for m in self.materials if m.tevStageNum is not None})
        offsets[20] = alignOffset(offsets[19]+len(self.tevStageNumArray)*self.tevStageNumArray.itemsize)
        self.tevStageArray = list({x for m in self.materials for x in m.tevStages if x is not None})
        offsets[21] = offsets[20]+len(self.tevStageArray)*TevStageInfo.header.size
        self.tevSwapModeArray = list({x for m in self.materials for x in m.tevSwapModes if x is not None})
        offsets[22] = offsets[21]+len(self.tevSwapModeArray)*TevSwapModeInfo.header.size
        self.tevSwapModeTableArray = list({x for m in self.materials for x in m.tevSwapModeTables if x is not None})
        offsets[23] = offsets[22]+len(self.tevSwapModeTableArray)*TevSwapModeTableInfo.header.size
        self.fogArray = list({m.fog for m in self.materials if m.fog is not None})
        offsets[24] = offsets[23]+len(self.fogArray)*44
        self.alphaCompArray = list({m.alphaComp for m in self.materials if m.alphaComp is not None})
        offsets[25] = offsets[24]+len(self.alphaCompArray)*AlphaCompInfo.header.size
        self.blendArray = list({m.blend for m in self.materials if m.blend is not None})
        offsets[26] = offsets[25]+len(self.blendArray)*BlendInfo.header.size
        self.zModeArray = list({m.zMode for m in self.materials if m.zMode is not None})
        offsets[27] = offsets[26]+len(self.zModeArray)*ZModeInfo.header.size
        self.zCompLocArray = array('B', {m.zCompLoc for m in self.materials if m.zCompLoc is not None})
        offsets[28] = alignOffset(offsets[27]+len(self.zCompLocArray)*self.zCompLocArray.itemsize)
        self.ditherArray = array('B', {m.dither for m in self.materials if m.dither is not None})
        offsets[29] = alignOffset(offsets[28]+len(self.ditherArray)*self.ditherArray.itemsize)
        super().write(fout)
        fout.write(pack('>30L', *offsets))
        for m in self.materials:
            m.index(self)
            m.write(fout)
        swapArray(self.remapTable).tofile(fout)
        alignFile(fout)
        writeStringTable(fout, self.materialNames)
        alignFile(fout)
        for x in self.indirectArray: x.write(fout)
        swapArray(self.cullModeArray).tofile(fout)
        for x in self.matColorArray: fout.write(pack('BBBB', *x))
        self.colorChanNumArray.tofile(fout)
        alignFile(fout)
        for x in self.colorChanArray: x.write(fout)
        for x in self.ambColorArray: fout.write(pack('BBBB', *x))
        for x in self.lightInfoArray: x.write(fout)
        self.texGenNumArray.tofile(fout)
        alignFile(fout)
        for x in self.texCoordArray: x.write(fout)
        for x in self.postTexGenArray: x.write(fout)
        for x in self.texMtxArray: x.write(fout)
        for x in self.postTexMtxArray: x.write(fout)
        swapArray(self.texNoArray).tofile(fout)
        for x in self.tevOrderArray: x.write(fout)
        for x in self.tevColorArray: fout.write(pack('>HHHH', *x))
        for x in self.tevKColorArray: fout.write(pack('BBBB', *x))
        self.tevStageNumArray.tofile(fout)
        alignFile(fout)
        for x in self.tevStageArray: x.write(fout)
        for x in self.tevSwapModeArray: x.write(fout)
        for x in self.tevSwapModeTableArray: x.write(fout)
        for x in self.fogArray: x.write(fout)
        for x in self.alphaCompArray: x.write(fout)
        for x in self.blendArray: x.write(fout)
        for x in self.zModeArray: x.write(fout)
        self.zCompLocArray.tofile(fout)
        alignFile(fout)
        self.ditherArray.tofile(fout)
        alignFile(fout)
        for x in self.nbtScaleArray: x.write(fout)


class VtxAttr(Enum):
    PTNMTXIDX  =  0
    TEX0MTXIDX =  1
    TEX1MTXIDX =  2
    TEX2MTXIDX =  3
    TEX3MTXIDX =  4
    TEX4MTXIDX =  5
    TEX5MTXIDX =  6
    TEX6MTXIDX =  7
    TEX7MTXIDX =  8
    POS        =  9
    NRM        = 10
    CLR0       = 11
    CLR1       = 12
    TEX0       = 13
    TEX1       = 14
    TEX2       = 15
    TEX3       = 16
    TEX4       = 17
    TEX5       = 18
    TEX6       = 19
    TEX7       = 20
    NONE       = 0xFF

class VtxAttrIn(Enum):
    NONE = 0
    DIRECT = 1
    INDEX8 = 2
    INDEX16 = 3

class Index:
    sizeStructs = {VtxAttrIn.NONE: Struct(''), VtxAttrIn.DIRECT: Struct('b'), VtxAttrIn.INDEX8: Struct('B'), VtxAttrIn.INDEX16: Struct('>H')}
    def __init__(self):
        super().__init__()
        self.indices = [INVALID_INDEX]*21
    
    def read(self, fin, attribs):
        for attrib in attribs:
            #get value
            s = self.sizeStructs[attrib.dataType]
            val, = s.unpack(fin.read(s.size))
            
            if attrib.attrib.value < len(self.indices):
                self.indices[attrib.attrib.value] = val
            else:
                #assert(false && "shp1: got invalid attrib in packet. should never happen because "
                #"dumpBatch() should check this before calling dumpPacket()")

                pass #ignore unknown types, it's enough to warn() in dumpBatch
        self.indices = tuple(self.indices)
    
    def write(self, fout, attribs):
        for attrib in attribs:
            s = self.sizeStructs[attrib.dataType]
            fout.write(s.pack(self.indices[attrib.attrib.value]))
    
    def replace(self, fmt, value):
        other = Index()
        other.indices = self.indices[:fmt.value]+(value,)+self.indices[fmt.value+1:]
        return other
    
    @property
    def matrixIndex(self):
        return self.indices[VtxAttr.PTNMTXIDX.value]

    @property
    def posIndex(self):
        return self.indices[VtxAttr.POS.value]

    @property
    def normalIndex(self):
        return self.indices[VtxAttr.NRM.value]

    @property
    def colorIndex(self):
        return self.indices[VtxAttr.CLR0.value:VtxAttr.CLR1.value+1]

    @property
    def texCoordIndex(self):
        return self.indices[VtxAttr.TEX0.value:VtxAttr.TEX7.value+1]
    
    def __repr__(self):
        return ", ".join("{}: {}".format(VtxAttr(i).name, self.indices[i]) for i in range(21))

class PrimitiveType(Enum):
    NONE          = 0
    POINTS        = 0xB8 # Draws a series of points. Each vertex is a single point.
    LINES         = 0xA8 # Draws a series of unconnected line segments. Each pair of vertices makes a line.
    LINESTRIP     = 0xB0 # Draws a series of lines. Each vertex (besides the first) makes a line between it and the previous.
    TRIANGLES     = 0x90 # Draws a series of unconnected triangles. Three vertices make a single triangle.
    TRIANGLESTRIP = 0x98 # Draws a series of triangles. Each triangle (besides the first) shares a side with the previous triangle.
                         # Each vertex (besides the first two) completes a triangle.
    TRIANGLEFAN   = 0xA0 # Draws a single triangle fan. The first vertex is the "centerpoint". The second and third vertex complete
                         # the first triangle. Each subsequent vertex completes another triangle which shares a side with the previous
                         # triangle (except the first triangle) and has the centerpoint vertex as one of the vertices.
    QUADS         = 0x80 # Draws a series of unconnected quads. Every four vertices completes a quad. Internally, each quad is
                         # translated into a pair of triangles.

class Primitive(ReadableStruct):
    header = Struct('>BH')
    fields = [("type", PrimitiveType), "count"]
    def read(self, fin, attribs):
        super().read(fin)
        if self.type == PrimitiveType.NONE: return

        self.points = [Index() for jkl in range(self.count)]
        self.count = None

        for currPoint in self.points:
            currPoint.read(fin, attribs)
    
    def write(self, fout, attribs):
        self.count = len(self.points)
        super().write(fout)
        if self.type == PrimitiveType.NONE: return
        for currPoint in self.points:
            currPoint.write(fout, attribs)

    def __eq__(self, other):
        return super().__eq__(other) and \
            self.points == other.points

class ShapeDraw(ReadableStruct):
    header = Struct('>II')
    fields = ["displayListSize", "displayListStart"]
    def read(self, fin, base, attribs):
        super().read(fin)
        fin.seek(base+self.displayListStart)
        self.primitives = []
        while fin.tell() < base+self.displayListStart+self.displayListSize:
            currPrimitive = Primitive()
            currPrimitive.read(fin, attribs)
            if currPrimitive.type == PrimitiveType.NONE:
                break
            self.primitives.append(currPrimitive)
        self.displayListStart = self.displayListSize = None
    def __eq__(self, other):
        return super().__eq__(other) and \
            self.primitives == other.primitives

class ShapeMtx(ReadableStruct):
    header = Struct('>HHI')
    fields = ["useMtxIndex", "count", "firstIndex"]
    def read(self, fin, base):
        super().read(fin)
        if self.count > 10: raise ValueError("%d is more than 10 matrix slots"%self.count)
        fin.seek(base+2*self.firstIndex)
        self.firstIndex = None
        self.matrixTable = array('H')
        self.matrixTable.fromfile(fin, self.count)
        self.count = None
        if sys.byteorder == 'little': self.matrixTable.byteswap()
    def write(self, fout):
        self.count = len(self.matrixTable)
        super().write(fout)
    def __eq__(self, other):
        return super().__eq__(other) and \
            self.matrixTable == other.matrixTable

class VtxDesc(ReadableStruct):
    header = Struct('>II')
    fields = [("attrib", VtxAttr), ("dataType", VtxAttrIn)]

class Shape(ReadableStruct):
    header = Struct('>BxHHHH2xf')
    fields = ["shapeMtxType", "mtxGroupCount", "vtxDescIndex", "shapeMtxInitDataIndex",
        "shapeDrawInitDataIndex", "boundingSphereRadius"]
    def read(self, fin):
        super().read(fin)
        self.bbMin = bbStruct.unpack(fin.read(12))
        self.bbMax = bbStruct.unpack(fin.read(12))
    
    def write(self, fout):
        self.mtxGroupCount = len(self.matrixGroups)
        super().write(fout)
        fout.write(bbStruct.pack(*self.bbMin))
        fout.write(bbStruct.pack(*self.bbMax))

    def readVtxDesc(self, fin, vtxDescTableOffset):
        fin.seek(vtxDescTableOffset+self.vtxDescIndex)
        self.vtxDescIndex = None
        self.attribs = []
        a = VtxDesc(fin)
        while a.attrib != VtxAttr.NONE:
            self.attribs.append(a)
            a = VtxDesc(fin)

        self.hasMatrixIndices = self.hasPositions = self.hasNormals = False
        self.hasColors = [False]*2
        self.hasTexCoords = [False]*8
        for a in self.attribs:
            if a.attrib == VtxAttr.PTNMTXIDX:
                self.hasMatrixIndices = True
            elif a.attrib == VtxAttr.POS:
                self.hasPositions = True
            elif a.attrib == VtxAttr.NRM:
                self.hasNormals = True
            elif a.attrib in (VtxAttr.CLR0, VtxAttr.CLR1):
                self.hasColors[a.attrib.value - VtxAttr.CLR0.value] = True
            elif a.attrib.value >= VtxAttr.TEX0.value and a.attrib.value <= VtxAttr.TEX7.value:
                self.hasTexCoords[a.attrib.value - VtxAttr.TEX0.value] = True
            else:
                warn("shp1, readVtxDesc(): unknown vertex attribute %s" % a.attrib)

    def readMatrixGroups(self, fin, baseOffset, \
            drawInitDataOffset, displayListOffset, \
            mtxInitDataOffset, matrixTableOffset):
        
        matrices = []
        for i in range(self.mtxGroupCount):
            fin.seek(baseOffset+mtxInitDataOffset+(self.shapeMtxInitDataIndex + i)*ShapeMtx.header.size)
            matrixInfo = ShapeMtx()
            matrixInfo.read(fin, baseOffset+matrixTableOffset)
            matrices.append(matrixInfo)
        self.shapeMtxInitDataIndex = None
        
        draws = []
        for i in range(self.mtxGroupCount):
            fin.seek(baseOffset+drawInitDataOffset+(self.shapeDrawInitDataIndex + i)*ShapeDraw.header.size)
            drawInitData = ShapeDraw()
            drawInitData.read(fin, baseOffset+displayListOffset, self.attribs)
            draws.append(drawInitData)
        self.shapeDrawInitDataIndex = self.mtxGroupCount = None
        
        self.matrixGroups = list(map(tuple, zip(draws, matrices)))

    def __eq__(self, other):
        return super().__eq__(other) and \
            self.matrixGroups == other.matrixGroups and \
            self.attribs == other.attribs and \
            self.bbMin == other.bbMin and \
            self.bbMax == other.bbMax

class ShapeBlock(Section):
    header = Struct('>H2xIIIIIIII')
    fields = [
        'shapeCount', 'shapeInitDataOffset', 'remapTableOffset', 'shapeNameTableOffset',
        'vtxDescTableOffset', 'matrixTableOffset', 'displayListOffset',
        'mtxInitDataOffset', 'drawInitDataOffset'
    ]
    
    def read(self, fin, start, size):
        super().read(fin, start, size)
        self.batches = []
        fin.seek(start+self.shapeInitDataOffset)
        self.shapeInitDataOffset = None
        for i in range(self.shapeCount):
            shape = Shape()
            shape.read(fin)
            self.batches.append(shape)
        
        fin.seek(start+self.remapTableOffset)
        self.remapTableOffset = None
        self.remapTable = array('H')
        self.remapTable.fromfile(fin, self.shapeCount)
        self.shapeCount = None
        if sys.byteorder == 'little': self.remapTable.byteswap()
        
        if self.shapeNameTableOffset == 0:
            for shape in self.batches:
                shape.name = None
        else:
            shapeNames = readStringTable(start+self.shapeNameTableOffset, fin)
            for name, shape in zip(shapeNames, self.batches):
                shape.name = name
        self.shapeNameTableOffset = None
        
        for shape in self.batches:
            shape.readVtxDesc(fin, start+self.vtxDescTableOffset)
        self.vtxDescTableOffset = None
        
        for shape in self.batches:
            shape.readMatrixGroups(fin, start, self.drawInitDataOffset, self.displayListOffset, self.mtxInitDataOffset, self.matrixTableOffset)
        self.drawInitDataOffset = self.displayListOffset = self.mtxInitDataOffset = self.matrixTableOffset = None
    
    def write(self, fout):
        if len(self.batches) != len(self.remapTable): raise ValueError()
        self.shapeCount = len(self.batches)
        self.shapeInitDataOffset = self.header.size+8
        self.remapTableOffset = self.shapeInitDataOffset + (Shape.header.size+24)*len(self.batches)
        shapeNames = [shape.name for shape in self.batches if shape.name is not None]
        if len(shapeNames) == 0:
            self.shapeNameTableOffset = 0
            self.vtxDescTableOffset = alignOffset(self.remapTableOffset + self.remapTable.itemsize*len(self.remapTable), 8)
        else:
            self.shapeNameTableOffset = alignOffset(self.remapTableOffset + self.remapTable.itemsize*len(self.remapTable), 2)
            self.vtxDescTableOffset = alignOffset(self.shapeNameTableOffset + stringTableSize(shapeNames), 8)
        
        vtxDescSets = []
        dummyVtxDesc = VtxDesc()
        dummyVtxDesc.attrib = VtxAttr.NONE
        dummyVtxDesc.dataType = VtxAttrIn.NONE
        for shape in self.batches:
            idx = arrayStringSearch(vtxDescSets, shape.attribs)
            if idx is None:
                idx = len(vtxDescSets)
                vtxDescSets.extend(shape.attribs)
                vtxDescSets.append(dummyVtxDesc)
            shape.vtxDescIndex = idx*VtxDesc.header.size
        
        self.matrixTableOffset = self.vtxDescTableOffset + len(vtxDescSets)*VtxDesc.header.size
        
        matrixTableSets = array('H')
        for shape in self.batches:
            for shapeDraw, shapeMatrix in shape.matrixGroups:
                shapeMatrix.firstIndex = arrayStringSearch(matrixTableSets, shapeMatrix.matrixTable)
                if shapeMatrix.firstIndex is None:
                    shapeMatrix.firstIndex = len(matrixTableSets)
                    matrixTableSets.extend(shapeMatrix.matrixTable)
        
        self.displayListOffset = alignOffset(self.matrixTableOffset + len(matrixTableSets)*matrixTableSets.itemsize+8, 32)
        
        offset = 0
        for shape in self.batches:
            for shapeDraw, shapeMatrix in shape.matrixGroups:
                shapeDraw.displayListStart = offset
                shapeDraw.displayListSize = 0
                for primitive in shapeDraw.primitives:
                    shapeDraw.displayListSize += primitive.header.size
                    for currPoint in primitive.points:
                        for attrib in shape.attribs:
                            shapeDraw.displayListSize += Index.sizeStructs[attrib.dataType].size
                shapeDraw.displayListSize = alignOffset(shapeDraw.displayListSize, 32)
                offset += shapeDraw.displayListSize
        
        self.mtxInitDataOffset = self.displayListOffset + offset
        
        offset = 0
        for i, shape in enumerate(self.batches):
            shape.shapeMtxInitDataIndex = i
            offset += len(shape.matrixGroups)*ShapeMtx.header.size
        
        self.drawInitDataOffset = self.mtxInitDataOffset + offset
        
        shapeDrawSets = []
        for shape in self.batches:
            shapeDraws = [shapeDraw for shapeDraw, shapeMatrix in shape.matrixGroups]
            shape.shapeDrawInitDataIndex = arrayStringSearch(shapeDrawSets, shapeDraws)
            if shape.shapeDrawInitDataIndex is None:
                shape.shapeDrawInitDataIndex = len(shapeDrawSets)
                shapeDrawSets.extend(shapeDraws)
        
        super().write(fout)
        for shape in self.batches:
            shape.write(fout)
        swapArray(self.remapTable).tofile(fout)
        if len(shapeNames) != 0:
            alignFile(fout, 2)
            writeStringTable(fout, shapeNames)
        alignFile(fout, 8)
        for attrib in vtxDescSets:
            attrib.write(fout)
        swapArray(matrixTableSets).tofile(fout)
        alignFile(fout, 32, 8)
        for shape in self.batches:
            for shapeDraw, shapeMatrix in shape.matrixGroups:
                for primitive in shapeDraw.primitives:
                    primitive.write(fout, shape.attribs)
                alignFile(fout, 32, 8)
        for shape in self.batches:
            for shapeDraw, shapeMatrix in shape.matrixGroups:
                shapeMatrix.write(fout)
        for shapeDraw in shapeDrawSets:
            shapeDraw.write(fout)


class TextureBlock(Section):
    header = Struct('>H2xII')
    fields = ['texCount', 'textureHeaderOffset', 'stringTableOffset']
    def read(self, fin, start, length):
        super().read(fin, start, length)
        textureNames = readStringTable(start+self.stringTableOffset, fin)
        if len(textureNames) != self.texCount: raise ValueError()
        self.texCount = None
        fin.seek(start+self.textureHeaderOffset)
        self.textures = []
        for i, name in enumerate(textureNames):
            im = Image()
            im.name = name
            im.read(fin, start, self.textureHeaderOffset, i)
            self.textures.append(im)
        self.textureHeaderOffset = None
    def write(self, fout):
        self.texCount = len(self.textures)
        self.textureHeaderOffset = alignOffset(self.header.size+8, 16)
        
        datas = []
        for im in self.textures:
            b = swapArray(im.data).tobytes()
            if b not in datas:
                datas.append(b)
        dataOffsets = [sum(map(len, datas[:i])) for i in range(len(datas))]
        
        palettes = []
        for im in self.textures:
            b = swapArray(im.palette).tobytes()
            if b not in datas:
                palettes.append(b)
        paletteOffsets = [sum(map(len, palettes[:i])) for i in range(len(palettes))]
        
        for texNo, im in enumerate(self.textures):
            dataIdx = datas.index(swapArray(im.data).tobytes())
            im.dataOffset = dataOffsets[dataIdx] + paletteOffsets[-1] + 32*(len(self.textures) - texNo)
            palIdx = palettes.index(swapArray(im.palette).tobytes())
            im.paletteOffset = paletteOffsets[palIdx] + 32*(len(self.textures) - texNo)
        self.stringTableOffset = Image.header.size*len(self.textures) + self.textureHeaderOffset + max(dataOffsets) + len(datas[-1])
        
        super().write(fout)
        alignFile(fout, 16, 8)
        for im in self.textures:
            super(Image, im).write(fout)
        for data in datas:
            fout.write(data)
        for palette in palettes:
            fout.write(palette)
        writeStringTable(fout, [im.name for im in self.textures])


class VertexBlock(Section):
    header = Struct('>L')
    fields = ['arrayFormatOffset']
    def __init__(self):
        self.colors = [None for i in range(2)]
        self.texCoords = [None for i in range(8)]
    def read(self, fin, start, size):
        super().read(fin, start, size)
        offsets = unpack('>13L', fin.read(52))
        
        fin.seek(start+self.arrayFormatOffset)
        self.arrayFormatOffset = None
        self.formats = [None]*13
        for i in range(13):
            if offsets[i] != 0:
                self.formats[i] = ArrayFormat(fin)
        self.originalData = []
        self.asFloat = []
        for i in range(13):
            if offsets[i] == 0:
                self.originalData.append(None)
                self.asFloat.append(None)
                continue
            currFormat = self.formats[i]
            startOffset = offsets[i]
            length = size-startOffset
            for k in range(i+1, 13):
                if offsets[k] != 0:
                    length = offsets[k] - startOffset
                    break

            offset = start+offsets[i]
            fin.seek(offset)
            #convert array to float (so we have n + m cases, not n*m)
            data = array('f')
            if currFormat.arrayType not in (VtxAttr.CLR0, VtxAttr.CLR1) and currFormat.dataType == CompSize.S16:
                tmp = array('h')
                tmp.fromfile(fin, length//2)
                if sys.byteorder == 'little': tmp.byteswap()
                self.originalData.append(tmp)
                scale = .5**currFormat.decimalPoint
                data.extend([tmp[k]*scale for k in range(0, length//2)])
            elif currFormat.arrayType not in (VtxAttr.CLR0, VtxAttr.CLR1) and currFormat.dataType == CompSize.F32:
                data.fromfile(fin, length//4)
                if sys.byteorder == 'little': data.byteswap()
                self.originalData.append(data)
            elif currFormat.arrayType in (VtxAttr.CLR0, VtxAttr.CLR1) and currFormat.dataType == CompSize.RGBA8:
                tmp = array('B')
                tmp.fromfile(fin, length)
                self.originalData.append(tmp)
                data.extend([float(tmp[k]) for k in range(0, length)])
            else:
                warn("vtx1: unknown array data type %s"%dataType)
                self.originalData.append(None)
                self.asFloat.append(None)
                continue
            self.asFloat.append(data)

            #stuff floats into appropriate vertex array
            if currFormat.arrayType == VtxAttr.POS:
                if currFormat.componentCount == CompType.POS_XY:
                    self.positions = [None for i in range(len(data)/2)]
                    k = 0
                    for l in range(0, len(self.positions)):
                        self.positions[l] = Vector((data[k], data[k + 1], 0))
                        k += 2
                elif currFormat.componentCount == CompType.POS_XYZ:
                    self.positions = [None for i in range(len(data)//3)]
                    k = 0
                    for l in range(0, len(self.positions)):
                        self.positions[l] = Vector((data[k], data[k + 1], data[k + 2]))
                        k += 3
                else:
                    warn("vtx1: unsupported componentCount for positions array: %s"%currFormat.componentCount)
                    self.positions = []
            elif currFormat.arrayType == VtxAttr.NRM:
                if currFormat.componentCount == CompType.NRM_XYZ:
                    self.normals = [None for i in range(len(data)//3)]
                    k = 0
                    for l in range(0, len(self.normals)):
                        self.normals[l] = Vector((data[k], data[k + 1], data[k + 2]))
                        k += 3
                else:
                    warn("vtx1: unsupported componentCount for normals array: %s"%currFormat.componentCount)
            elif currFormat.arrayType in (VtxAttr.CLR0, VtxAttr.CLR1):
                index = currFormat.arrayType.value-0xb
                if currFormat.componentCount == CompType.CLR_RGB:
                    self.colors[index] = [None for i in range(len(data)//3)]
                    k = 0
                    for l in range(len(self.colors[index])):
                        self.colors[index][l] = (data[k], data[k + 1], data[k + 2])
                        k += 3
                elif currFormat.componentCount == CompType.CLR_RGBA:
                    self.colors[index] = [None for i in range(len(data)//4)]
                    k = 0
                    for l in range(len(self.colors[index])):
                        self.colors[index][l] = (data[k], data[k + 1], data[k + 2], data[k + 3])
                        k += 4
                else:
                    warn("vtx1: unsupported componentCount for colors array %d: %s"%
                        index, currFormat.componentCount)
            elif currFormat.arrayType in (VtxAttr.TEX0, VtxAttr.TEX1, VtxAttr.TEX2, VtxAttr.TEX3, VtxAttr.TEX4, VtxAttr.TEX5, VtxAttr.TEX6, VtxAttr.TEX7):
                index = currFormat.arrayType.value - 0xd
                if currFormat.componentCount == CompType.TEX_S:
                    self.texCoords[index] = [None for i in range(len(data))]
                    for l in range(0, len(self.texCoords[index])):
                        self.texCoords[index][l] = Vector((data[l], 0))
                elif currFormat.componentCount == CompType.TEX_ST:
                    self.texCoords[index] = [None for i in range(len(data)//2)]
                    k = 0
                    for l in range(0, len(self.texCoords[index])):
                        self.texCoords[index][l] = Vector((data[k], data[k + 1]))
                        k += 2
                else:
                    warn("vtx1: unsupported componentCount for texcoords array %d: %s"%index, currFormat.componentCount)

            else:
                warn("vtx1: unknown array type %s"%currFormat.arrayType)
    
    def write(self, fout):
        self.arrayFormatOffset = self.header.size + 8 + 13*4
        super().write(fout)
        offset = self.arrayFormatOffset + (len(self.formats)-self.formats.count(None)+1)*ArrayFormat.header.size
        for data in self.originalData:
            if data is None:
                fout.write(pack('>L', 0))
            else:
                fout.write(pack('>L', offset))
                offset += len(data)*data.itemsize
        
        for fmt in self.formats:
            if fmt is not None:
                fmt.write(fout)
        
        dummyFmt = ArrayFormat()
        dummyFmt.arrayType = VtxAttr.NONE
        dummyFmt.componentCount = CompType.POS_XYZ
        dummyFmt.dataType = CompSize.U8
        dummyFmt.decimalPoint = 0
        dummyFmt.write(fout)
        
        for data in self.originalData:
            if data is not None:
                swapArray(data).tofile(fout)


class CompType(Enum):
    POS_XY   = 0  # X,Y position
    POS_XYZ  = 1  # X,Y,Z position
    NRM_XYZ  = 0  # X,Y,Z normal
    NRM_NBT  = 1
    NRM_NBT3 = 2
    CLR_RGB  = 0  # RGB color
    CLR_RGBA = 1  # RGBA color
    TEX_S    = 0  # One texture dimension
    TEX_ST   = 1  # Two texture dimensions

class CompSize(Enum):
    U8     = 0 # Unsigned 8-bit integer
    S8     = 1 # Signed 8-bit integer
    U16    = 2 # Unsigned 16-bit integer
    S16    = 3 # Signed 16-bit integer
    F32    = 4 # 32-bit floating-point
    RGB565 = 0 # 16-bit RGB
    RGB8   = 1 # 24-bit RGB
    RGBX8  = 2 # 32-bit RGBX
    RGBA4  = 3 # 16-bit RGBA
    RGBA6  = 4 # 24-bit RGBA
    RGBA8  = 5 # 32-bit RGBA

class ArrayFormat(ReadableStruct):
    header = Struct('>IIIB3x')
    fields = [("arrayType", VtxAttr), ("componentCount", CompType), ("dataType", CompSize), "decimalPoint"]


def computeSectionLengths(offsets, sizeOfSection):
    lengths = [None]*30
    for i in range(30):
        length = 0
        if offsets[i] != 0:
            next = sizeOfSection
            for j in range(30):
                if offsets[j] > offsets[i] and offsets[j] < next:
                    next = offsets[j]
            length = next - offsets[i]
        lengths[i] = length
    return lengths

class MaterialDLBlock(Section):
    header = Struct('>H2xIIIIII')
    fields = ['count', 'offset1', 'offset2', 'offset3', 'offset4', 'offset5', 'stringTableOffset']
    def read(self, fin, start, size):
        super().read(fin, start, size)
        #fout = open("mld3.cdata", 'wb')
        #fin.seek(start)
        #fout.write(fin.read(size))
        #fout.close()
        fin.seek(start+self.offset1)
        self.offset1 = None
        self.things1 = [unpack('>II', fin.read(8)) for i in range(self.count)]
        for subOffset, thing in self.things1:
            fin.seek(start+self.offset1+subOffset)
        
        fin.seek(start+self.offset2)
        self.offset2 = None
        self.things2 = [fin.read(16) for i in range(self.count)]
        assert fin.tell() <= start+self.offset3
        
        fin.seek(start+self.offset3)
        self.offset3 = None
        self.things3 = [fin.read(8) for i in range(self.count)]
        assert fin.tell() <= start+self.offset4
        
        fin.seek(start+self.offset4)
        self.offset4 = None
        self.things4 = array('B')
        self.things4.fromfile(fin, self.count)
        assert fin.tell() <= start+self.offset5
        
        fin.seek(start+self.offset5)
        self.offset5 = None
        self.things5 = array('H')
        self.things5.fromfile(fin, self.count)
        self.count = None
        if sys.byteorder == 'little': self.things5.byteswap()
        assert fin.tell() <= start+self.stringTableOffset
        
        self.strings = readStringTable(start+self.stringTableOffset, fin)
        self.stringTableOffset = None
    
    def write(self, fout):
        self.count = len(self.things1)
        if self.count != len(self.things2) or self.count != len(self.things3) or self.count != len(self.things4) or self.count != len(self.things5): raise ValueError()
        self.offset1 = self.header.size+8
        self.offset2 = self.offset1 + len(self.things1)*8
        self.offset3 = self.offset2 + len(self.things2)*16
        self.offset4 = self.offset3 + len(self.things3)*8
        self.offset5 = self.offset4 + len(self.things4)*self.things4.itemsize
        self.stringTableOffset = self.offset5 + len(self.things5)*self.things5.itemsize
        super().write(fout)
        for x in self.things1: fout.write(pack('>II', *x))
        for x in self.things2: fout.write(x)
        for x in self.things3: fout.write(x)
        swapArray(self.things4).tofile(fout)
        swapArray(self.things5).tofile(fout)
        writeStringTable(fout, self.strings)

class BModel(BFile):
    sectionHandlers = {
        b'INF1': ModelInfoBlock,
        b'VTX1': VertexBlock,
        b'JNT1': JointBlock,
        b'SHP1': ShapeBlock,
        b'MAT3': MaterialBlock,
        b'TEX1': TextureBlock,
        b'EVP1': EnvelopBlock,
        b'DRW1': DrawBlock,
        b'MDL3': MaterialDLBlock
    }
    
    def readChunks(self, fin):
        if self.signature[:4] == b'bres': fin.seek(0xa0, 1)
        super().readChunks(fin)

        self.scenegraph = SceneGraph()
        if hasattr(self, "inf1"):
            buildSceneGraph(self.inf1, self.scenegraph)
        # remove dummy node at root
        if len(self.scenegraph.children) == 1:
            self.scenegraph = self.scenegraph.children[0]
        else:
            self.scenegraph.type = self.scenegraph.index = -1
            warn("buildSceneGraph(): Unexpected size %d"%len(self.scenegraph.children))

        buildMatrices(self.scenegraph, self)


def localMatrix(i, bm):
    s = Matrix()
    for j in range(3):
        s[j][j] = bm.jnt1.frames[i].scale[0]
    #TODO: I don't know which of these two return values are the right ones
    #(if it's the first, then what is scale used for at all?)

    #looks wrong in certain circumstances...
    return bm.jnt1.matrices[i] #this looks better with vf_064l.bdl (from zelda)
    return bm.jnt1.matrices[i]@s #this looks a bit better with mario's bottle_in animation

def updateMatrixTable(bmd, currPacket, matrixTable):
    for n, index in enumerate(currPacket.matrixTable):
        if index != 0xffff: #this means keep old entry
            if bmd.drw1.isWeighted[index]:
                #the following _does_ the right thing...it looks
                #ok for all files, but i don't understand why :-P
                #(and this code is slow as hell, so TODO: fix this)

                #NO idea if this is right this way...
                m = Matrix()
                m.zero()
                mmi = bmd.evp1.weightedIndices[bmd.drw1.data[index]]
                mmw = bmd.evp1.weightedWeights[bmd.drw1.data[index]]
                for mIdx, mWeight in zip(mmi, mmw):
                    sm1 = bmd.evp1.matrices[mIdx]
                    sm2 = localMatrix(mIdx, bmd)
                    m += mWeight*(sm2@sm1)
                m[3][3] = 1

                matrixTable[n] = (m, mmi, mmw)
            else:
                mmi = [bmd.drw1.data[index]]
                mmw = [1.0]
                matrixTable[n] = (bmd.jnt1.matrices[bmd.drw1.data[index]], mmi, mmw)

def frameMatrix(f):
    t = Matrix.Translation(f.translation).to_4x4()
    r = f.rotation.to_matrix().to_4x4()
    s = Matrix()
    s[0][0] = f.scale.x
    s[1][1] = f.scale.y
    s[2][2] = f.scale.z
    return t@r@s

def updateMatrix(f, effP):
    return effP@frameMatrix(f)

def printMatrix(m, indent=0):
    for i in range(4):
        print((' '*indent)+("%.1f %.1f %.1f %.1f"%m[i][:]))

def buildMatrices(sg, bmd, onDown=True, matIndex=0, p=None, indent=0):
    if p is None: p = Matrix.Identity(4)
    effP = p

    if sg.type == 2:
        raise Exception("Unexpected exit node!")
    elif sg.type == 0x10:
        # joint
        f = bmd.jnt1.frames[sg.index]
        bmd.jnt1.matrices[sg.index] = updateMatrix(f, effP)
        effP = bmd.jnt1.matrices[sg.index]

    for node in sg.children:
        buildMatrices(node, bmd, onDown, matIndex, effP, indent+1)

