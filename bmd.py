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
        f.write(stringTableEntryStruct.pack(calcKeyCode(s), offset))
    f.write(table)

class Drw1(Section):
    header = Struct('>H2xLL')
    fields = [
        'count',
        'offsetToIsWeighted',
        'offsetToData'
    ]
    def read(self, fin, start, size):
        super().read(fin, start, size)
        fin.seek(start+self.offsetToIsWeighted)
        bisWeighted = array('B')
        bisWeighted.fromfile(fin, self.count)
        if not all([x in (0,1) for x in bisWeighted]):
            raise Exception("unexpected value in isWeighted array: %s", bisWeighted)
        self.isWeighted = list([x == 1 for x in bisWeighted])

        fin.seek(start+self.offsetToData)
        self.data = array('H')
        self.data.fromfile(fin, self.count)
        if sys.byteorder == 'little': self.data.byteswap()
        
    def write(self, fout):
        self.count = len(self.data)
        self.offsetToIsWeighted = self.header.size+8
        self.offsetToData = self.offsetToIsWeighted+self.count
        super().write(fout)
        bisWeighted = array('B', self.isWeighted)
        bisWeighted.tofile(fout)
        swapArray(self.data).tofile(fout)


class Evp1(Section):
    header = Struct('>HH4I')
    fields = [
        'count',
        'pad',
        'boneCountOffset',
        'weightedIndicesOffset',
        'boneWeightsTableOffset',
        'matrixTableOffset'
    ]
    def read(self, fin, start, size):
        super().read(fin, start, size)
        fin.seek(start+self.boneCountOffset)
        counts = array('B')
        counts.fromfile(fin, self.count)

        fin.seek(start+self.weightedIndicesOffset)
        self.weightedIndices = [array('H') for i in range(self.count)]
        for i in range(self.count):
            self.weightedIndices[i].fromfile(fin, counts[i])
            if sys.byteorder == 'little': self.weightedIndices[i].byteswap()
        numMatrices = max(list(map(max, self.weightedIndices)))+1 if self.count > 0 else 0

        fin.seek(start+self.boneWeightsTableOffset)
        self.weightedWeights = [array('f') for i in range(self.count)]
        for i in range(self.count):
            self.weightedWeights[i].fromfile(fin, counts[i])
            if sys.byteorder == 'little': self.weightedWeights[i].byteswap()

        fin.seek(start+self.matrixTableOffset)
        self.matrices = []
        for i in range(numMatrices):
            m = Matrix()
            for j in range(3):
                m[j] = unpack('>ffff', fin.read(16))
            self.matrices.append(m)
    
    def write(self, fout):
        self.count = len(self.weightedIndices)
        self.boneCountOffset = self.header.size+8
        self.weightedIndicesOffset = self.boneCountOffset+self.count
        self.boneWeightsTableOffset = self.weightedIndicesOffset+(2*sum(map(len, self.weightedIndices)))
        self.matrixTableOffset = self.boneWeightsTableOffset+(4*sum(map(len, self.weightedWeights)))
        super().write(fout)
        counts = array('B', map(len, self.weightedIndices))
        counts.tofile(fout)
        for indices in self.weightedIndices:
            swapArray(indices).tofile(fout)
        for weights in self.weightedWeights:
            swapArray(weights).tofile(fout)
        for m in self.matrices:
            for row in m[:3]:
                fout.write(pack('>ffff', *row))


class Node(ReadableStruct):
    header = Struct('>HH')
    fields = ["type", "index"]

class Inf1(Section):
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
        self.scenegraph = []
        n = Node()
        n.read(fin)
        while n.type != 0:
            self.scenegraph.append(n)
            n = Node()
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



class Jnt1(Section):
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
        self.remapTable = array('H')
        self.remapTable.fromfile(fin, self.count)
        if sys.byteorder == 'little': self.remapTable.byteswap()
    
    def write(self, fout):
        self.count = len(self.frames)
        self.jntEntryOffset = self.header.size+8
        self.remapTableOffs = self.jntEntryOffset+(self.count*(Jnt1Entry.header.size+bbStruct.size+bbStruct.size))
        self.stringTableOffset = self.remapTableOffs+len(self.remapTable)*self.remapTable.itemsize
        super().write(fout)
        for f in self.frames:
            f.write(fout)
        swapArray(self.remapTable).tofile(fout)
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
        self.rotation = Euler((rx/0x8000*math.pi, ry/0x8000*math.pi, rz/0x8000*math.pi))
        self.translation = Vector((tx, ty, tz))
        self.bbMin = bbStruct.unpack(fin.read(bbStruct.size))
        self.bbMax = bbStruct.unpack(fin.read(bbStruct.size))
    
    def write(self, fout):
        fout.write(self.header.pack(
            self.flags, self.calcFlags,
            self.scale.x, self.scale.y, self.scale.z,
            int(self.rotation.x*0x8000/math.pi),
            int(self.rotation.y*0x8000/math.pi),
            int(self.rotation.z*0x8000/math.pi),
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

class IndTexMtx(ReadableStruct):
    def read(self, fin):
        p = unpack('>6f', fin.read(0x18))
        exponent, = unpack('Bxxx', fin.read(4))
        scale = 2**exponent
        self.m = [
            p[0]*scale, p[1]*scale, p[2]*scale, scale,
            p[3]*scale, p[4]*scale, p[5]*scale, 0.0
        ]
    def write(self, fout):
        p = [
            self.m[0], self.m[1], self.m[2],
            self.m[4], self.m[5], self.m[6]
        ]
        fout.write(pack('>6f', *p))
        fout.write(b'\0\0\0\0')

class IndTexCoordScale(ReadableStruct):
    header = Struct('BBxx')
    fields = ["scaleS", "scaleT"]

class IndTevStage(ReadableStruct):
    header = Struct('BBBBBBBBBxxx')
    fields = ["indTexId", "format", "bias", "mtxId", "wrapS", "wrapT", "addPrev", ("unmodifiedTexCoordLod", bool), "a"]

class IndirectInfo(ReadableStruct):
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
    IDENTITY = 60
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

class TexGenInfo(ReadableStruct):
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

class AlphaCompare(ReadableStruct):
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

class ZMode(ReadableStruct):
    header = Struct('>BBBx')
    fields = [
        ("enable", bool),
        ("func", CompareType),
        ("write", bool)
    ]

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

class TevSwapMode(ReadableStruct):
    header = Struct('>BB2x')
    fields = ["rasSel", "texSel"]

class TevSwapModeTable(ReadableStruct):
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
        self.lightIndices = unpack('>8H', fin.read(16))
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
        self.tevKAlphaSels = unpack('>16B', fin.read(16))
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
        self.colorChanNum = safeGet(mat3.colorChanNumArray, self.colorChanNumIndex)
        self.texGenNum = safeGet(mat3.texGenNumArray, self.texGenNumIndex)
        self.tevStageNum = safeGet(mat3.tevStageNumArray, self.tevStageNumIndex)
        self.zCompLoc = safeGet(mat3.zCompLocArray, self.zCompLocIndex)
        self.zMode = safeGet(mat3.zModeArray, self.zModeIndex)
        self.dither = safeGet(mat3.ditherArray, self.ditherIndex)
        self.matColors = [safeGet(mat3.matColorArray, i) for i in self.matColorIndices]
        self.colorChans = [safeGet(mat3.colorChanArray, i) for i in self.colorChanIndices]
        self.ambColors = [safeGet(mat3.ambColorArray, i) for i in self.ambColorIndices]
        self.lights = [safeGet(mat3.lightInfoArray, i) for i in self.lightIndices]
        self.texCoords = [safeGet(mat3.texCoordArray, i) for i in self.texCoordIndices]
        #self.postTexGens = [safeGet(mat3.postTexGenArray, i) for i in self.postTexGenIndices]
        self.texMtxs = [safeGet(mat3.texMtxArray, i) for i in self.texMtxIndices]
        #self.postTexMtxs = [safeGet(mat3.postTexMtxArray, i) for i in self.postTexMtxIndices]
        self.texNos = [safeGet(mat3.texNoArray, i) for i in self.texNoIndices]
        self.tevKColors = [safeGet(mat3.tevKColorArray, i) for i in self.tevKColorIndices]
        self.tevOrders = [safeGet(mat3.tevOrderArray, i) for i in self.tevOrderIndices]
        self.tevColors = [safeGet(mat3.tevColorArray, i) for i in self.tevColorIndices]
        self.tevStages = [safeGet(mat3.tevStageArray, i) for i in self.tevStageIndices]
        self.tevSwapModes = [safeGet(mat3.tevSwapModeArray, i) for i in self.tevSwapModeIndices]
        self.tevSwapModeTables = [safeGet(mat3.tevSwapModeTableArray, i) for i in self.tevSwapModeTableIndices]
        self.fog = safeGet(mat3.fogArray, self.fogIndex)
        self.alphaComp = safeGet(mat3.alphaCompArray, self.alphaCompIndex)
        self.blend = safeGet(mat3.blendArray, self.blendIndex)
        #self.nbtScale = safeGet(mat3.nbtScaleArray, self.nbtScaleIndex)

    def write(self, fout):
        super().write(fout)
        fout.write('>2H', *self.matColorIndices)
        fout.write('>4H', *self.colorChanIndices)
        fout.write('>2H', *self.ambColorIndices)
        fout.write('>8H', *self.lightIndices)
        fout.write('>8H', *self.texCoordIndices)
        fout.write('>8H', *self.postTexGenIndices)
        fout.write('>10H', *self.texMtxIndices)
        fout.write('>20H', *self.postTexMtxIndices)
        fout.write('>8H', *self.texNoIndices)
        fout.write('>4H', *self.tevKColorIndices)
        fout.write('>16B', *self.tevKColorSels)
        fout.write('>16B', *self.tevKAlphaSels)
        fout.write('>16H', *self.tevOrderIndices)
        fout.write('>4H', *self.tevColorIndices)
        fout.write('>16H', *self.tevStageIndices)
        fout.write('>16H', *self.tevSwapModeIndices)
        fout.write('>4H', *self.tevSwapModeTableIndices)
        fout.write('>12H', *self.unknownIndices6)
        fout.write('>HHHH', self.fogIndex, self.alphaCompIndex, self.blendIndex, self.nbtScaleIndex)
    
    def index(self, mat3):
        self.cullModeIndex = safeIndex(mat3.cullModeArray, self.cullMode)
        self.colorChanNumIndex = safeIndex(mat3.colorChanNumArray, self.colorChanNum)
        self.texGenNumIndex = safeIndex(mat3.texGenNumArray, self.texGenNum)
        self.tevStageNumIndex = safeIndex(mat3.tevStageNumArray, self.tevStageNum)
        self.zCompLocIndex = safeIndex(mat3.zCompLocArray, self.zCompLoc)
        self.zModeIndex = safeIndex(mat3.zModeArray, self.zMode)
        self.ditherIndex = safeIndex(mat3.ditherArray, self.dither)
        self.matColorIndices = [safeIndex(mat3.matColorArray, x) for x in self.matColors]
        self.colorChanIndices = [safeIndex(mat3.colorChanArray, x) for x in self.colorChans]
        self.ambColorIndices = [safeIndex(mat3.ambColorArray, x) for x in self.ambColors]
        self.lightIndices = [safeIndex(mat3.lightInfoArray, x) for x in self.lights]
        self.texCoordIndices = [safeIndex(mat3.texCoordArray, x) for x in self.texCoords]
        #self.postTexGenIndices = [safeIndex(mat3.postTexGenArray, x) for x in self.postTexGens]
        self.texMtxIndices = [safeIndex(mat3.texMtxArray, x) for x in self.texMtxs]
        #self.postTexMtxIndices = [safeIndex(mat3.postTexMtxArray, x) for x in self.postTexMtxs]
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
        #self.nbtScaleIndex = safeIndex(mat3.nbtScaleArray, self.nbtScale)

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
        print("lights =", self.lights)
        print("texCoords =", self.texCoords)
        #print("postTexGens =", self.postTexGens)
        print("texMtxs =", self.texMtxs)
        #print("postTexMtxs =", self.postTexMtxs)
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
        #print("nbtScale =", self.nbtScale)
    
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
            tuple(self.lights),
            tuple(self.texCoords),
            #tuple(self.postTexGens),
            tuple(self.texMtxs),
            #tuple(self.postTexMtxs),
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
            #self.nbtScale
        ))

class Mat3(Section):
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
        
        fin.seek(start+offsets[3])
        self.indirectArray = [IndirectInfo.try_make(fin) for i in range(lengths[3]//0x138)]

        fin.seek(start+offsets[4])
        self.cullModeArray = array('I')
        self.cullModeArray.fromfile(fin, lengths[4]//4)
        if sys.byteorder == 'little': self.cullModeArray.byteswap()

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
        self.texCoordArray = [TexGenInfo.try_make(fin) for i in range(lengths[11]//TexGenInfo.header.size)]

        # 12 (postTexGen)
        
        fin.seek(start + offsets[13])
        self.texMtxArray = [TexMtxInfo.try_make(fin) for i in range(lengths[13]//100)]
        
        # 14 (postTexMtx)
        
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
        self.tevSwapModeArray = [TevSwapMode.try_make(fin) for i in range(lengths[21]//TevSwapMode.header.size)]
        
        fin.seek(start+offsets[22])
        self.tevSwapModeTableArray = [TevSwapModeTable.try_make(fin) for i in range(lengths[22]//TevSwapModeTable.header.size)]

        fin.seek(start+offsets[22])
        self.fogArray = [FogInfo.try_make(fin) for i in range(lengths[23]//44)]
        
        fin.seek(start+offsets[24])
        self.alphaCompArray = [AlphaCompare.try_make(fin) for i in range(lengths[24]//AlphaCompare.header.size)]

        fin.seek(start+offsets[25])
        self.blendArray = [BlendInfo.try_make(fin) for i in range(lengths[25]//BlendInfo.header.size)]

        fin.seek(start+offsets[26])
        self.zModeArray = [ZMode.try_make(fin) for i in range(lengths[26]//ZMode.header.size)]
        
        fin.seek(start+offsets[27])
        self.zCompLocArray = array('B')
        self.zCompLocArray.fromfile(fin, lengths[27])

        fin.seek(start+offsets[28])
        self.ditherArray = array('B')
        self.ditherArray.fromfile(fin, lengths[28])

        # 29 (nbtScale)
        
        for m in self.materials:
            m.resolve(self)
        #    m.debug()
    
    def write(self, fout):
        self.count = len(self.materials)
        offsets = [0]*30
        offsets[0] = self.header.size+8
        offsets[1] = offsets[0]+len(self.materials)*0x14C
        #self.remapTable = array('H', range(len(self.materials)))
        offsets[2] = offsets[1]+len(self.remapTable)*self.remapTable.itemsize
        self.materialNames = list({m.name for m in self.materials})
        offsets[3] = offsets[2]+stringTableSize(self.materialNames)
        offsets[4] = offsets[3]
        self.cullModeArray = array('I', {m.cullMode for m in self.materials})
        offsets[5] = offsets[4]+len(self.cullModeArray)*self.cullModeArray.itemsize
        self.matColorArray = list({m.matColor for m in self.materials})
        offsets[6] = offsets[5]+len(self.matColorArray)*4
        self.colorChanNumArray = array('B', {m.colorChanNum for m in self.materials})
        offsets[7] = offsets[6]+len(self.colorChanNumArray)*self.colorChanNumArray.itemsize
        self.colorChanArray = list({m.colorChan for m in self.materials})
        offsets[8] = offsets[7]+len(self.colorChanArray)*ColorChanInfo.header.size
        self.ambColorArray = list({m.ambColor for m in self.materials})
        offsets[9] = offsets[8]+len(self.ambColorArray)*4
        self.lightInfoArray = list({m.lightInfo for m in self.materials})
        offsets[10] = offsets[9]+len(self.lightInfoArray)*LightInfo.header.size
        self.texGenNumArray = array('B', {m.texGenNum for m in self.materials})
        offsets[11] = offsets[10]+len(self.texGenNumArray)*self.texGenNumArray.itemsize
        self.texCoordArray = list({m.texCoord for m in self.materials})
        offsets[12] = offsets[11]+len(self.texCoordArray)*TexGenInfo.header.size
        offsets[13] = offsets[12]
        self.texMtxArray = list({m.texMtx for m in self.materials})
        offsets[14] = offsets[13]+len(self.texMtxArray)*0x64
        offsets[15] = offsets[14]
        self.texNoArray = array('H', {m.texNo for m in self.materials})
        offsets[16] = offsets[15]+len(self.texNoArray)*self.texNoArray.itemsize
        self.tevOrderArray = list({m.tevOrder for m in self.materials})
        offsets[17] = offsets[16]+len(self.tevOrderArray)*TevOrderInfo.header.size
        self.tevColorArray = list({m.tevColor for m in self.materials})
        offsets[18] = offsets[17]+len(self.tevColorArray)*8
        self.tevKColorArray = list({m.tevKColor for m in self.materials})
        offsets[19] = offsets[18]+len(self.tevKColorArray)*4
        self.tevStageNumArray = array('B', {m.tevStageNum for m in self.materials})
        offsets[20] = offsets[19]+len(self.tevStageNumArray)*self.tevStageNumArray.itemsize
        self.tevStageArray = list({m.tevStage for m in self.materials})
        offsets[21] = offsets[20]+len(self.tevStageArray)*TevStageInfo.header.size
        self.tevSwapModeArray = list({m.tevSwapMode for m in self.materials})
        offsets[22] = offsets[21]+len(self.tevSwapModeArray)*TevSwapMode.header.size
        self.tevSwapModeTableArray = list({m.tevSwapModeTable for m in self.materials})
        offsets[23] = offsets[22]+len(self.tevSwapModeTableArray)*TevSwapModeTable.header.size
        self.fogArray = list({m.fog for m in self.materials})
        offsets[24] = offsets[23]+len(self.fogArray)*44
        self.alphaCompArray = list({m.alphaComp for m in self.materials})
        offsets[25] = offsets[24]+len(self.alphaCompArray)*AlphaCompare.header.size
        self.blendArray = list({m.blend for m in self.materials})
        offsets[26] = offsets[25]+len(self.blendArray)*BlendInfo.header.size
        self.zModeArray = list({m.zMode for m in self.materials})
        offsets[27] = offsets[26]+len(self.zModeArray)*ZMode.header.size
        self.zCompLocArray = array('B', {m.zCompLoc for m in self.materials})
        offsets[28] = offsets[27]+len(self.zCompLocArray)*self.zCompLocArray.itemsize
        self.ditherArray = array('B', {m.dither for m in self.materials})
        offsets[29] = offsets[28]+len(self.ditherArray)*self.ditherArray.itemsize
        super().write(fout)
        fout.write('>30L', *offsets)
        for m in self.materials:
            m.index(self)
            m.write(fout)
        swapArray(self.remapTable).tofile(fout)
        writeStringTable(fout, self.materialNames)
        swapArray(self.cullModeArray).tofile(fout)
        for x in self.matColorArray: fout.write(pack('BBBB', *x))
        self.colorChanNumArray.tofile(fout)
        for x in self.colorChanArray: x.write(fout)
        for x in self.ambColorArray: fout.write(pack('BBBB', *x))
        for x in self.lightInfoArray: x.write(fout)
        self.texGenNumArray.tofile(fout)
        for x in self.texCoordArray: x.write(fout)
        for x in self.texMtxArray: x.write(fout)
        swapArray(self.texNoArray).tofile(fout)
        for x in self.tevOrderArray: x.write(fout)
        for x in self.tevColorArray: fout.write(pack('>HHHH', *x))
        for x in self.tevKColorArray: fout.write(pack('BBBB', *x))
        self.tevStageNumArray.tofile(fout)
        for x in self.tevStageArray: x.write(fout)
        for x in self.tevSwapModeArray: x.write(fout)
        for x in self.tevSwapModeTableArray: x.write(fout)
        for x in self.fogArray: x.write(fout)
        for x in self.alphaCompArray: x.write(fout)
        for x in self.blendArray: x.write(fout)
        for x in self.zModeArray: x.write(fout)
        self.zCompLocArray.tofile(fout)
        self.ditherArray.tofile(fout)


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

class Index:
    sizeStructs = {CompSize.S8: Struct('>B'), CompSize.S16: Struct('>H')}
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

        for currPoint in self.points:
            currPoint.read(fin, attribs)
    
    def write(self, fout, attribs):
        super().write(fout)
        if self.type == PrimitiveType.NONE: return
        for currPoint in self.points:
            currPoint.write(fout, attribs)

class Packet:
    locationHeader = Struct('>II')
    matrixInfoHeader = Struct('>HHI')
    def read(self, fin, baseOffset, offsetData, offsetToMatrixData, \
            firstMatrixData, packetIndex, offsetToMatrixTable, attribs):
        locationSize, locationOffset = self.locationHeader.unpack(fin.read(8))

        fin.seek(baseOffset+offsetData+locationOffset)
        self.primitives = dumpPacketPrimitives(attribs, locationSize, fin)

        fin.seek(baseOffset+offsetToMatrixData+(firstMatrixData+packetIndex)*8)
        useMtxIndex, count, firstIndex = self.matrixInfoHeader.unpack(fin.read(8))
        if count > 10: raise ValueError("%d is more than 10 matrix slots"%count)

        fin.seek(baseOffset+offsetToMatrixTable+2*firstIndex)
        self.matrixTable = array('H')
        self.matrixTable.fromfile(fin, count)
        if sys.byteorder == 'little': self.matrixTable.byteswap()
    
    #def writeMatrixData(self, fout):
    
    #def writeLocation(self, fout):

class BatchAttrib(ReadableStruct):
    header = Struct('>II')
    fields = [("attrib", VtxAttr), ("dataType", CompSize)]

class Batch(ReadableStruct):
    header = Struct('>BxHHHH2xf')
    fields = ["displayFlags", "packetCount", "offsetToAttribs", "firstMatrixData",
        "firstPacketLocation", "boundingSphereRadius"]
    def read(self, fin):
        super().read(fin)
        self.bbMin = bbStruct.unpack(fin.read(12))
        self.bbMax = bbStruct.unpack(fin.read(12))
    
    def write(self, fout):
        super().write(fout)
        fout.write(bbStruct.pack(*self.bbMin))
        fout.write(bbStruct.pack(*self.bbMax))

    def getBatchAttribs(self, fin, baseOffset, offsetToBatchAttribs):
        old = fin.tell()
        fin.seek(baseOffset+offsetToBatchAttribs+self.offsetToAttribs)
        self.attribs = []
        a = BatchAttrib(fin)
        while a.attrib != VtxAttr.NONE:
            self.attribs.append(a)
            a = BatchAttrib(fin)
        fin.seek(old)

    def dumpBatch(self, fin, baseOffset, offsetToBatchAttribs, \
            offsetToPacketLocations, \
            offsetData, offsetToMatrixData, \
            batchIndex, offsetToMatrixTable):
        self.hasMatrixIndices = self.hasPositions = self.hasNormals = False
        self.hasColors = [False]*2
        self.hasTexCoords = [False]*8
        for a in self.attribs:
            if a.dataType != CompSize.S8 and a.dataType != CompSize.S16:
                warn("shp1, dumpBatch(): unknown attrib data type %s, skipping batch" % a.dataType)
                return
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
                warn("shp1, dumpBatch(): unknown attrib %d in batch, it might not display correctly" % a.attrib)

        self.packets = []
        for j in range(self.packetCount):
            fin.seek(baseOffset+offsetToPacketLocations+(self.firstPacketLocation + j)*8)
            p = Packet()
            p.read(fin, baseOffset, offsetData, offsetToMatrixData, \
                self.firstMatrixData, j, offsetToMatrixTable, self.attribs)
            self.packets.append(p)

class Shp1(Section):
    header = Struct('>H2xIIIIIIII')
    fields = [
        'batchCount', 'offsetToBatches', 'offsetToRemapTable', 'offsetToNameTable',
        'offsetToBatchAttribs', 'offsetToMatrixTable', 'offsetData',
        'offsetToMatrixData', 'offsetToPacketLocations'
    ]
    
    def read(self, fin, start, size):
        super().read(fin, start, size)
        self.batches = []
        fin.seek(start+self.offsetToBatches)
        for i in range(self.batchCount):
            batch = Batch()
            batch.read(fin)
            nextBatch = fin.tell()
            batch.getBatchAttribs(fin, start, self.offsetToBatchAttribs)
            batch.dumpBatch(fin, start, self.offsetToBatchAttribs, self.offsetToPacketLocations, self.offsetData, self.offsetToMatrixData, i, self.offsetToMatrixTable)
            self.batches.append(batch)
            fin.seek(nextBatch)
    
    def write(self, fout):
        self.batchCount = len(self.batches)
        self.offsetToBatches = self.header.size+8
        self.offsetToBatchAttribs = self.offsetToBatches + (Batch.header.size+24)*len(self.batches)
        offset = 0
        for batch in self.batches:
            batch.offsetToAttribs = offset
            offset += (len(batch.attribs)+1)*BatchAttrib.header.size
        self.offsetToMatrixTable = offset
        for batch in self.batches:
            for packet in batch.packets:
                offset += packet.matrixTable.itemsize*len(packet.matrixTable)
        self.offsetData = offset
        for batch in self.batches:
            for packet in batch.packets:
                for primitive in packet.primitives:
                    offset += primitive.header.size
                    for currPoint in primitive.points:
                        for attrib in batch.attribs:
                            offset += Index.sizeStructs[attrib.dataType].size
        self.offsetToMatrixData = offset
        for batch in self.batches:
            offset += len(batch.packets)*Packet.matrixInfoHeader.size
        self.offsetToPacketLocations = offset
        super().write(fout)
        for batch in self.batches:
            batch.write(fout)
        for batch in self.batches:
            for attrib in batch.attribs:
                attrib.write(fout)
        for batch in self.batches:
            for packet in batch.packets:
                packet.matrixTable.tofile(fout)
        for batch in self.batches:
            for packet in batch.packets:
                for primitive in packet.primitives:
                    offset += primitive.header.size
                    for currPoint in primitive.points:
                        currPoint.write(fout, batch.attribs)
        for batch in self.batches:
            for packet in batch.packets:
                packet.writeMatrixData(fout)
        for batch in self.batches:
            for packet in batch.packets:
                packet.writeLocation(fout)

def dumpPacketPrimitives(attribs, dataSize, fin):
    primitives = []
    start = fin.tell()
    while fin.tell()-start < dataSize:
        currPrimitive = Primitive()
        currPrimitive.read(fin, attribs)
        if currPrimitive.type == PrimitiveType.NONE:
            break
        primitives.append(currPrimitive)

    return primitives


class Tex1(Section):
    header = Struct('>H2xII')
    fields = ['texCount', 'textureHeaderOffset', 'stringTableOffset']
    def read(self, fin, start, length):
        super().read(fin, start, length)
        try: textureNames = readStringTable(start+self.stringTableOffset, fin)
        except StructError: textureNames = []
        fin.seek(start+self.textureHeaderOffset)
        self.textures = []
        for i, name in enumerate(textureNames):
            im = Image()
            im.name = name
            im.read(fin, start, self.textureHeaderOffset, i)
            self.textures.append(im)
    def write(self, fout):
        self.texCount = len(self.textures)
        self.textureHeaderOffset = self.header.size+8
        self.stringTableOffset = self.textureHeaderOffset+Image.header.size*len(self.textures)
        super().write(fout)
        for im in self.textures:
            im.writeHeader(fout)
        writeStringTable(fout, [im.name for im in self.textures])


class Vtx1(Section):
    header = Struct('>L')
    fields = ['arrayFormatOffset']
    def __init__(self):
        self.colors = [None for i in range(2)]
        self.texCoords = [None for i in range(8)]
    def read(self, fin, start, size):
        super().read(fin, start, size)
        offsets = unpack('>13L', fin.read(52))
        numArrays = 0
        for i in range(13):
            if offsets[i] != 0: numArrays += 1
        fin.seek(start+self.arrayFormatOffset)
        self.formats = [ArrayFormat(fin) for i in range(numArrays)]
        self.originalData = []
        self.asFloat = []
        j = 0
        for i in range(13):
            if offsets[i] == 0: continue
            currFormat = self.formats[j]
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
                j += 1
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

            j += 1


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

class ArrayFormat(ReadableStruct):
    header = Struct('>IIIBBH')
    fields = [("arrayType", VtxAttr), ("componentCount", CompType), ("dataType", CompSize), "decimalPoint", "unknown3", "unknown4"]


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

class Mdl3(Section):
    header = Struct('>H2xIIIIII')
    fields = ['count', 'offset1', 'offset2', 'offset3', 'offset4', 'offset5', 'stringTableOffset']
    def read(self, fin, start, size):
        super().read(fin, start, size)
        #fout = open("mld3.cdata", 'wb')
        #fin.seek(start)
        #fout.write(fin.read(size))
        #fout.close()
        fin.seek(start+self.offset1)
        self.things1 = [unpack('>II', fin.read(8)) for i in range(self.count)]
        for subOffset, thing in self.things1:
            fin.seek(start+self.offset1+subOffset)
        
        fin.seek(start+self.offset2)
        self.things2 = [fin.read(16) for i in range(self.count)]
        assert fin.tell() <= start+self.offset3
        
        fin.seek(start+self.offset3)
        self.things3 = [fin.read(8) for i in range(self.count)]
        assert fin.tell() <= start+self.offset4
        
        fin.seek(start+self.offset4)
        self.things4 = array('B')
        self.things4.fromfile(fin, self.count)
        assert fin.tell() <= start+self.offset5
        
        fin.seek(start+self.offset5)
        self.things5 = array('H')
        self.things5.fromfile(fin, self.count)
        if sys.byteorder == 'little': self.things5.byteswap()
        assert fin.tell() <= start+self.stringTableOffset
        
        self.strings = readStringTable(start+self.stringTableOffset, fin)

class BModel(BFile):
    sectionHandlers = {
        b'INF1': Inf1,
        b'VTX1': Vtx1,
        b'JNT1': Jnt1,
        b'SHP1': Shp1,
        b'MAT3': Mat3,
        b'TEX1': Tex1,
        b'EVP1': Evp1,
        b'DRW1': Drw1,
        b'MDL3': Mdl3
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

