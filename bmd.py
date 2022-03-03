import sys
from struct import unpack, pack, Struct, error as StructError
from warnings import warn
from array import array
import math
from enum import Enum, IntEnum
from common import *
from texture import *
from mathutils import *

bbStruct = Struct('>fff')

stringTableCountStruct = Struct('>H2x')
stringTableOffsetStruct = Struct('>HH')
def readstringtable(pos, f):
    dest = []
    oldPos = f.tell()

    f.seek(pos)

    count, = stringTableCountStruct.unpack(f.read(4))

    for i in range(count):
        unknown, stringOffset = stringTableOffsetStruct.unpack(f.read(4))
        s = getString(pos + stringOffset, f)
        dest.append(s)

    f.seek(oldPos)
    return dest



class Drw1(Section):
    def read(self, fin, start, size):
        count, offsetToIsWeighted, offsetToData = unpack('>H2xLL', fin.read(12))
        fin.seek(start+offsetToIsWeighted)
        bisWeighted = array('B')
        bisWeighted.fromfile(fin, count)
        if not all([x in (0,1) for x in bisWeighted]):
            raise Exception("unexpected value in isWeighted array: %s", bisWeighted)
        self.isWeighted = list([x == 1 for x in bisWeighted])

        fin.seek(start+offsetToData)
        self.data = array('H')
        self.data.fromfile(fin, count)
        if sys.byteorder == 'little': self.data.byteswap()



class Evp1(Section):
    header = Struct('>HH4I')
    def read(self, fin, start, size):
        count, pad, boneCountOffset, weightedIndicesOffset, boneWeightsTableOffset, matrixTableOffset = self.header.unpack(fin.read(20))

        fin.seek(start+boneCountOffset)
        counts = array('B')
        counts.fromfile(fin, count)

        fin.seek(start+weightedIndicesOffset)
        self.weightedIndices = [array('H') for i in range(count)]
        for i in range(count):
            self.weightedIndices[i].fromfile(fin, counts[i])
            if sys.byteorder == 'little': self.weightedIndices[i].byteswap()
        numMatrices = max(list(map(max, self.weightedIndices)))+1 if count > 0 else 0

        fin.seek(start+boneWeightsTableOffset)
        self.weightedWeights = [array('f') for i in range(count)]
        for i in range(count):
            self.weightedWeights[i].fromfile(fin, counts[i])
            if sys.byteorder == 'little': self.weightedWeights[i].byteswap()

        fin.seek(start+matrixTableOffset)
        self.matrices = []
        for i in range(numMatrices):
            m = Matrix()
            for j in range(3):
                m[j] = unpack('>ffff', fin.read(16))
            self.matrices.append(m)



class Node(ReadableStruct):
    header = Struct('>HH')
    fields = ["type", "index"]

class Inf1(Section):
    header = Struct('>H2xIII')
    def read(self, fin, start, size):
        loadFlags, mtxGroupCount, self.vertexCount, offsetToEntries = self.header.unpack(fin.read(16))
        fin.seek(start+offsetToEntries)
        self.scenegraph = []
        n = Node()
        n.read(fin)
        while n.type != 0:
            self.scenegraph.append(n)
            n = Node()
            n.read(fin)

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
        sg.type = sg.index = -1
        warn("buildSceneGraph(): Unexpected size %d"%len(sg.children))

    return 0



class Jnt1(Section):
    header = Struct('>H2xIII')
    def read(self, fin, start, size):
        count, jntEntryOffset, unknownOffset, stringTableOffset = self.header.unpack(fin.read(16))
        boneNames = readstringtable(start+stringTableOffset, fin)
        if len(boneNames) != count: warn("number of strings doesn't match number of joints")

        fin.seek(start+jntEntryOffset)
        self.matrices = [Matrix() for i in range(count)]
        for m in self.matrices:
            m.zero()
        self.isMatrixValid = [False]*count
        self.frames = []
        for i in range(count):
            f = Jnt1Entry()
            f.read(fin)
            f.name = boneNames[i]
            self.frames.append(f)

class Jnt1Entry(Readable):
    header = Struct('>HBxfffhhh2xffff')
    def __init__(self, name=None, scale=None, rotation=None, translation=None):
        if name is not None: self.name = name
        if scale is not None: self.scale = scale
        if rotation is not None: self.rotation = rotation
        if translation is not None: self.translation = translation
    
    def read(self, fin):
        unknown, unknown3, \
            sx, sy, sz, \
            rx, ry, rz, \
            tx, ty, tz, \
            unknown2 = self.header.unpack(fin.read(40))
        self.scale = Vector((sx, sy, sz))
        self.rotation = Euler((rx/32768*math.pi, ry/32768*math.pi, rz/32768*math.pi))
        self.translation = Vector((tx, ty, tz))
        self.bbMin = bbStruct.unpack(fin.read(12))
        self.bbMax = bbStruct.unpack(fin.read(12))
    
    def __repr__(self):
        return "{}({}, {}, {}, {})".format(__class__.__name__, repr(self.name), self.scale, self.rotation, self.translation)


class ColorSrc(Enum):
    REG = 0
    VTX = 1

class DiffuseFunction(Enum):
    NONE = 0
    SIGN = 1
    CLAMP = 2

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

def safeGet(arr, idx):
    if idx >= 0 and idx < len(arr):
        return arr[idx]
    else:
        return None

class Material(ReadableStruct):
    header = Struct('>BBBBBxBx')
    fields = ["flag", "cullModeIndex", "lightChanCountIndex", "texGenCountIndex",
        "tevCountIndex", "zModeIndex"]
    def read(self, fin):
        super().read(fin)
        # 0x08
        self.matColorIndices = unpack('>2H', fin.read(4))
        # 0x0C
        self.lightChanIndices = unpack('>4H', fin.read(8))

        # 0x14
        self.ambientColorIndices = unpack('>2H', fin.read(4))
        # 0x18
        self.lightIndices = unpack('>8H', fin.read(16))

        # 0x28
        self.texGenIndices = unpack('>8H', fin.read(16))
        # 0x38
        self.postTexGenIndices = unpack('>8H', fin.read(16))
        # 0x48
        self.texMtxIndices = unpack('>10H', fin.read(20))
        # 0x5C
        self.postTexMtxIndices = unpack('>20H', fin.read(40))
        # 0x84
        self.texStageIndices = unpack('>8H', fin.read(16))
        # 0x94
        self.constColorIndices = unpack('>4H', fin.read(8))
        # 0x9C
        self.constColorSels = list(map(TevKColorSel, unpack('>16B', fin.read(16))))
        # 0xAC
        self.constAlphaSels = unpack('>16B', fin.read(16))
        # 0xBC
        self.tevOrderIndices = unpack('>16H', fin.read(32))
        # 0xDC
        self.colorIndices = unpack('>4H', fin.read(8))
        # 0xE4
        self.tevStageIndices = unpack('>16H', fin.read(32))
        # 0x104
        self.tevSwapModeIndices = unpack('>16H', fin.read(32))
        # 0x124
        self.tevSwapModeTableIndices = unpack('>4H', fin.read(8))
        # 0x12C
        self.unknownIndices6 = unpack('>12H', fin.read(24))
        # 0x144
        self.fogIndex, self.alphaCompIndex, self.blendIndex = unpack('>HHH2x', fin.read(8))
    
    def resolve(self, mat3):
        self.cullMode = safeGet(mat3.cullModeArray, self.cullModeIndex)
        self.lightChanCount = safeGet(mat3.lightChanCountArray, self.lightChanCountIndex)
        self.texGenCount = safeGet(mat3.texGenCountArray, self.texGenCountIndex)
        self.tevStageCount = safeGet(mat3.tevCountArray, self.tevCountIndex)
        self.zMode = safeGet(mat3.zModeArray, self.zModeIndex)
        self.matColors = [safeGet(mat3.matColorArray, i) for i in self.matColorIndices]
        self.lightChanInfos = [safeGet(mat3.lightChanInfoArray, i) for i in self.lightChanIndices]
        self.ambientColors = [safeGet(mat3.ambientColorArray, i) for i in self.ambientColorIndices]
        self.texGenInfos = [safeGet(mat3.texGenInfoArray, i) for i in self.texGenIndices]
        #self.postTexGenInfos = [safeGet(mat3.postTexGenInfoArray, i) for i in self.postTexGenIndices]
        self.texMtxInfos = [safeGet(mat3.texMtxInfoArray, i) for i in self.texMtxIndices]
        #self.postTexMtxInfos = [safeGet(mat3.postTexMtxInfoArray, i) for i in self.postTexMtxIndices]
        self.textureIndexes = [safeGet(mat3.textureIndexArray, i) for i in self.texStageIndices]
        self.constColors = [safeGet(mat3.constColorArray, i) for i in self.constColorIndices]
        self.tevOrderInfos = [safeGet(mat3.tevOrderInfoArray, i) for i in self.tevOrderIndices]
        self.colors = [safeGet(mat3.colorArray, i) for i in self.colorIndices]
        self.tevStageInfos = [safeGet(mat3.tevStageInfoArray, i) for i in self.tevStageIndices]
        self.tevSwapModeInfos = [safeGet(mat3.tevSwapModeInfoArray, i) for i in self.tevSwapModeIndices]
        self.tevSwapModeTables = [safeGet(mat3.tevSwapModeTableArray, i) for i in self.tevSwapModeTableIndices]
        #self.fogInfo = safeGet(mat3.blendInfoArray, self.fogIndex)
        self.alphaComp = safeGet(mat3.alphaCompArray, self.alphaCompIndex)
        self.blendInfo = safeGet(mat3.blendInfoArray, self.blendIndex)
        
    def debug(self):
        print(self.name)
        print("flag =", self.flag)
        print("cullMode =", self.cullMode)
        print("lightChanCount =", self.lightChanCount)
        print("texGenCount =", self.texGenCount)
        print("zMode =", self.zMode)
        print("matColors =", self.matColors)
        print("lightChanInfos =", self.lightChanInfos)
        print("ambientColors =", self.ambientColors)
        print("texGenInfos =", self.texGenInfos)
        #print("postTexGenInfos =", self.postTexGenInfos)
        print("texMtxInfos =", self.texMtxInfos)
        #print("postTexMtxInfos =", self.postTexMtxInfos)
        print("textureIndexes =", self.textureIndexes)
        print("constColors =", self.constColors)
        print("tevOrderInfos =", self.tevOrderInfos)
        print("colors =", self.colors)
        print("tevStageInfos =", self.tevStageInfos)
        print("tevSwapModeInfos =", self.tevSwapModeInfos)
        print("tevSwapModeTables =", self.tevSwapModeTables)
        print("alphaComp =", self.alphaComp)
        print("blendInfo =", self.blendInfo)

class Mat3(Section):
    header = Struct('>H2x')
    def read(self, fin, start, size):
        count, = self.header.unpack(fin.read(4))
        offsets = unpack('>30L', fin.read(120))

        lengths = computeSectionLengths(offsets, size)

        fin.seek(start+offsets[0])
        orderedMaterials = [None]*count
        for i in range(count):
            m = Material()
            m.read(fin)
            orderedMaterials[i] = m
        
        fin.seek(start+offsets[1])
        self.indexToMatIndex = array('H') # remapTable
        self.indexToMatIndex.fromfile(fin, count)
        if sys.byteorder == 'little': self.indexToMatIndex.byteswap()
        
        self.materials = [None]*count
        for i in range(count):
            self.materials[i] = orderedMaterials[self.indexToMatIndex[i]]
        
        self.materialNames = readstringtable(start+offsets[2], fin)
        if count != len(self.materialNames):
            warn("mat3: number of strings (%d) doesn't match number of elements (%d)"%len(self.materialNames), count)
        for m, n in zip(self.materials, self.materialNames):
            m.name = n

        # 3 (IndirectTexturing)

        fin.seek(start+offsets[4])
        self.cullModeArray = array('I')
        self.cullModeArray.fromfile(fin, lengths[4]//4)
        if sys.byteorder == 'little': self.cullModeArray.byteswap()

        fin.seek(start+offsets[5])
        self.matColorArray = [unpack('>BBBB', fin.read(4)) for i in range(lengths[5]//4)]

        fin.seek(start+offsets[6])
        self.lightChanCountArray = array('B')
        self.lightChanCountArray.fromfile(fin, lengths[6])

        fin.seek(start+offsets[7])
        self.lightChanInfoArray = [ColorChanInfo.try_make(fin) for i in range(lengths[7]//ColorChanInfo.header.size)]

        fin.seek(start+offsets[8])
        self.ambientColorArray = [unpack('>BBBB', fin.read(4)) for i in range(lengths[8]//4)] 

        # 9 (LightInfo)
        
        fin.seek(start+offsets[10])
        self.texGenCountArray = array('B')
        self.texGenCountArray.fromfile(fin, lengths[10])

        fin.seek(start+offsets[11])
        self.texGenInfoArray = [TexGenInfo.try_make(fin) for i in range(lengths[11]//TexGenInfo.header.size)]

        # 12 (TexCoord2Info)
        # postTexGen
        
        fin.seek(start + offsets[13])
        self.texMtxInfoArray = [TexMtxInfo.try_make(fin) for i in range(lengths[13]//100)]
        
        # 14 (TexMtxInfo2)
        # postTexMtx
        
        fin.seek(start+offsets[15])
        self.textureIndexArray = array('H')
        self.textureIndexArray.fromfile(fin, lengths[15]//2)
        if sys.byteorder == 'little': self.textureIndexArray.byteswap()

        fin.seek(start+offsets[16])
        self.tevOrderInfoArray = [TevOrderInfo.try_make(fin) for i in range(lengths[16]//TevOrderInfo.header.size)]
        
        fin.seek(start+offsets[17])
        self.colorArray = [unpack('>hhhh', fin.read(8)) for i in range(lengths[17]//8)] 
        
        fin.seek(start+offsets[18])
        self.constColorArray = [unpack('>BBBB', fin.read(4)) for i in range(lengths[18]//4)] 

        fin.seek(start+offsets[19])
        self.tevCountArray = array('B')
        self.tevCountArray.fromfile(fin, lengths[19])

        fin.seek(start+offsets[20])
        self.tevStageInfoArray = [TevStageInfo.try_make(fin) for i in range(lengths[20]//TevStageInfo.header.size)]
        
        fin.seek(start+offsets[21])
        self.tevSwapModeInfoArray = [TevSwapMode.try_make(fin) for i in range(lengths[21]//TevSwapMode.header.size)]
        
        fin.seek(start+offsets[22])
        self.tevSwapModeTableArray = [TevSwapModeTable.try_make(fin) for i in range(lengths[22]//TevSwapModeTable.header.size)]

        # 23 (FogInfo)
        
        fin.seek(start+offsets[24])
        self.alphaCompArray = [AlphaCompare.try_make(fin) for i in range(lengths[24]//AlphaCompare.header.size)]

        fin.seek(start+offsets[25])
        self.blendInfoArray = [BlendInfo.try_make(fin) for i in range(lengths[25]//BlendInfo.header.size)]

        fin.seek(start+offsets[26])
        self.zModeArray = [ZMode.try_make(fin) for i in range(lengths[26]//ZMode.header.size)]
        
        # 27 (MaterialData6)
        # 28 (MaterialData7)
        # 29 (NBTScaleInfo)
        
        #for m in self.materials:
        #    m.resolve(self)
        #    m.debug()


class Index(Readable):
    sizeStructs = {1: Struct('>B'), 3: Struct('>H')}
    def __init__(self):
        super().__init__()
        self.matrixIndex = -1
        self.posIndex = -1
        self.normalIndex = -1
        self.colorIndex = [-1]*2
        self.texCoordIndex = [-1]*8
        self.attrIndices = []
    def read(self, fin, attribs):
        for attrib in attribs:
            #get value
            s = self.sizeStructs[attrib.dataType]
            val, = s.unpack(fin.read(s.size))
            self.attrIndices.append(val)

            #set appropriate index
            if attrib.attrib == 0:
                self.matrixIndex = val

            elif attrib.attrib == 9:
                self.posIndex = val

            elif attrib.attrib == 0xa:
                self.normalIndex = val

            elif attrib.attrib in (0xb,  0xc):
                self.colorIndex[attrib.attrib - 0xb] = val

            elif attrib.attrib in (0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14):
                self.texCoordIndex[attrib.attrib - 0xd] = val

            else:
                #assert(false && "shp1: got invalid attrib in packet. should never happen because "
                #"dumpBatch() should check this before calling dumpPacket()")

                pass #ignore unknown types, it's enough to warn() in dumpBatch

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

        for j in range(self.count):
            currPoint = self.points[j]
            currPoint.read(fin, attribs)

class Packet(Readable):
    locationHeader = Struct('>II')
    matrixInfoHeader = Struct('>2xHI')
    def read(self, fin, baseOffset, offsetData, offsetToMatrixData, \
            firstMatrixData, packetIndex, offsetToMatrixTable, attribs):
        locationSize, locationOffset = self.locationHeader.unpack(fin.read(8))

        fin.seek(baseOffset+offsetData+locationOffset)
        self.primitives = dumpPacketPrimitives(attribs, locationSize, fin)

        fin.seek(baseOffset+offsetToMatrixData+(firstMatrixData+packetIndex)*8)
        count, firstIndex = self.matrixInfoHeader.unpack(fin.read(8))
        if count > 10: raise Exception()

        fin.seek(baseOffset+offsetToMatrixTable+2*firstIndex)
        self.matrixTable = array('H')
        self.matrixTable.fromfile(fin, count)
        if sys.byteorder == 'little': self.matrixTable.byteswap()

class BatchAttrib(ReadableStruct):
    header = Struct('>II')
    fields = ["attrib", "dataType"]

class Batch(ReadableStruct):
    header = Struct('>BxHHHH6x')
    fields = ["matrixType", "packetCount", "offsetToAttribs", "firstMatrixData", "firstPacketLocation"]
    def read(self, fin):
        super().read(fin)
        self.bbMin = bbStruct.unpack(fin.read(12))
        self.bbMax = bbStruct.unpack(fin.read(12))

    def getBatchAttribs(self, fin, baseOffset, offsetToBatchAttribs):
        old = fin.tell()
        fin.seek(baseOffset+offsetToBatchAttribs+self.offsetToAttribs)
        self.attribs = []
        a = BatchAttrib(fin)
        while a.attrib != 0xff:
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
            if a.dataType != 1 and a.dataType != 3:
                warn("shp1, dumpBatch(): unknown attrib data type %d, skipping batch" % attribs[i].dataType)
                return
            if a.attrib == 0:
                self.hasMatrixIndices = True
            elif a.attrib == 9:
                self.hasPositions = True
            elif a.attrib == 0xa:
                self.hasNormals = True
            elif a.attrib in (0xb, 0xc):
                self.hasColors[a.attrib - 0xb] = True
            elif a.attrib >= 0xd and a.attrib <= 0x14:
                self.hasTexCoords[a.attrib - 0xd] = True
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
    header = Struct('>H2xII4xIIIII')
    def read(self, fin, start, size):
        # header
        batchCount, offsetToBatches, offsetUnknown, offsetToBatchAttribs, \
            offsetToMatrixTable, offsetData, offsetToMatrixData, \
            offsetToPacketLocations = self.header.unpack(fin.read(36))
        # batches
        self.batches = []
        fin.seek(start+offsetToBatches)
        for i in range(batchCount):
            batch = Batch()
            batch.read(fin)
            nextBatch = fin.tell()
            batch.getBatchAttribs(fin, start, offsetToBatchAttribs)
            batch.dumpBatch(fin, start, offsetToBatchAttribs, offsetToPacketLocations, offsetData, offsetToMatrixData, i, offsetToMatrixTable)
            self.batches.append(batch)
            fin.seek(nextBatch)

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



class Image(ReadableStruct):
    header = Struct('>BxHHBBxBHI4xBB2xBx2xI')
    fields = [
        ("format", TF),
        "width",
        "height",
        "wrapS",
        "wrapT",
        ("paletteFormat", TL),
        "paletteNumEntries",
        "paletteOffset",
        "minFilter",
        "magFilter",
        "mipmapCount",
        "dataOffset"
    ]
    def read(self, fin, start=None, textureHeaderOffset=None, texIndex=None):
        super().read(fin)
        self.mipmapCount = max(self.mipmapCount, 1)
        if self.format in (TF.C4, TF.C8, TF.C14X2):
            self.hasAlpha = self.paletteFormat in (TL.IA8, TL.RGB5A3)
        else:
            self.hasAlpha = self.format in (TF.IA4, TF.IA8, TF.RGB5A3, TF.RGBA8)
        if start is not None:
            nextHeader = fin.tell()
            
            self.fullDataOffset = start+textureHeaderOffset+self.dataOffset+0x20*texIndex
            fin.seek(self.fullDataOffset)
            self.data = readTextureData(fin, self.format, self.width, self.height, self.mipmapCount)
            
            if self.format in (TF.C4, TF.C8, TF.C14X2):
                self.fullPaletteOffset = start+textureHeaderOffset+self.paletteOffset+0x20*texIndex
                fin.seek(self.fullPaletteOffset)
                self.palette = readPaletteData(fin, self.paletteFormat, self.paletteNumEntries)
            else:
                self.palette = None
            
            fin.seek(nextHeader)
    
    def getDataName(self, bmd):
        s = bmd.name+"@"+hex(self.fullDataOffset)
        if self.format in (TF.C4, TF.C8, TF.C14X2):
            s += "p"+hex(self.fullPaletteOffset)
        return s
    
class Tex1(Section):
    headerCount = Struct('>H2x')
    headerOffsets = Struct('>II')
    def read(self, fin, start, length):
        texCount, = self.headerCount.unpack(fin.read(self.headerCount.size))
        if texCount == 0:
            # JPA style
            name = fin.read(0x14)
            if name[0] == 0:
                textureNames = []
                textureHeaderOffset = 0
            else:
                textureNames = [name.decode('shift-jis').rstrip("\0")]
                textureHeaderOffset = 0x20
        else:
            textureHeaderOffset, stringTableOffset = self.headerOffsets.unpack(fin.read(self.headerOffsets.size))
            try: textureNames = readstringtable(start+stringTableOffset, fin)
            except StructError: textureNames = []
        fin.seek(start+textureHeaderOffset)
        self.textures = []
        for i, name in enumerate(textureNames):
            im = Image()
            im.name = name
            im.read(fin, start, textureHeaderOffset, i)
            self.textures.append(im)


class Vtx1(Section):
    def __init__(self):
        self.colors = [None for i in range(2)]
        self.texCoords = [None for i in range(8)]
    def read(self, fin, start, size):
        arrayFormatOffset, = unpack('>L', fin.read(4))
        offsets = unpack('>13L', fin.read(52))
        numArrays = 0
        for i in range(13):
            if offsets[i] != 0: numArrays += 1
        fin.seek(start+arrayFormatOffset)
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

class Mdl3Dummy(Section):
    def read(self, fin, start, size):
        #fout = open("mld3.cdata", 'wb')
        #fout.write(fin.read(size-8))
        #fout.close()
        pass

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
        b'MDL3': Mdl3Dummy
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

