import sys
from struct import unpack, pack, Struct, error as StructError
from warnings import warn
from array import array
import os.path
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


import bpy, bmesh


def flipY(vec):
    return Vector((vec.x, 1.0-vec.y))

def srgbToLinearrgb(c):
    """
    >>> round(srgbToLinearrgb(0.019607843), 6)
    0.001518
    >>> round(srgbToLinearrgb(0.749019608), 6)
    0.520996
    """
    if c < 0.04045:
        return 0.0 if c < 0.0 else (c * (1.0 / 12.92))
    else:
        return ((c + 0.055) * (1.0 / 1.055)) ** 2.4

def color8ToLinear(c):
    res = srgbToLinearrgb(c[0]/255), srgbToLinearrgb(c[1]/255), srgbToLinearrgb(c[2]/255)
    if len(c) == 4:
        res += (c[3]/255,)
    return res

def drawBatch(bmd, index, mdef, matIndex, bmverts, bm, indent=0):
    batch = bmd.shp1.batches[index]
    assert batch.hasPositions
    matrixTable = [(Matrix(), [], []) for i in range(10)]
    for mat, mmi, mmw in matrixTable:
        mat.zero()
    for i, packet in enumerate(batch.packets):
        # draw packet
        updateMatrixTable(bmd, packet, matrixTable)
        mat, mmi, mmw = matrixTable[0]
        for curr in packet.primitives:
            a = 0
            b = 1
            flip = True
            for c in range(2, len(curr.points)):
                pa, pb, pc = curr.points[a], curr.points[b], curr.points[c]

                if flip:
                    x = pa
                    pa = pb
                    pb = x

                bmFaceVerts = []
                for p in (pa, pb, pc):
                    bmIdx = [None, None, None]
                    if batch.hasPositions:
                        bmIdx[0] = p.posIndex
                    if batch.hasNormals:
                        bmIdx[1] = p.normalIndex
                    if batch.hasMatrixIndices:
                        bmIdx[2] = p.matrixIndex
                        mat, mmi, mmw = matrixTable[p.matrixIndex//3]
                    bmIdx = tuple(bmIdx)
                    if bmIdx in bmverts:
                        bmFaceVerts.append(bmverts[bmIdx])
                    else:
                        v = bm.verts.new(mat@bmd.vtx1.positions[p.posIndex])
                        if batch.hasNormals:
                            v.normal = (mat@bmd.vtx1.normals[p.normalIndex].resized(4)).resized(3)
                        layer = bm.verts.layers.deform.verify()
                        for jntIdx, weight in zip(mmi, mmw):
                            jnt = bmd.jnt1.frames[jntIdx]
                            v[layer][jntIdx] = weight
                        bmverts[bmIdx] = v
                        bmFaceVerts.append(v)
                try:
                    f = bm.faces.new(bmFaceVerts)
                except ValueError as e:
                    #print(e)
                    f = None

                if f is not None:
                    f.smooth = batch.hasNormals
                    f.material_index = matIndex
                    for j, hasColorLayer in enumerate(batch.hasColors):
                        if hasColorLayer:
                            layer = bm.loops.layers.color[str(j)]
                            f.loops[0][layer] = color8ToLinear(bmd.vtx1.colors[j][pa.colorIndex[j]])
                            f.loops[1][layer] = color8ToLinear(bmd.vtx1.colors[j][pb.colorIndex[j]])
                            f.loops[2][layer] = color8ToLinear(bmd.vtx1.colors[j][pc.colorIndex[j]])
                    for j, hasTexLayer in enumerate(batch.hasTexCoords):
                        if hasTexLayer:
                            layer = bm.loops.layers.uv[str(j)]
                            f.loops[0][layer].uv = flipY(bmd.vtx1.texCoords[j][pa.texCoordIndex[j]])
                            f.loops[1][layer].uv = flipY(bmd.vtx1.texCoords[j][pb.texCoordIndex[j]])
                            f.loops[2][layer].uv = flipY(bmd.vtx1.texCoords[j][pc.texCoordIndex[j]])

                if curr.type == PrimitiveType.TRIANGLESTRIP:
                    flip = not flip
                    a = b
                    b = c
                elif curr.type == PrimitiveType.TRIANGLEFAN:
                    b = c
                else:
                    warn("Unknown primitive type %d"%curr.type)
                    continue

def traverseScenegraph(sg, bmverts, bm, bmd, onDown=True, matIndex=0, p=None, indent=0):
    if p is None: p = Matrix.Identity(4)
    effP = p

    if sg.type == 2:
        raise Exception("Unexpected exit node!")
    elif sg.type == 0x10:
        # joint
        f = bmd.jnt1.frames[sg.index]
        bmd.jnt1.matrices[sg.index] = updateMatrix(f, effP)
        effP = bmd.jnt1.matrices[sg.index]
        parentBone = sg.index
    elif sg.type == 0x11:
        # material
        matIndex = sg.index
        mat = bmd.mat3.materials[sg.index]
        onDown = mat.flag == 1
    elif sg.type == 0x12 and onDown:
        # shape
        batch = bmd.shp1.batches[sg.index]
        drawBatch(bmd, sg.index, effP, matIndex, bmverts, bm, indent)

    for node in sg.children:
        traverseScenegraph(node, bmverts, bm, bmd, onDown, matIndex, effP, indent+1)

    if sg.type == 0x12 and not onDown:
        batch = bmd.shp1.batches[sg.index]
        drawBatch(bmd, sg.index, effP, matIndex, bmverts, bm, indent)

class Column:
    def __init__(self, x=0):
        self.x = x
        self.bottom = 0
        self.maxWidth = 0

class NodePlacer:
    def __init__(self, tree):
        self.tree = tree
        self.columns = [Column()]
        self.colIdx = 0
        self.margin = 10
    
    def nextColumn(self):
        if self.colIdx >= len(self.columns)-1:
            self.columns.append(Column())
        lastCol = self.columns[self.colIdx]
        self.colIdx += 1
        self.columns[self.colIdx].x = lastCol.x+lastCol.maxWidth+self.margin
    
    def previousColumn(self):
        self.colIdx -= 1
    
    def addNode(self, type):
        col = self.columns[self.colIdx]
        node = self.tree.nodes.new(type)
        node.location = (col.x, col.bottom)
        node.select = False
        node.hide = True
        col.bottom -= node.bl_height_max+self.margin
        if col.maxWidth < node.bl_width_default: col.maxWidth = node.bl_width_default
        return node

def importMesh(filePath, bmd, mesh, bm=None):
    btextures = []
    if hasattr(bmd, "tex1"):
        print("Importing textures")
        for texture in bmd.tex1.textures:
            imageName = texture.name#getDataName(bmd)
            if imageName in bpy.data.images:
                image = bpy.data.images[imageName]
            else:
                fileName = "/tmp/" + imageName + ".png"
                try:
                    image = bpy.data.images.load(fileName)
                except RuntimeError as e:
                    imgs = decodeTexturePIL(self.data, self.format, self.width, self.height, self.paletteFormat, self.palette, mipmapCount=self.mipmapCount)
                    imgs[0][0].save(fileName)
                    image = bpy.data.images.load(fileName)
                    image.pack()
                image.name = imageName
            btextures.append(image)

    if hasattr(bmd, "mat3"):
        print("Importing materials")
        for i, mat in enumerate(bmd.mat3.materials):
            bmat = None
            if False and mat.name in bpy.data.materials:
                bmat = bpy.data.materials[mat.name]
                mesh.materials.append(bmat)
                continue
            else:
                bmat = bpy.data.materials.new(mat.name)
            mesh.materials.append(bmat)
            
            if mat.cullMode is not None:
                bmat.use_backface_culling = mat.cullMode == 2
            if mat.blendInfo == BlendMode.NONE:
                bmat.blend_method = 'OPAQUE'
            elif mat.blendInfo == BlendMode.BLEND:
                bmat.blend_method = 'BLEND'
            if len(mat.colors) > 0 and mat.colors[0] is not None:
                bmat.diffuse_color = color8ToLinear(mat.colors[0])
            
            bmat.use_nodes = True
            tree = bmat.node_tree
            tree.nodes.clear()
            
            placer = NodePlacer(tree)
            
            # Shader variables
            colorMatReg = []
            colorAmbReg = []
            konstColorReg = []
            colorReg = []
            for values, name, out in [
                (mat.matColors, "Material", colorMatReg),
                (mat.ambientColors, "Ambient", colorAmbReg),
                (mat.constColors, "Constant", konstColorReg),
                (mat.colors, "Base", colorReg)
            ]:
                for j, color in enumerate(values):
                    node = placer.addNode('ShaderNodeRGB')
                    node.outputs[0].default_value = color8ToLinear(color)
                    node.label = name + ' ' + str(j)
                    out.append(node.outputs[0])
            colorVtxReg = []
            for j in range(mat.lightChanCount):
                node = placer.addNode('ShaderNodeVertexColor')
                node.layer_name = str(j)
                colorVtxReg.append(node.outputs['Color']) # TODO alpha
            placer.nextColumn()
            
            # Light channels
            colorChannels = []
            for j in range(mat.lightChanCount):
                colorChannel = safeGet(mat.lightChanInfos, j*2)
                #alphaChannel = safeGet(mat.lightChanInfos, j*2+1)
                matSource = {ColorSrc.REG: colorMatReg, ColorSrc.VTX: colorVtxReg}[colorChannel.matColorSource][j]
                ambSource = {ColorSrc.REG: colorAmbReg, ColorSrc.VTX: colorVtxReg}[colorChannel.ambColorSource][j]
                if colorChannel.lightingEnabled and colorChannel.litMask != 0:
                    if colorChannel.attenuationFunction in (1, 3):
                        node = placer.addNode('ShaderNodeEeveeSpecular')
                        tree.links.new(matSource, node.inputs['Specular'])
                        tree.links.new(ambSource, node.inputs['Emissive Color'])
                        if colorChannel.diffuseFunction == DiffuseFunction.NONE:
                            node.inputs['Base Color'].default_value = (0,0,0,0)
                        else:
                            tree.links.new(matSource, node.inputs['Base Color'])
                        out = node.outputs['BSDF']
                    else:
                        if colorChannel.diffuseFunction == DiffuseFunction.NONE:
                            out = matSource
                        else:
                            node = placer.addNode('ShaderNodeBsdfDiffuse')
                            tree.links.new(matSource, node.inputs['Color'])
                            out = node.outputs['BSDF']
                        placer.nextColumn()
                        node = placer.addNode('ShaderNodeAddShader')
                        tree.links.new(ambSource, node.inputs[0])
                        tree.links.new(out, node.inputs[1])
                        placer.previousColumn()
                        out = node.outputs['Shader']
                    node.label = "Light channel %d"%j
                    colorChannels.append(out)
                else:
                    colorChannels.append(matSource) # TODO add ambient?
            placer.nextColumn()
            
            # Texgen stages
            texGens = []
            for j, texGen in enumerate(mat.texGenInfos[:mat.texGenCount]):
                if texGen.source == TexGenSrc.POS:
                    node = placer.addNode('ShaderNodeNewGeometry')
                    out = node.outputs['Position']
                elif texGen.source == TexGenSrc.NRM:
                    node = placer.addNode('ShaderNodeNewGeometry')
                    out = node.outputs['Normal']
                elif texGen.source == TexGenSrc.BINRM:
                    node1 = placer.addNode('ShaderNodeNewGeometry')
                    placer.nextColumn()
                    node = placer.addNode('ShaderNodeVectorMath')
                    placer.previousColumn()
                    tree.links.new(node1.outputs['Normal'], node.inputs[0])
                    tree.links.new(node1.outputs['Tangent'], node.inputs[1])
                    out = node.outputs['Vector']
                elif texGen.source == TexGenSrc.TANGENT:
                    node = placer.addNode('ShaderNodeNewGeometry')
                    out = node.outputs['Tangent']
                elif texGen.source >= TexGenSrc.TEX0 and texGen.source <= TexGenSrc.TEX7:
                    node = placer.addNode('ShaderNodeUVMap')
                    out = node.outputs['UV']
                    node.uv_map = str(texGen.source-TexGenSrc.TEX0)
                elif texGen.source >= TexGenSrc.TEXCOORD0 and texGen.source <= TexGenSrc.TEXCOORD6:
                    node = placer.addNode('NodeReroute')
                    out = node.outputs[0]
                    tree.links.new(texGens[texGen.source-TexGenSrc.TEXCOORD0], node.inputs[0])
                elif texGen.source >= TexGenSrc.COLOR0 and texGen.source <= TexGenSrc.COLOR1:
                    node = placer.addNode('NodeReroute')
                    out = node.outputs[0]
                    tree.links.new(colorChannels[texGen.source-TexGenSrc.COLOR0], node.inputs[0])
                node.label = "Texture coordinate generation source %d"%j
                placer.nextColumn()
                if texGen.type == TexGenType.MTX3x4 or texGen.type == TexGenType.MTX2x4:
                    node = placer.addNode('ShaderNodeMapping')
                    node.vector_type = 'POINT'
                    if texGen.matrix >= TexGenMatrix.TEXMTX0 and texGen.matrix <= TexGenMatrix.TEXMTX9 and mat.texMtxInfos[texGen.matrix-TexGenMatrix.TEXMTX0] is not None:
                        texMtx = mat.texMtxInfos[texGen.matrix-TexGenMatrix.TEXMTX0]
                        node.inputs['Location'].default_value = texMtx.translation+(0,)
                        node.inputs['Rotation'].default_value = (0,0,texMtx.rotation) # TODO what units
                        node.inputs['Scale'].default_value = texMtx.scale+(1,)
                    tree.links.new(out, node.inputs[0])
                    out = node.outputs[0]
                elif texGen.type == TexGenType.SRTG:
                    node = placer.addNode('ShaderNodeShaderToRGB')
                    out = node.outputs[0]
                placer.previousColumn()
                texGens.append(out)
            placer.nextColumn()
            placer.nextColumn()
            
            for j in range(mat.tevStageCount):
                tevOrderInfo = mat.tevOrderInfos[j]
                tevStage = mat.tevStageInfos[j]
                
                colorSources = []
                for colorSrc in (tevStage.colorInA, tevStage.colorInB, tevStage.colorInC, tevStage.colorInD):
                    if colorSrc in (TevColorArg.CPREV, TevColorArg.C0, TevColorArg.C1, TevColorArg.C2):
                        colorSources.append(colorReg[colorSrc.value//2])
                    elif colorSrc in (TevColorArg.TEXC, TevColorArg.TEXA):
                        texture = bmd.tex1.textures[mat.textureIndexes[tevOrderInfo.texMap]]
                        node = placer.addNode('ShaderNodeTexImage')
                        if texture.wrapS == 0: node.extension = 'EXTEND'
                        elif texture.wrapS == 1: node.extension = 'REPEAT'
                        elif texture.wrapS == 2: node.extension = 'CHECKER'
                        node.interpolation = 'Linear' if texture.magFilter%2 == 1 else 'Closest'
                        node.image = bpy.data.images[texture.name]#getDataName(bmd)
                        tree.links.new(texGens[tevOrderInfo.texCoordId], node.inputs[0])
                        if colorSrc == TevColorArg.TEXC:
                            colorSources.append(node.outputs[0])
                        else:
                            colorSources.append(node.outputs[1])
                    elif colorSrc == TevColorArg.RASC:
                        if tevOrderInfo.chanId == ColorChannelID.COLOR0:
                            colorSources.append(colorChannels[0])
                        elif tevOrderInfo.chanId == ColorChannelID.COLOR1:
                            colorSources.append(colorChannels[0])
                        elif tevOrderInfo.chanId == ColorChannelID.COLOR0A0:
                            colorSources.append(colorChannels[0])
                        elif tevOrderInfo.chanId == ColorChannelID.COLOR1A1:
                            colorSources.append(colorChannels[0])
                        else:
                            assert False, tevOrderInfo.chanId
                            colorSources.append(None)
                    elif colorSrc == TevColorArg.ONE:
                        colorSources.append(1.0)
                    elif colorSrc == TevColorArg.HALF:
                        colorSources.append(0.5)
                    elif colorSrc == TevColorArg.KONST:
                        constColorSel = mat.constColorSels[j]
                        if constColorSel == TevKColorSel.CONST_1:
                            colorSources.append(1.0)
                        elif constColorSel == TevKColorSel.CONST_7_8:
                            colorSources.append(7/8)
                        elif constColorSel == TevKColorSel.CONST_3_4:
                            colorSources.append(3/4)
                        elif constColorSel == TevKColorSel.CONST_5_8:
                            colorSources.append(5/8)
                        elif constColorSel == TevKColorSel.CONST_1_2:
                            colorSources.append(1/2)
                        elif constColorSel == TevKColorSel.CONST_3_8:
                            colorSources.append(3/8)
                        elif constColorSel == TevKColorSel.CONST_1_4:
                            colorSources.append(1/4)
                        elif constColorSel == TevKColorSel.CONST_1_8:
                            colorSources.append(1/8)
                        elif constColorSel >= TevKColorSel.K0 and constColorSel <= TevKColorSel.K1:
                            colorSources.append(konstColorReg[constColorSel-TevKColorSel.K0])
                        else:
                            #sep = placer.addNode('ShaderNodeSeparateRGB')
                            #tree.links.new(konstColorReg[constColorSel.value%4], sep.inputs[0])
                            #colorSources.append(sep.outputs[(constColorSel.value-0x10)//4])
                            colorSources.append(konstColorReg[constColorSel.value%4])
                    elif colorSrc == TevColorArg.ZERO:
                        colorSources.append(0.0)
                    else:
                        assert False, colorSrc
                        colorSources.append(None)
                assert len(colorSources) == 4, (tevStage.colorInA, tevStage.colorInB, tevStage.colorInC, tevStage.colorInD, colorSources)
                
                placer.nextColumn()
                if tevStage.colorOp in (TevOp.ADD, TevOp.SUB):
                    node = placer.addNode('ShaderNodeMixRGB')
                    node.blend_type = 'MIX'
                    if isinstance(colorSources[2], float):
                        node.inputs['Fac'].default_value = colorSources[2]
                    else:
                        tree.links.new(colorSources[2], node.inputs['Fac'])
                    if isinstance(colorSources[0], float):
                        node.inputs[1].default_value = (colorSources[0],colorSources[0],colorSources[0],1)
                    else:
                        tree.links.new(colorSources[0], node.inputs[1])
                    if isinstance(colorSources[1], float):
                        node.inputs[2].default_value = (colorSources[1],colorSources[1],colorSources[1],1)
                    else:
                        tree.links.new(colorSources[1], node.inputs[2])
                    
                    placer.nextColumn()
                    node2 = placer.addNode('ShaderNodeMixRGB')
                    node2.blend_type = 'ADD' if tevStage.colorOp == TevOp.ADD else 'SUBTRACT'
                    node2.inputs['Fac'].default_value = 1.0
                    tree.links.new(node.outputs[0], node2.inputs[1])
                    if isinstance(colorSources[3], float):
                        node2.inputs[2].default_value = (colorSources[3],colorSources[3],colorSources[3],1)
                    else:
                        tree.links.new(colorSources[3], node2.inputs[2])
                    placer.previousColumn()
                    colorReg[0] = node2.outputs[0]
                placer.nextColumn()
                placer.nextColumn()
                

            shout = placer.addNode('ShaderNodeOutputMaterial')
            tree.links.new(colorReg[0], shout.inputs[0])

    print("Importing mesh")
    if bm is None: bm = bmesh.new()

    if hasattr(bmd, "vtx1"):
        for i, colorLayer in enumerate(bmd.vtx1.colors):
            if colorLayer is not None:
                bm.loops.layers.color.new(str(i))
        for i, texLayer in enumerate(bmd.vtx1.texCoords):
            if texLayer is not None:
                bm.loops.layers.uv.new(str(i))
    if hasattr(bmd, "jnt1") and len(bmd.jnt1.frames) > 0:
        bm.verts.layers.deform.verify()

    bmverts = {}
    
    traverseScenegraph(bmd.scenegraph, bmverts, bm, bmd)

    bm.to_mesh(mesh)
    return mesh

from functools import reduce
import operator

def drawSkeleton(bmd, sg, arm, onDown=True, p=None, parent=None, indent=0):
    if p is None: p = Matrix.Identity(4)
    effP = p
    
    if sg.type == 0x10:
        f = bmd.jnt1.frames[sg.index]
        effP = updateMatrix(f, p)
        bone = arm.edit_bones[f.name]
        bone.head = Vector((0,0,0))
        if len(sg.children) == 0:
            bone.tail = Vector((0,0,8))
        else:
            ts = [bmd.jnt1.frames[node.index].translation for node in sg.children if node.index < len(bmd.jnt1.frames)]
            if len(ts) == 0:
                bone.tail = Vector((0,0,8))
            else:
                bone.tail = reduce(operator.add, ts)/len(sg.children)
        bone.matrix = effP@Matrix(((0,1,0,0),(0,0,1,0),(1,0,0,0),(0,0,0,1)))
        #Matrix(((0,1,0,0),(-1,0,0,0),(0,0,1,0),(0,0,0,1)))
        if parent is not None:
            bone.parent = parent
        bone['_bmd_rest_scale'] = ','.join([repr(x) for x in f.scale])
        bone['_bmd_rest'] = repr(frameMatrix(f)[:])
    else:
        bone = parent

    for node in sg.children:
        drawSkeleton(bmd, node, arm, onDown, effP, bone, indent+1)

def importSkeleton(bmd, arm):
    drawSkeleton(bmd, bmd.scenegraph, arm)
    return arm

bl_info = {
    "name": "Import BMD/BDL",
    "author": "Spencer Alves",
    "version": (1,0,0),
    "blender": (2, 80, 0),
    "location": "Import",
    "description": "Import J3D BMD/BDL model",
    "warning": "",
    "wiki_url": "",
    "tracker_url": "",
    "category": "Import-Export"}

# ImportHelper is a helper class, defines filename and
# invoke() function which calls the file selector.
from bpy_extras.io_utils import ImportHelper
from bpy.props import StringProperty, BoolProperty, EnumProperty, CollectionProperty
from bpy.types import Operator, OperatorFileListElement

def importFile(filepath):
    fin = open(filepath, 'rb')
    print("Reading", filepath)
    bmd = BModel()
    bmd.name = os.path.splitext(os.path.split(filepath)[-1])[0]
    bmd.read(fin)
    fin.close()

    mesh = bpy.data.meshes.new(bmd.name)
    meshObject = bpy.data.objects.new(name=mesh.name+"_mesh", object_data=mesh)
    arm = bpy.data.armatures.new(name=bmd.name)
    armObject = bpy.data.objects.new(name=arm.name+"_arm", object_data=arm)

    print("Importing armature")
    meshObject.parent = armObject
    armObject.scale = Vector((1,1,1))/100 # approximate, according to mario's height
    armObject.rotation_euler = Vector((math.pi/2,0,0))
    armMod = meshObject.modifiers.new('Armature', 'ARMATURE')
    armMod.object = armObject
    bpy.context.scene.collection.objects.link(meshObject)
    bpy.context.scene.collection.objects.link(armObject)

    bpy.context.view_layer.objects.active = armObject
    bpy.ops.object.mode_set(mode='EDIT')

    if hasattr(bmd, "jnt1"):
        for i, f in enumerate(bmd.jnt1.frames):
            meshObject.vertex_groups.new(name=f.name)
            arm.edit_bones.new(name=f.name)
    
        importSkeleton(bmd, arm)
    
    bpy.ops.object.mode_set(mode='OBJECT')
    
    #armObject["scenegraph"] = repr(bmd.scenegraph.to_dict(bmd))
    
    bm = bmesh.new()
    bm.from_object(meshObject, bpy.context.evaluated_depsgraph_get())
    importMesh(filepath, bmd, mesh, bm)

    if 0:
        mesh = bpy.data.meshes.new(bmd.name+"_debug")
        meshObject = bpy.data.objects.new(name=mesh.name, object_data=mesh)
        bm = bmesh.new()
        bm.from_mesh(mesh)
        
        for f in bmd.jnt1.frames:
            meshObject.vertex_groups.new(f.name)

        def drawSkeletonDebug(bmd, sg, bm, meshObject, p=None, indent=0):
            if p is None: p = Matrix.Identity(4)
            effP = p
        
            if sg.type == 0x10:
                f = bmd.jnt1.frames[sg.index]
                effP = updateMatrix(f, p)
                size = Vector(f.bbMax)-Vector(f.bbMin)
                if size.length > 0:
                    layer = bm.verts.layers.deform.verify()
                    center = (Vector(f.bbMin)+Vector(f.bbMax))*0.5
                    m = Matrix.Translation(center).to_4x4()
                    m[0][0] = size.x
                    m[1][1] = size.y
                    m[2][2] = size.z
                    for v in bmesh.ops.create_cube(bm, size=1.0, matrix=p*m, calc_uvs=False)['verts']:
                        v[layer][sg.index] = 1.0

            for node in sg.children:
                drawSkeletonDebug(bmd, node, bm, meshObject, effP, indent+1)
        drawSkeletonDebug(bmd, bmd.scenegraph, bm, meshObject)
    
        bm.verts.layers.deform.verify()
        meshObject.draw_type = 'WIRE'
        meshObject.parent = armObject
        armMod = meshObject.modifiers.new('Armature', 'ARMATURE')
        armMod.object = armObject
        bm.to_mesh(mesh)
        bm.free()
        bpy.context.scene.collection.objects.link(meshObject)

class ImportBMD(Operator, ImportHelper):
    files: CollectionProperty(type=OperatorFileListElement, options={'HIDDEN', 'SKIP_SAVE'})
    directory: StringProperty(maxlen=1024, subtype='FILE_PATH', options={'HIDDEN', 'SKIP_SAVE'})

    bl_idname = "import_scene.bmd"  # important since its how bpy.ops.import_test.some_data is constructed
    bl_label = "Import BMD/BDL"

    # ImportHelper mixin class uses this
    filename_ext = ".bmd"

    filter_glob: StringProperty(
            default="*.bmd;*.bmt;*.bdl",
            options={'HIDDEN'},
            )

    def execute(self, context):
        context.window_manager.progress_begin(0, len(self.files))
        for i, file in enumerate(self.files):
            context.window_manager.progress_update(i)
            importFile(os.path.join(self.directory, file.name))
        context.window_manager.progress_end()
        return {'FINISHED'}

# Only needed if you want to add into a dynamic menu
def menu_func_import(self, context):
    self.layout.operator(ImportBMD.bl_idname, text="Import J3D BMD/BDL model (*.bmd,*.bdl)")


def register():
    bpy.utils.register_class(ImportBMD)
    bpy.types.TOPBAR_MT_file_import.append(menu_func_import)


def unregister():
    bpy.utils.unregister_class(ImportBMD)
    bpy.types.TOPBAR_MT_file_import.remove(menu_func_import)


if __name__ == "__main__":
    register()

    # test call
    #bpy.ops.import_scene.bmd('INVOKE_DEFAULT')

elif 0:
    import sys
    fin = open(sys.argv[1], 'rb')
    bmd = BModel()
    bmd.name = os.path.splitext(os.path.split(sys.argv[1])[-1])[0]
    bmd.read(fin)
    fin.close()

