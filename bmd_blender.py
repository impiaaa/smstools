import sys
from struct import unpack, pack, Struct, error as StructError
from warnings import warn
from array import array
import os.path
import math
import bpy, bmesh
from mathutils import *
from common import *
from texture import *

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
    header = Struct('>HH4L')
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



class Node(Readable):
    header = Struct('>HH')
    def read(self, fin):
        self.type, self.index = self.header.unpack(fin.read(4))

class Inf1(Section):
    header = Struct('>H2xLLL')
    def read(self, fin, start, size):
        unknown1, unknown2, self.vertexCount, offsetToEntries = self.header.unpack(fin.read(16))
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
                d['material'] = bmd.mat3.materials[bmd.mat3.indexToMatIndex[self.index]]
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
    header = Struct('>H2xLLL')
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


class ColorChanInfo(Readable):
    header = Struct('>BBBBBB2x')
    def read(self, fin):
        self.lightingEnabled, self.matColorSource, self.litMask, \
            self.diffuseFunction, self.attenuationFunction, \
            self.ambColorSource = self.header.unpack(fin.read(8))

class TexGenInfo(Readable):
    header = Struct('>BBBx')
    def read(self, fin):
        self.type, self.source, self.matrix = self.header.unpack(fin.read(4))
    def __repr__(self):
        return "TexGenInfo texGenType=%x, texGenSrc=%x, matrix=%x"%(self.type, self.source, self.matrix)

class TexMtxInfo(Readable):
    header = Struct('>BB2x')
    def read(self, fin):
        self.projection, self.info = self.header.unpack(fin.read(4))
        self.center = unpack('>3f', fin.read(12))
        self.scale = unpack('>2f', fin.read(8))
        self.rotation = unpack('>h2x', fin.read(4))[0]/0x7FFF
        self.translation = unpack('>2f', fin.read(8))
        self.effectMatrix = unpack('>16f', fin.read(64))

def safeindex(ls,index):
    if index < len(ls) and index > 0: return ls[index]
    else: return hex(index)

colorids = ['COLOR0', 'COLOR1', 'ALPHA0', 'ALPHA1', 'COLOR0A0', 'COLOR1A1', 'COLORZERO', 'BUMP ', 'BUMPN', 'COLORNULL']
class TevOrderInfo(Readable):
    header = Struct('>BBBx')
    def read(self, fin):
        self.texCoordId, self.texMap, self.chanId = self.header.unpack(fin.read(4))
    def __repr__(self):
        return "TevOrderInfo texCoordId=%x, texMap=%x, chanId=%s"%(self.texCoordId, self.texMap, safeindex(colorids,self.chanId))

class TevSwapModeInfo(Readable): pass
class TevSwapModeTable(Readable): pass

class AlphaCompare(Readable):
    header = Struct('>BBBBB3x')
    def read(self, fin):
        self.comp0, self.ref0, self.alphaOp, self.comp1, self.ref1 = self.header.unpack(fin.read(8))

class BlendInfo(Readable):
    header = Struct('>BBBB')
    def read(self, fin):
        self.blendMode, self.srcFactor, self.dstFactor, self.logicOp = self.header.unpack(fin.read(4))

class ZMode(Readable):
    header = Struct('>BBBx')
    def read(self, fin):
        self.enable, self.func, self.updateEnable = self.header.unpack(fin.read(4))
    def __repr__(self):
        return "ZMode enable=%x, func=%x, updateEnable=%x"%(self.enable, self.func, self.updateEnable)

srcregs = ["CPREV", "APREV", "C0", "A0", "C1", "A1", "C2", "A2", \
"TEXC", "TEXA", "RASC", "RASA", "ONE", "HALF", "KONST", "ZERO"]
ops = ["ADD", "SUB", None, None, None, None, None, None, \
"COMP_R8_GT", "COMP_R8_EQ", \
"COMP_GR16_GT", "COMP_GR16_EQ", \
"COMP_BGR24_GT", "COMP_BGR24_EQ", \
"COMP_RGB8_GT", "COMP_RGB8_EQ"]
biases = ["ZERO", "ADDHALF", "SUBHALF"]
scales = ["SCALE_1", "SCALE_2", "SCALE_4", "DIVIDE_2"]
destregs = ["PREV", "REG0", "REG1", "REG2"]
def fmtsrcreg(x): return safeindex(srcregs, x)
def fmtsrcregs(l): return "("+(", ".join(tuple(map(fmtsrcreg, l))))+")"
class TevStageInfo(Readable):
    colorInStruct = Struct('>x4B')
    colorInfoStruct = Struct('>BBBBB')
    alphaInStruct = Struct('>4B')
    alphaInfoStruct = Struct('BBBBBx')
    def read(self, fin):
        self.colorIn = self.colorInStruct.unpack(fin.read(5))
        self.colorOp, self.colorBias, self.colorScale, self.colorClamp, self.colorRegId = self.colorInfoStruct.unpack(fin.read(5))
        self.alphaIn = self.alphaInStruct.unpack(fin.read(4))
        self.alphaOp, self.alphaBias, self.alphaScale, self.alphaClamp, self.alphaRegId = self.alphaInfoStruct.unpack(fin.read(6))
    def __repr__(self):
        return "TevStageInfo colorIn=%s, colorOp=%s, colorBias=%s, colorScale=%s, colorClamp=%x, colorRegId=%s, \
alphaIn=%s, alphaOp=%s, alphaBias=%s, alphaScale=%s, alphaClamp=%x, alphaRegId=%s"%(\
fmtsrcregs(self.colorIn), safeindex(ops,self.colorOp), safeindex(biases,self.colorBias), safeindex(scales,self.colorScale), self.colorClamp, safeindex(destregs,self.colorRegId), \
fmtsrcregs(self.alphaIn), safeindex(ops,self.alphaOp), safeindex(biases,self.alphaBias), safeindex(scales,self.alphaScale), self.alphaClamp, safeindex(destregs,self.alphaRegId))

class Material(Readable):
    header = Struct('>BBBBBxBx')
    def read(self, fin):
        self.flag, self.cullIndex, self.numChansIndex, self.texGenCountIndex, \
            self.tevCountIndex, self.zModeIndex = self.header.unpack(fin.read(8))
        self.materialColor = unpack('>2H', fin.read(4))
        self.chanControls = unpack('>4H', fin.read(8))

        self.ambientColor = unpack('>2H', fin.read(4))
        self.lights = unpack('>8H', fin.read(16))

        self.texGenInfos = unpack('>8h', fin.read(16)) # postTexGen
        self.texGenInfos2 = unpack('>8H', fin.read(16))
        self.texMtxInfos = unpack('>10h', fin.read(20))
        self.dttMatrices = unpack('>20H', fin.read(40))
        self.texStages = unpack('>8H', fin.read(16))
        self.color3 = unpack('>4H', fin.read(8))
        self.constColorSel = unpack('>16B', fin.read(16))
        self.constAlphaSel = unpack('>16B', fin.read(16))
        self.tevOrderInfo = unpack('>16H', fin.read(32))
        self.colorS10 = unpack('>4H', fin.read(8))
        self.tevStageInfo = unpack('>16h', fin.read(32))
        self.tevSwapModeInfo = unpack('>16H', fin.read(32))
        self.tevSwapModeTable = unpack('>4H', fin.read(8))
        self.unknown6 = unpack('>12H', fin.read(24))
        self.alphaCompIndex, self.blendIndex = unpack('>2xHH2x', fin.read(8))

    def debug(self, mat3):
        print("\tflag =", self.flag)
        print("\tcull =", mat3.cullModes[self.cullIndex])
        print("\tnumChans =", mat3.numChans[self.numChansIndex])
        print("\ttexGenCount =", mat3.texGenCounts[self.texGenCountIndex])
        print("\ttevCount =", mat3.tevCounts[self.tevCountIndex])
        print("\tzMode =", mat3.zModes[self.zModeIndex])
        for j in range(mat3.tevCounts[self.tevCountIndex]):
            print("\tOrder", j)
            print("\t\t", mat3.tevOrderInfos[self.tevOrderInfo[j]])
            print("\tStage", j)
            print("\t\t", mat3.tevStageInfos[self.tevStageInfo[j]])
    
    def __repr__(self):
        return "{}({})".format(__class__.__name__, repr(self.name))

class Mat3(Section):
    header = Struct('>HH')
    def read(self, fin, start, size):
        count, pad = self.header.unpack(fin.read(4))
        offsets = unpack('>30L', fin.read(120))

        lengths = computeSectionLengths(offsets, size)

        fin.seek(start+offsets[0])
        self.materials = [None]*count
        for i in range(count):
            m = Material()
            m.read(fin)
            self.materials[i] = m
        
        fin.seek(start+offsets[1])
        self.indexToMatIndex = array('H') # remapTable
        self.indexToMatIndex.fromfile(fin, count)
        if sys.byteorder == 'little': self.indexToMatIndex.byteswap()
        
        self.materialNames = readstringtable(start+offsets[2], fin)
        if count != len(self.materialNames):
            warn("mat3: number of strings (%d) doesn't match number of elements (%d)"%len(self.materialNames), count)
        for m, n in zip(self.materials, self.materialNames):
            m.name = n

        fin.seek(start+offsets[3]) # indirect
        # TODO offset[3] indirect texturing blocks (always as many as count)

        fin.seek(start+offsets[4])
        self.cullModes = array('L')
        self.cullModes.fromfile(fin, lengths[4])
        if sys.byteorder == 'little': self.cullModes.byteswap()

        fin.seek(start+offsets[5])
        self.materialColor = [unpack('>BBBB', fin.read(4)) for i in range(lengths[5]//4)]

        fin.seek(start+offsets[6])
        self.numChans = array('B')
        self.numChans.fromfile(fin, lengths[6])

        fin.seek(start+offsets[7])
        self.colorChanInfos = [ColorChanInfo(fin) for i in range(lengths[7]//8)]

        fin.seek(start+offsets[8])
        self.ambientColor = [unpack('>BBBB', fin.read(4)) for i in range(lengths[8]//4)] 

        # 9 (LightInfo)
        
        fin.seek(start+offsets[10])
        self.texGenCounts = array('B')
        self.texGenCounts.fromfile(fin, lengths[10])

        fin.seek(start+offsets[11])
        self.texGenInfos = [TexGenInfo(fin) for i in range(lengths[11]//4)]

        # 12 (TexCoord2Info)
        # postTexGen
        
        fin.seek(start + offsets[13])
        self.texMtxInfos = [TexMtxInfo(fin) for i in range(lengths[13]//100)]
        
        # 14 (TexMtxInfo2)
        # postTexMtx
        
        fin.seek(start+offsets[15])
        self.texStageIndexToTextureIndex = array('H')
        self.texStageIndexToTextureIndex.fromfile(fin, lengths[15]//2)
        if sys.byteorder == 'little': self.texStageIndexToTextureIndex.byteswap()

        fin.seek(start+offsets[16])
        self.tevOrderInfos = [TevOrderInfo(fin) for i in range(lengths[16]//4)]
        
        # TODO offsets[17] (read colorS10)
        fin.seek(start+offsets[17])
        # colorRegister
        
        # TODO offsets[18] (color3)
        # colorConstant

        fin.seek(start+offsets[19])
        self.tevCounts = array('B')
        self.tevCounts.fromfile(fin, lengths[19])

        fin.seek(start+offsets[20])
        self.tevStageInfos = [TevStageInfo(fin) for i in range(lengths[20]//20)]
        
        # TODO offset[21] (TevSwapModeInfos)
        
        # TODO offset[22] (TevSwapModeTable)

        # 23 (FogInfo)        
        
        fin.seek(start+offsets[24])
        self.alphaCompares = [AlphaCompare(fin) for i in range(lengths[24]//8)]

        fin.seek(start+offsets[25])
        self.blendInfos = [BlendInfo(fin) for i in range(lengths[25]//4)]

        fin.seek(start+offsets[26])
        self.zModes = [ZMode(fin) for i in range(lengths[26]//4)]
        
        # 27 (MaterialData6)
        # 28 (MaterialData7)
        # 29 (NBTScaleInfo)


class Index(Readable):
    sizeStructs = {1: Struct('>B'), 3: Struct('>H')}
    def __init__(self):
        super().__init__()
        self.colorIndex = [-1]*2
        self.texCoordIndex = [-1]*8
    def read(self, fin, attribs):
        for attrib in attribs:
            #get value
            s = self.sizeStructs[attrib.dataType]
            val, = s.unpack(fin.read(s.size))

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

class Primitive(Readable):
    header = Struct('>BH')
    def read(self, fin, attribs):
        self.type, count = self.header.unpack(fin.read(3))
        if self.type == 0: return

        self.points = [Index() for jkl in range(count)]

        for j in range(count):
            currPoint = self.points[j]
            currPoint.read(fin, attribs)

class Packet(Readable):
    locationHeader = Struct('>LL')
    matrixInfoHeader = Struct('>2xHL')
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

class BatchAttrib(Readable):
    header = Struct('>LL')
    def read(self, fin):
        self.attrib, self.dataType = self.header.unpack(fin.read(8))

class Batch(Readable):
    header = Struct('>BxHHHH6x')
    def read(self, fin):
        self.matrixType, self.packetCount, self.offsetToAttribs, self.firstMatrixData, self.firstPacketLocation = self.header.unpack(fin.read(16))
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

    def __repr__(self):
        return "{}()".format(__class__.__name__)

class Shp1(Section):
    header = Struct('>H2xLL4xLLLLL')
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
        if currPrimitive.type == 0:
            break
        primitives.append(currPrimitive)

    return primitives



class Image(Readable):
    header = Struct('>BxHHBBxBHL4xBB2xBx2xL')
    def read(self, fin, start=None, textureHeaderOffset=None, texIndex=None):
        self.format, self.width, self.height, self.wrapS, self.wrapT, self.paletteFormat, \
            paletteNumEntries, paletteOffset, self.minFilter, self.magFilter, \
            self.mipmapCount, dataOffset = self.header.unpack(fin.read(32))
        self.mipmapCount = max(self.mipmapCount, 1)
        if self.format in (GX_TF_C4, GX_TF_C8, GX_TF_C14X2):
            self.hasAlpha = self.paletteFormat in (GX_TL_IA8, GX_TL_RGB5A3)
        else:
            self.hasAlpha = self.format in (GX_TF_IA4, GX_TF_IA8, GX_TF_RGB5A3, GX_TF_RGBA8)
        if start is not None:
            nextHeader = fin.tell()
            
            fin.seek(start+textureHeaderOffset+dataOffset+0x20*texIndex)
            self.data = readTextureData(fin, self.format, self.width, self.height, self.mipmapCount)
            
            if self.format in (GX_TF_C4, GX_TF_C8, GX_TF_C14X2):
                fin.seek(start+textureHeaderOffset+paletteOffset+0x20*texIndex)
                self.palette = readPaletteData(fin, self.paletteFormat, paletteNumEntries)
            else:
                self.palette = None
            
            fin.seek(nextHeader)
    
    def export(self, imageName):
        #im = bpy.data.images.new(self.name, self.width, self.height, alpha=self.hasAlpha)
        #decodeTextureBPY(im, self.data, self.format, self.width, self.height, self.paletteFormat, self.palette, mipmapCount=self.mipmapCount)
        imgs = decodeTexturePIL(self.data, self.format, self.width, self.height, self.paletteFormat, self.palette, mipmapCount=self.mipmapCount)
        imgs[0][0].save(imageName)
        im = bpy.data.images.load(imageName)
        im.pack()
        return im

    def __repr__(self):
        return "%s: %dx%d, fmt=%d, mips=%d" % (self.name, self.width, self.height, self.format, self.mipmapCount)

class Tex1(Section):
    headerCount = Struct('>H2x')
    headerOffsets = Struct('>LL')
    def read(self, fin, start, length):
        texCount, = self.headerCount.unpack(fin.read(self.headerCount.size))
        if texCount == 0:
            # JPA style
            name = fin.read(0x14)
            if name[0] == 0:
                textureNames = []
                textureHeaderOffset = 0
            else:
                textureNames = [name.decode('shift-jis').strip("\0")]
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
        formats = [ArrayFormat(fin) for i in range(numArrays)]
        j = 0
        for i in range(13):
            if offsets[i] == 0: continue
            currFormat = formats[j]
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
            if currFormat.dataType == 3: #s16 fixed point
                tmp = array('h')
                tmp.fromfile(fin, length//2)
                if sys.byteorder == 'little': tmp.byteswap()
                scale = .5**currFormat.decimalPoint
                data.extend([tmp[k]*scale for k in range(0, length//2)])
            elif currFormat.dataType == 4: #f32
                data.fromfile(fin, length//4)
                if sys.byteorder == 'little': data.byteswap()
            elif currFormat.dataType == 5: #rgb(a)
                tmp = array('B')
                tmp.fromfile(fin, length)
                data.extend([float(tmp[k]) for k in range(0, length)])
            else:
                warn("vtx1: unknown array data type %d"%dataType)
                j += 1
                continue

            #stuff floats into appropriate vertex array
            if currFormat.arrayType == 9: #positions
                if currFormat.componentCount == 0: #xy
                    self.positions = [None for i in range(len(data)/2)]
                    k = 0
                    for l in range(0, len(self.positions)):
                        self.positions[l] = Vector((data[k], data[k + 1], 0))
                        k += 2
                elif currFormat.componentCount == 1: #xyz
                    self.positions = [None for i in range(len(data)//3)]
                    k = 0
                    for l in range(0, len(self.positions)):
                        self.positions[l] = Vector((data[k], data[k + 1], data[k + 2]))
                        k += 3
                else:
                    warn("vtx1: unsupported componentCount for positions array: %d"%currFormat["componentCount"])
                    self.positions = []
            elif currFormat.arrayType == 0xa: #normals
                if currFormat.componentCount == 0: #xyz
                    self.normals = [None for i in range(len(data)//3)]
                    k = 0
                    for l in range(0, len(self.normals)):
                        self.normals[l] = Vector((data[k], data[k + 1], data[k + 2]))
                        k += 3
                else:
                    warn("vtx1: unsupported componentCount for normals array: %d"%currFormat["componentCount"])
            elif currFormat.arrayType in (0xb, 0xc): #color0,color1
                index = currFormat.arrayType-0xb
                if currFormat.componentCount == 0: #rgb
                    self.colors[index] = [None for i in range(len(data)//3)]
                    k = 0
                    for l in range(len(self.colors[index])):
                        self.colors[index][l] = (data[k], data[k + 1], data[k + 2])
                        k += 3
                elif currFormat.componentCount == 1: #rgba
                    self.colors[index] = [None for i in range(len(data)//4)]
                    k = 0
                    for l in range(len(self.colors[index])):
                        self.colors[index][l] = (data[k], data[k + 1], data[k + 2], data[k + 3])
                        k += 4
                else:
                    warn("vtx1: unsupported componentCount for colors array %d: %d"%
                        index, currFormat.componentCount)
            #texcoords 0 - 7
            elif currFormat.arrayType in (0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14):
                index = currFormat.arrayType - 0xd
                if currFormat.componentCount == 0: #s
                    self.texCoords[index] = [None for i in range(len(data))]
                    for l in range(0, len(self.texCoords[index])):
                        self.texCoords[index][l] = Vector((data[l], 0))
                elif currFormat.componentCount == 1: #st
                    self.texCoords[index] = [None for i in range(len(data)//2)]
                    k = 0
                    for l in range(0, len(self.texCoords[index])):
                        self.texCoords[index][l] = Vector((data[k], data[k + 1]))
                        k += 2
                else:
                    warn("vtx1: unsupported componentCount for texcoords array %d: %d"%index, currFormat.componentCount)

            else:
                warn("vtx1: unknown array type %d"%currFormat.arrayType)

            j += 1

class ArrayFormat(Readable):
    header = Struct('>LLLBBH')
    def read(self, fin):
        self.arrayType, self.componentCount, self.dataType, self.decimalPoint, self.unknown3, self.unknown4 = self.header.unpack(fin.read(16))



def computeSectionLengths(offsets, sizeOfSection):
    lengths = [None]*30
    for i in range(30):
        length = 0
        if offsets[i] != 0:
            next = sizeOfSection
            for j in range(i + 1, 30):
                if offsets[j] != 0:
                    next = offsets[j]
                    break
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

def flipY(vec):
    return Vector((vec.x, 1.0-vec.y))

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
                    f.material_index = bmd.mat3.indexToMatIndex[matIndex]
                    for j, hasColorLayer in enumerate(batch.hasColors):
                        if hasColorLayer:
                            layer = bm.loops.layers.color[str(j)]
                            f.loops[0][layer] = [c/255 for c in bmd.vtx1.colors[j][pa.colorIndex[j]]]
                            f.loops[1][layer] = [c/255 for c in bmd.vtx1.colors[j][pb.colorIndex[j]]]
                            f.loops[2][layer] = [c/255 for c in bmd.vtx1.colors[j][pc.colorIndex[j]]]
                    for j, hasTexLayer in enumerate(batch.hasTexCoords):
                        if hasTexLayer:
                            layer = bm.loops.layers.uv[str(j)]
                            f.loops[0][layer].uv = flipY(bmd.vtx1.texCoords[j][pa.texCoordIndex[j]])
                            f.loops[1][layer].uv = flipY(bmd.vtx1.texCoords[j][pb.texCoordIndex[j]])
                            f.loops[2][layer].uv = flipY(bmd.vtx1.texCoords[j][pc.texCoordIndex[j]])

                if curr.type == 0x98:
                    flip = not flip
                    a = b
                    b = c
                elif curr.type == 0xa0:
                    b = c
                else:
                    warn("Unknown primitive type %d"%curr.type)
                    continue

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
        mat = bmd.mat3.materials[bmd.mat3.indexToMatIndex[sg.index]]
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
    print("Importing textures")
    btextures = []
    if hasattr(bmd, "tex1"):
        for texture in bmd.tex1.textures:
            btex = bpy.data.textures.new(texture.name, 'IMAGE')
            if texture.wrapS == 0: btex.extension = 'EXTEND'
            elif texture.wrapS == 1: btex.extension = 'REPEAT'
            elif texture.wrapS == 2: btex.extension = 'CHECKER'
            btex.use_interpolation = texture.magFilter%2 == 1
            btex.filter_type = 'BOX'
            btex.use_mipmap = texture.magFilter >= 2
            btex.use_mipmap_gauss = texture.magFilter >= 4
            if texture.name in bpy.data.images:
                btex.image = bpy.data.images[texture.name]
            else:
                # look for a texture exported from bmdview
                imageName = filePath+"_tex"+texture.name+".tga"
                try:
                    btex.image = bpy.data.images.load(imageName)
                except RuntimeError as e:
                    pass
                if not btex.image:
                    dirName = "/tmp/" + bmd.name
                    imageName = dirName + "/" + texture.name + ".png"
                    try:
                        btex.image = bpy.data.images.load(imageName)
                    except RuntimeError as e:
                        pass
                    if not btex.image:
                        if not os.path.isdir(dirName): os.mkdir(dirName)
                        btex.image = texture.export(imageName)
                btex.image.name = texture.name
            btextures.append(btex)

    print("Importing materials")
    if hasattr(bmd, "mat3"):
        for i, mat in enumerate(bmd.mat3.materials):
            bmat = None
            m = i#bmd.mat3.indexToMatIndex.index(i) #XXX
            if False and bmd.mat3.materialNames[m] in bpy.data.materials:
                bmat = bpy.data.materials[bmd.mat3.materialNames[m]]
                mesh.materials.append(bmat)
                continue
            else:
                bmat = bpy.data.materials.new(bmd.mat3.materialNames[m])
            
            #bmat.diffuse_color = bmd.mat3.materialColor[mat.materialColor[0]]
            bmat.use_backface_culling = bmd.mat3.cullModes[mat.cullIndex] == 2

            bmat.use_nodes = True
            tree = bmat.node_tree
            tree.nodes.clear()
            
            placer = NodePlacer(tree)
            colorMatReg = []
            for j, colorMatIndex in enumerate(mat.materialColor):
                color = placer.addNode('ShaderNodeRGB')
                color.outputs[0].default_value = [c/255 for c in bmd.mat3.materialColor[colorMatIndex]]
                color.name = "Material color {}".format(j)
                color.label = "Material index {}".format(colorMatIndex)
                colorMatReg.append(color)
            colorAmbReg = []
            for j, colorAmbIndex in enumerate(mat.ambientColor):
                color = placer.addNode('ShaderNodeRGB')
                color.outputs[0].default_value = [c/255 for c in bmd.mat3.ambientColor[colorAmbIndex]]
                color.name = "Ambient color {}".format(j)
                color.label = "Ambient index {}".format(colorAmbIndex)
                colorAmbReg.append(color)
            colorVtxReg = []
            for j in range(2):
                reg = placer.addNode('ShaderNodeAttribute')
                reg.attribute_name = str(j)
                reg.name = "Vertex {}".format(j)
                colorVtxReg.append(reg)
            texGens = []
            for j, texGenIndex in enumerate(mat.texGenInfos):
                if texGenIndex < 0: continue
                texGen = bmd.mat3.texGenInfos[texGenIndex]
                node = None
                out = None
                if texGen.source == 0:
                    node = placer.addNode('ShaderNodeGeometry')
                    out = node.outputs['Position']
                elif texGen.source == 1:
                    node = placer.addNode('ShaderNodeGeometry')
                    out = node.outputs['Normal']
                elif texGen.source == 3:
                    node = placer.addNode('ShaderNodeGeometry')
                    out = node.outputs['Tangent']
                elif texGen.source >= 4 and texGen.source <= 11:
                    node = placer.addNode('ShaderNodeUVMap')
                    out = node.outputs['UV']
                    node.uv_map = str(texGen.source-4)
                if node is not None:
                    node.name = "Tex gen {}".format(j)
                    node.label = "Tex gen index {}".format(texGenIndex)
                texMtxIndex = mat.texMtxInfos[j]
                if texMtxIndex >= 0:
                    texMtx = bmd.mat3.texMtxInfos[texMtxIndex]
                    placer.nextColumn()
                    node = placer.addNode('ShaderNodeMapping')
                    node.vector_type = 'POINT'
                    node.translation = texMtx.translation+(0,)
                    node.rotation.z = texMtx.rotation # TODO what units
                    node.scale = texMtx.scale+(1,)
                    tree.links.new(out, node.inputs[0])
                    out = node.outputs[0]
                    placer.previousColumn()
                texGens.append(out)
            
            placer.nextColumn()
            lightChannels = []
            for j in range(bmd.mat3.numChans[mat.numChansIndex]):
                colorChannel = bmd.mat3.colorChanInfos[mat.chanControls[j*2]]
                #alphaChannel = bmd.mat3.colorChanInfos[mat.chanControls[j*2+1]]
                matSource = [colorMatReg, colorVtxReg][colorChannel.matColorSource][j]
                ambSource = [colorAmbReg, colorVtxReg][colorChannel.ambColorSource][j]
                if colorChannel.lightingEnabled:
                    if colorChannel.attenuationFunction in (0,2):
                        attn = placer.addNode('ShaderNodeRGB')
                        attn.outputs[0].default_value = (1.0,1.0,1.0,1.0)
                    elif colorChannel.attenuationFunction == 1:
                        attn = placer.addNode('ShaderNodeEeveeSpecular')
                        tree.links.new(matSource.outputs['Color'], attn.inputs[0])
                    elif colorChannel.attenuationFunction == 3:
                        attn = placer.addNode('ShaderNodeBsdfDiffuse')
                        tree.links.new(matSource.outputs['Color'], attn.inputs[0])
                    placer.nextColumn()
                    reg = placer.addNode('ShaderNodeAddShader')
                    reg.name = "Color channel {}".format(j)
                    reg.label = "Color channel index {}".format(mat.chanControls[j*2])
                    tree.links.new(ambSource.outputs['Color'], reg.inputs[0])
                    tree.links.new(attn.outputs[0], reg.inputs[1])
                    lightChannels.append(reg)
                    placer.previousColumn()
            
            placer.nextColumn()
            for j, tevStageIndex in enumerate(mat.tevStageInfo):
                if tevStageIndex < 0: continue
                stage = bmd.mat3.tevStageInfos[tevStageIndex]
            
            placer.nextColumn()
            if len(lightChannels) == 1:
                shout = placer.addNode('ShaderNodeOutputMaterial')
                tree.links.new(lightChannels[0].outputs['Shader'], shout.inputs[0])
            elif len(lightChannels) == 2:
                n = placer.addNode('ShaderNodeAddShader')
                placer.nextColumn()
                shout = placer.addNode('ShaderNodeOutputMaterial')
                tree.links.new(lightChannels[0].outputs['Shader'], n.inputs[0])
                tree.links.new(lightChannels[1].outputs['Shader'], n.inputs[1])
                tree.links.new(n.outputs[0], shout.inputs[0])

            mesh.materials.append(bmat) # XXX

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

def drawSkeleton(bmd, sg, arm, onDown=True, p=None, parent=None, indent=0):
    if p is None: p = Matrix.Identity(4)
    effP = p
    
    if sg.type == 0x10:
        f = bmd.jnt1.frames[sg.index]
        effP = updateMatrix(f, p)
        bone = arm.edit_bones[f.name]
        bone.head = Vector((0,0,0))
        bone.tail = Vector((0,0,8))
        bone.matrix = effP
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
    armObject.scale = Vector((1,1,1))/96
    armObject.rotation_euler = Vector((math.pi/2,0,math.pi/2))
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
    files = CollectionProperty(type=OperatorFileListElement, options={'HIDDEN', 'SKIP_SAVE'})
    directory = StringProperty(maxlen=1024, subtype='FILE_PATH', options={'HIDDEN', 'SKIP_SAVE'})

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

