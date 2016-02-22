import sys, struct
from struct import unpack, pack
from warnings import warn
from array import array
import os.path
import math, numpy
import transformations

BMD_TO_VTF_FMT = {
 1:  5, # I8
 3:  6, # A8_I8
 4:  4, # RGB565
14: 13  # DXT1
}
formatWidths = {
 0: .5,
 1:  1,
 2:  1,
 3:  2,
 4:  2,
 5:  1,
 6:  1,
 8: .5,
 9:  1,
10:  2,
14: .5
}
vtfFormatWidths = {
 8: 1,
 1: 4,
11: 4,
17: 2,
 3: 3,
10: 3,
19: 2,
21: 2,
12: 4,
18: 2,
16: 4,
13: .5,
20: .5,
14: 1,
15: 1,
 5: 1,
 6: 2,
 7: 1,
 4: 2,
 2: 3,
 9: 3,
25: 8,
24: 8,
 0: 4,
22: 2,
26: 4,
23: 4
}

def s3tc1ReverseByte(b):
    b1 = b & 0x3
    b2 = b & 0xc
    b3 = b & 0x30
    b4 = b & 0xc0
    return (b1 << 6) | (b2 << 2) | (b3 >> 2) | (b4 >> 6)

def getString(pos, f):
    t = f.tell()
    f.seek(pos)
    ret = ''

    c = f.read(1)
    while c != '\0':
        ret += c
        c = f.read(1)

    f.seek(t)

    return ret

def readstringtable(pos, f):
    dest = []
    oldPos = f.tell()

    f.seek(pos)

    count, = unpack('>H', f.read(2))
    f.seek(2, 1) #skip pad bytes

    for i in xrange(count):
        unknown, stringOffset = unpack('>HH', fin.read(4))
        s = getString(pos + stringOffset, f)
        dest.append(s)

    f.seek(oldPos)
    return dest

def computeSectionLengths(offsets, sizeOfSection):
    lengths = [None]*30
    for i in xrange(30):
        length = 0
        if offsets[i] != 0:
            next = sizeOfSection
            for j in xrange(i + 1, 30):
                if offsets[j] != 0:
                    next = offsets[j]
                    break
            length = next - offsets[i]
        lengths[i] = length
    return lengths

def dumpPacketPrimitives(attribs, dataSize, f):
    primitives = []
    done = False
    readBytes = 0

    while not done:
        type = ord(f.read(1))
        readBytes += 1

        if type == 0 or readBytes >= dataSize:
            done = True
            continue

        primitives.append(Primitive())
        currPrimitive = primitives[-1]
        currPrimitive.type = type

        count, = unpack('>H', fin.read(2))
        readBytes += 2

        currPrimitive.points = [Index() for jkl in xrange(count)]

        for j in xrange(count):
            currPoint = currPrimitive.points[j]

            for k in xrange(len(attribs)):
                #get value
                if attribs[k].dataType == 1: #s8
                    tmp = ord(f.read(1))
                    val = tmp
                    readBytes += 1

                elif attribs[k].dataType == 3: #s16
                    val, = unpack('>H', fin.read(2))
                    readBytes += 2

                else:
                    raise Exception("got invalid data type in packet. should never happen because dumpBatch() should check this before calling dumpPacket()")

                #set appropriate index
                if attribs[k].attrib == 0:
                    currPoint.matrixIndex = val

                elif attribs[k].attrib == 9:
                    currPoint.posIndex = val

                elif attribs[k].attrib == 0xa:
                    currPoint.normalIndex = val

                elif attribs[k].attrib in (0xb,  0xc):
                    currPoint.colorIndex[attribs[k].attrib - 0xb] = val

                elif attribs[k].attrib in (0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14):
                    currPoint.texCoordIndex[attribs[k].attrib - 0xd] = val

                else:
                    #assert(false && "shp1: got invalid attrib in packet. should never happen because "
                    #"dumpBatch() should check this before calling dumpPacket()")

                    pass #ignore unknown types, it's enough to warn() in dumpBatch
    return primitives

def dumpBatch(fin, baseOffset):
    # getBatchAttribs
    old = fin.tell()
    fin.seek(baseOffset+offsetToBatchAttribs+offsetToAttribs)
    attribs = []
    attrib, dataType = unpack('>LL', fin.read(8))
    while attrib != 0xff:
        a = Attrib()
        a.attrib = attrib
        a.dataType = dataType
        attribs.append(a)
        attrib, dataType = unpack('>LL', fin.read(8))
    fin.seek(old)
    # end getBatchAttribs
    hasMatrixIndices = hasPositions = hasNormals = False
    hasColors = [False]*2
    hasTexCoords = [False]*8
    packets = []
    for a in attribs:
        if a.dataType != 1 and a.dataType != 3:
            warn("shp1, dumpBatch(): unknown attrib data type %d, skipping batch" % attribs[i].dataType)
            return packets, hasMatrixIndices, hasPositions, hasNormals, hasColors, hasTexCoords
        if a.attrib == 0:
            hasMatrixIndices = True
            warn("Matrices unimplemented")
        elif a.attrib == 9:
            hasPositions = True
        elif a.attrib == 0xa:
            hasNormals = True
        elif a.attrib in (0xb, 0xc):
            hasColors[a.attrib - 0xb] = True
        elif a.attrib >= 0xd and a.attrib <= 0x14:
            hasTexCoords[a.attrib - 0xd] = True
        else:
            warn("shp1, dumpBatch(): unknown attrib %d in batch, it might not display correctly" % a.attrib)
    
    for j in xrange(packetCount):
        fin.seek(start+offsetToPacketLocations+(firstPacketLocation + j)*8)
        locationSize, locationOffset = unpack('>LL', fin.read(8))
        
        fin.seek(start+offsetData+locationOffset)
        primitives = dumpPacketPrimitives(attribs, locationSize, fin)
        
        fin.seek(start+offsetToMatrixData+(firstMatrixData+i)*8)
        count, firstIndex = unpack('>2xHL', fin.read(8))
        
        fin.seek(start+offsetToMatrixTable+2*firstIndex)
        matrixTable = array('H')
        matrixTable.fromfile(fin, count)
        matrixTable.byteswap()
        packets.append((primitives, matrixTable))
    
    return packets, hasMatrixIndices, hasPositions, hasNormals, hasColors, hasTexCoords

class material(object): pass
class Vector(object):
    def __init__(self, x=0.0, y=0.0, z=0.0):
        self.v = [x, y, z]
    def setXYZ(self, x, y, z):
        self.v[0] = x
        self.v[1] = y
        self.v[2] = z
    def transform(self, t):
        d = numpy.dot(t, self.v+[1])
        return Vector(*d[:3])

class TexCoord(object):
    def setST(self, s, t):
        self.s = s
        self.t = t
class Primitive(object): pass
class Index(object):
    def __init__(self):
        self.colorIndex = [-1]*2
        self.texCoordIndex = [-1]*8
class Attrib(object): pass
textureNames = None
texturesUseAlpha = {}
materials = []

fin = open(sys.argv[1], 'rb')
signature, fileLength, chunkCount, svr = unpack('>8sLL4s12x', fin.read(0x20))
if signature[:4] == "bres": fin.seek(0xa0, 1)

scenegraph_temp = []
joints = []

for chunkno in xrange(chunkCount):
    start = fin.tell()
    try: chunk, size = unpack('>4sL', fin.read(8))
    except struct.error:
        warn("File too small for chunk count of "+str(chunkCount))
        continue
    if chunk == "INF1":
        unknown1, unknown2, vertexCount, offsetToEntries = unpack('>H2xLLL', fin.read(16))
        fin.seek(start+offsetToEntries)
        scenegraph_temp = []
        indent = 0
        inftype, index = unpack('>HH', fin.read(4))
        while inftype != 0:
            scenegraph_temp.append((inftype, index))
            inftype, index = unpack('>HH', fin.read(4))
        #scenegraph = buildSceneGraph(scenegraph_temp)
    elif chunk == "VTX1":
        arrayFormatOffset, = unpack('>L', fin.read(4))
        offsets = unpack('>13L', fin.read(52))
        numArrays = 0
        for i in xrange(13):
            if offsets[i] != 0: numArrays += 1
        fin.seek(start+arrayFormatOffset)
        formats = [dict(zip(["arrayType", "componentCount", "dataType", "decimalPoint", "unknown3", "unknown4"], unpack('>LLLBBH', fin.read(16)))) for i in xrange(numArrays)]
        j = 0
        colors = [[], []]
        texCoords = [[] for i in xrange(8)]
        for i in xrange(13):
            if offsets[i] == 0: continue
            currFormat = formats[j]
            startOffset = offsets[i]
            length = size-startOffset
            for k in xrange(i+1, 13):
                if offsets[k] != 0:
                    length = offsets[k] - startOffset
                    break
            
            offset = start+offsets[i]
            fin.seek(offset)
            #convert array to float (so we have n + m cases, not n*m)
            data = array('f')
            if currFormat["dataType"] == 3: #s16 fixed point
                tmp = array('h')
                tmp.fromfile(fin, length/2)
                if sys.byteorder == 'little': tmp.byteswap()
                scale = .5**currFormat["decimalPoint"]
                data.extend([tmp[k]*scale for k in xrange(0, length/2)])
            elif currFormat["dataType"] == 4: #f32
                data.fromfile(fin, length/4)
                if sys.byteorder == 'little': data.byteswap()
            elif currFormat["dataType"] == 5: #rgb(a)
                tmp = array('B')
                tmp.fromfile(fin, length)
                data.extend([tmp[k] for k in xrange(0, len(data))])
            else:
                warn("vtx1: unknown array data type %d", dataType)
                j += 1
                continue
            
            #stuff floats into appropriate vertex array
            if currFormat["arrayType"] == 9: #positions
                if currFormat["componentCount"] == 0: #xy
                    positions = [Vector() for i in xrange(len(data)/2)]
                    k = 0
                    for l in xrange(0, len(positions)):
                        positions[l].setXYZ(data[k], data[k + 1], 0)
                        k += 2
                elif currFormat["componentCount"] == 1: #xyz
                    positions = [Vector() for i in xrange(len(data)/3)]
                    k = 0
                    for l in xrange(0, len(positions)):
                        positions[l].setXYZ(data[k], data[k + 1], data[k + 2])
                        k += 3
                else:
                    warn("vtx1: unsupported componentCount for positions array: %d", currFormat["componentCount"])
                    positions = []
            elif currFormat["arrayType"] == 0xa: #normals
                if currFormat["componentCount"] == 0: #xyz
                    normals = [Vector() for i in xrange(len(data)/3)]
                    k = 0
                    for l in xrange(0, len(normals)):
                        normals[l].setXYZ(data[k], data[k + 1], data[k + 2])
                        k += 3
                else:
                    warn("vtx1: unsupported componentCount for normals array: %d", currFormat["componentCount"])
            elif currFormat["arrayType"] in (0xb, 0xc): #color0,color1
                index = currFormat["arrayType"] - 0xb
                if currFormat["componentCount"] == 0: #rgb
                    colors[index] = [Color() for i in xrange(len(data)/3)]
                    k = 0
                    for l in xrange(0, len(colors[index])):
                        colors[index][l].setRGBA(data[k], data[k + 1], data[k + 2], 255.0)
                        k += 3
                elif currFormat["componentCount"] == 1: #rgba
                    colors[index] = [Color() for i in xrange(len(data)/4)]
                    k = 0
                    for l in xrange(0, len(colors[index])):
                        colors[index][l].setRGBA(data[k], data[k + 1], data[k + 2], data[k + 3])
                        k += 4
                else:
                    warn("vtx1: unsupported componentCount for colors array %d: %d",
                        index, currFormat["componentCount"])
            #texcoords 0 - 7
            elif currFormat["arrayType"] in (0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14):
                index = currFormat["arrayType"] - 0xd
                if currFormat["componentCount"] == 0: #s
                    texCoords[index] = [TexCoord() for i in xrange(len(data))]
                    for l in xrange(0, len(texCoords[index])):
                        texCoords[index][l].setST(data[l], 0)
                elif currFormat["componentCount"] == 1: #st
                    texCoords[index] = [TexCoord() for i in xrange(len(data)/2)]
                    k = 0
                    for l in xrange(0, len(texCoords[index])):
                        texCoords[index][l].setST(data[k], data[k + 1])
                        k += 2
                else:
                    warn("vtx1: unsupported componentCount for texcoords array %d: %d", index, currFormat["componentCount"])

            else:
                warn("vtx1: unknown array type %d", currFormat["arrayType"])
            
            j += 1
    elif chunk == "JNT1":
        count, jntEntryOffset, unknownOffset, stringTableOffset = unpack('>H2xLLL', fin.read(16))
        boneNames = readstringtable(start+stringTableOffset, fin)
        if len(boneNames) != count: warn("number of strings doesn't match number of joints")
        
        fin.seek(start+jntEntryOffset)
        joints = []
        for i in xrange(count):
            unknown, unknown3, sx, sy, sz, rx, ry, rz, tx, ty, tz, unknown2 = unpack('>HBxfffhhh2xffff', fin.read(40))
            rx = (rx*math.pi)/32768
            ry = (ry*math.pi)/32768
            rz = (rz*math.pi)/32768
            bbMin = unpack('>fff', fin.read(12))
            bbMax = unpack('>fff', fin.read(12))
            joints.append((sx, sy, sz, rx, ry, rz, tx, ty, tz))
    elif chunk == "SHP1":
        # header
        batchCount, offsetToBatches, offsetUnknown, offsetToBatchAttribs, offsetToMatrixTable, offsetData, offsetToMatrixData, offsetToPacketLocations = unpack('>H2xLL4xLLLLL', fin.read(36))
        # batches
        batches = []
        fin.seek(start+offsetToBatches)
        for i in xrange(batchCount):
            # readBatch
            matrixType, packetCount, offsetToAttribs, firstMatrixData, firstPacketLocation = unpack('>BxHHHH6x', fin.read(16))
            bbMin = unpack('>fff', fin.read(12))
            bbMax = unpack('>fff', fin.read(12))
            nextBatch = fin.tell()
            # end readBatch
            
            batches.append(dumpBatch(fin, start))
            
            fin.seek(nextBatch)
    elif chunk == "MAT3":
        count, pad = unpack('>HH', fin.read(4))
        offsets = unpack('>30L', fin.read(120))
                
        materialNames = readstringtable(start+offsets[2], fin)
        if count != len(materialNames):
            warn("mat3: number of strings (%d) doesn't match number of elements (%d)", len(materialNames), count)
        
        lengths = computeSectionLengths(offsets, size)
        
        fin.seek(start+offsets[1])
        indexToMatIndex = array('H')
        indexToMatIndex.fromfile(fin, count)
        if sys.byteorder == 'little': indexToMatIndex.byteswap()
        maxIndex = max(indexToMatIndex)
        
        fin.seek(start+offsets[4])
        cullModes = array('L')
        cullModes.fromfile(fin, lengths[4])
        if sys.byteorder == 'little': cullModes.byteswap()
        
        fin.seek(start+offsets[5])
        color1 = [unpack('>BBBB', fin.read(4)) for i in xrange(lengths[5]/4)]
        
        fin.seek(start+offsets[6])
        numChans = array('B')
        numChans.fromfile(fin, lengths[6])

        fin.seek(start+offsets[7])
        colorChanInfos = [dict(zip(["ambColorSource", "matColorSource", "litMask", "attenuationFracFunc", "diffuseAttenuationFunc"], unpack('>BBBBB3x', fin.read(8)))) for i in xrange(lengths[7]/8)]

        fin.seek(start+offsets[8])
        color2 = [unpack('>BBBB', fin.read(4)) for i in xrange(lengths[8]/4)]

        fin.seek(start+offsets[10])
        texGenCounts = array('B')
        texGenCounts.fromfile(fin, lengths[10])

        fin.seek(start+offsets[11])
        texGenInfos = [dict(zip(["texGenType", "texGenSrc", "matrix"], unpack('>BBBx', fin.read(4)))) for i in xrange(lengths[11]/4)]

        fin.seek(start+offsets[15])
        texStageIndexToTextureIndex = array('H')
        texStageIndexToTextureIndex.fromfile(fin, lengths[15]/2)
        texStageIndexToTextureIndex.byteswap()
        
        fin.seek(start+offsets[24])
        alphaCompares = [dict(zip(["comp0", "ref0", "alphaOp", "comp1", "ref1"], unpack('>BBBBB3x', fin.read(8)))) for i in xrange(lengths[24]/8)]

        fin.seek(start+offsets[25])
        blendInfos = [dict(zip(["blendMode", "srcFactor", "dstFactor", "logicOp"], unpack('>BBBB', fin.read(4)))) for i in xrange(lengths[25]/4)]
        
        fin.seek(start+offsets[26])
        zModes = [dict(zip(["enable", "func", "updateEnable"], unpack('>BBBx', fin.read(4)))) for i in xrange(lengths[26]/4)]
                
        fin.seek(start+offsets[0])
        materials = [None]*(maxIndex+1)
        for i in xrange(maxIndex+1):
            materials[i] = material()
            materials[i].flag, materials[i].cullIndex, materials[i].numChansIndex, materials[i].texGenCountIndex, materials[i].tevCountIndex, materials[i].zModeIndex = unpack('>BBBBBxBx', fin.read(8))
            materials[i].color1 = unpack('>2H', fin.read(4))
            materials[i].chanControls = unpack('>4H', fin.read(8))
  
            materials[i].color2 = unpack('>2H', fin.read(4))
            materials[i].lights = unpack('>8H', fin.read(16))
  
            materials[i].texGenInfos = unpack('>8H', fin.read(16))
            materials[i].texGenInfos2 = unpack('>8H', fin.read(16))
            materials[i].texMatrices = unpack('>10H', fin.read(20))
            materials[i].dttMatrices = unpack('>20H', fin.read(40))
            materials[i].texStages = unpack('>8H', fin.read(16))
            materials[i].color3 = unpack('>4H', fin.read(8))
            materials[i].constColorSel = unpack('>16B', fin.read(16))
            materials[i].constAlphaSel = unpack('>16B', fin.read(16))
            materials[i].tevOrderInfo = unpack('>16H', fin.read(32))
            materials[i].colorS10 = unpack('>4H', fin.read(8))
            materials[i].tevStageInfo = unpack('>16H', fin.read(32))
            materials[i].tevSwapModeInfo = unpack('>16H', fin.read(32))
            materials[i].tevSwapModeTable = unpack('>4H', fin.read(8))
            materials[i].unknown6 = unpack('>12H', fin.read(24))
            materials[i].alphaCompIndex, materials[i].blendIndex = unpack('>2xHH2x', fin.read(8))
            
    elif chunk == "TEX1":
        texCount, = unpack('>H2x', fin.read(4))
        if texCount == 0:
            # JPA style
            textureNames = [fin.read(0x14).strip('\0')]
            textureHeaderOffset = 0x20
        else:
            textureHeaderOffset, stringTableOffset = unpack('>LL', fin.read(8))
            try: textureNames = readstringtable(start+stringTableOffset, fin)
            except struct.error: textureNames = []
        fin.seek(start+textureHeaderOffset)
        wroteNames = []
        print "Reading", texCount, "textures"
        for i, name in enumerate(textureNames):
            format, width, height, wrapS, wrapT, paletteFormat, paletteNumEntries, paletteOffset, minFilter, magFilter, mipmapCount, dataOffset = unpack('>BxHHBBxBHL4xBB2xBx2xL', fin.read(32))
            
            texturesUseAlpha[i] = format in [2, 3, 5, 6]
            
            if width > height:
                lowResImageWidth = min(16, width)
                lowResImageHeight = (height*lowResImageWidth)/width
            else:
                lowResImageHeight = min(16, height)
                lowResImageWidth = (width*lowResImageHeight)/height
            lowResImageSize = (lowResImageWidth*lowResImageHeight)/2
            
            nextHeader = fin.tell()
            
            if name in wroteNames: continue
            wroteNames.append(name)
            
            if format in BMD_TO_VTF_FMT:
                vtfFormat = BMD_TO_VTF_FMT[format]
            elif format == 0:
                vtfFormat = 5
            elif format == 2:
                vtfFormat = 6
            elif format == 5:
                vtfFormat = 0
            else:
                warn("Unknown format 0x%x"%format)
                continue
            
            mipmapCount = max(mipmapCount, 1)
            
            print "%s @ 0x%X: %dx%d, fmt=%d, mips=%d" % (name, start+textureHeaderOffset+dataOffset, width, height, format, mipmapCount)
            
            flags = 0
            if wrapS == 0: flags |= 0x04
            if wrapT == 0: flags |= 0x08
            if magFilter == 0: flags |= 0x01
            
            fin.seek(start+textureHeaderOffset+dataOffset+0x20*i)
            
            mipData = [None]*mipmapCount
            mipwidth = width
            mipheight = height
            lowResIndex = -1
            for mip in xrange(mipmapCount):
                if format == 13 and mipwidth == lowResImageWidth and mipheight == lowResImageHeight:
                    lowResIndex = mip
                vtfImageSize = int((mipwidth*mipheight)*vtfFormatWidths[vtfFormat])
                imageSize = int((mipwidth*mipheight)*formatWidths[format])
                dest = [0]*vtfImageSize
                if format == 0:
                    for y in xrange(0, mipheight, 8):
                        for x in xrange(0, mipwidth, 8):
                            for dy in xrange(8):
                                for dx in xrange(0, 8, 2):
                                    if x + dx < mipwidth and y + dy < mipheight:
                                        c = ord(fin.read(1))
                                        #http://www.mindcontrol.org/~hplus/graphics/expand-bits.html
                                        t = c & 0xf0
                                        dest[mipwidth*(y + dy) + x + dx] = t | (t >> 4)
                                        t = c & 0xf
                                        dest[mipwidth*(y + dy) + x + dx + 1] = (t << 4) | t
                elif format == 1:
                    for y in xrange(0, mipheight, 4):
                        for x in xrange(0, mipwidth, 8):
                            for dy in xrange(4):
                                for dx in xrange(8):
                                    dest[mipwidth*(y + dy) + x + dx] = ord(fin.read(1))
                elif format == 2:
                    for y in xrange(0, mipheight, 4):
                        for x in xrange(0, mipwidth, 8):
                            for dy in xrange(4):
                                for dx in xrange(8):
                                    c = ord(fin.read(1))
                                    lum = c & 0xf
                                    lum |= lum << 4
                                    alpha = c & 0xf0
                                    alpha |= (alpha >> 4)
                                    dest[2*(mipwidth*(y + dy) + x + dx)] = lum
                                    dest[2*(mipwidth*(y + dy) + x + dx) + 1] = alpha
                elif format == 3:
                    for y in xrange(0, mipheight, 4):
                        for x in xrange(0, mipwidth, 4):
                            for dy in xrange(4):
                                for dx in xrange(4):
                                    c1, c2 = ord(fin.read(1)), ord(fin.read(1))
                                    if x + dx < mipwidth and y + dy < mipheight:
                                        di = 2*(mipwidth*(y + dy) + x + dx)
                                        dest[di + 1] = c1
                                        dest[di + 0] = c2
                elif format == 4:
                    for y in xrange(0, mipheight, 4):
                        for x in xrange(0, mipwidth, 4):
                            for dy in xrange(4):
                                for dx in xrange(4):
                                    di = 2*(mipwidth*(y + dy) + x + dx)
                                    rgb, = unpack('>H', fin.read(2))
                                    r = (rgb & 0xf100) >> 11
                                    g = (rgb & 0x7e0) >> 5
                                    b = (rgb & 0x1f)
                                    bgr = (b << 11) | (g << 5) | r
                                    dest[di + 0] = bgr&0xff
                                    dest[di + 1] = (bgr&0xff00)>>8
                elif format == 5:
                    for y in xrange(0, mipheight, 4):
                        for x in xrange(0, mipwidth, 4):
                            for dy in xrange(4):
                                for dx in xrange(4):
                                    if x + dx < mipwidth and y + dy < mipheight:
                                        c, = unpack('>H', fin.read(2))
                                        if (c & 0x8000) == 0x8000:
                                            a = 0xff
                                            r = (c & 0x7c00) >> 10
                                            r = (r << (8-5)) | (r >> (10-8))
                                            g = (c & 0x3e0) >> 5
                                            g = (g << (8-5)) | (g >> (10-8))
                                            b = c & 0x1f
                                            b = (b << (8-5)) | (b >> (10-8))
                                        else:
                                            a = (c & 0x7000) >> 12
                                            a = (a << (8-3)) | (a << (8-6)) | (a >> (9-8))
                                            r = (c & 0xf00) >> 8
                                            r = (r << (8-4)) | r
                                            g = (c & 0xf0) >> 4
                                            g = (g << (8-4)) | g
                                            b = c & 0xf
                                            b = (b << (8-4)) | b
                                        dest[4*(mipwidth*(y + dy) + x + dx)] = r
                                        dest[4*(mipwidth*(y + dy) + x + dx) + 1] = g
                                        dest[4*(mipwidth*(y + dy) + x + dx) + 2] = b
                                        dest[4*(mipwidth*(y + dy) + x + dx) + 3] = a
                elif format == 14:
                    for y in xrange(0, mipheight/4, 2):
                        for x in xrange(0, mipwidth/4, 2):
                            for dy in xrange(2):
                                for dx in xrange(2):
                                    for k in xrange(8):
                                        dest[8*((y + dy)*mipwidth/4 + x + dx) + k] = ord(fin.read(1))
                    for k in xrange(0, mipwidth*mipheight/2, 8):
                        a = dest[k]
                        dest[k] = dest[k+1]
                        dest[k+1] = a
                        a = dest[k+2]
                        dest[k+2] = dest[k+3]
                        dest[k+3] = a
                        dest[k+4] = s3tc1ReverseByte(dest[k+4])
                        dest[k+5] = s3tc1ReverseByte(dest[k+5])
                        dest[k+6] = s3tc1ReverseByte(dest[k+6])
                        dest[k+7] = s3tc1ReverseByte(dest[k+7])
                else:
                    dest = map(ord, fin.read(imageSize))
                mipData[mip] = dest
                mipwidth /= 2
                mipheight /= 2
            mipData.reverse()
            lowResFormat = -1 if lowResIndex == -1 else 13
            fout = open(name+'.vtf', 'wb')
            fout.write("VTF\0")
            fout.write(pack('<LLLHHLHH4x3f4xfLBlBBH', 7, 2, 80, width, height, flags, 1, 0, 1.0, 1.0, 1.0, 1.0, vtfFormat, mipmapCount, lowResFormat, lowResImageWidth, lowResImageHeight, 1))
            if lowResIndex != -1:
                for c in mipData[0]:
                    fout.write(chr(c))
            # ???
            fout.write('\0\0\0')
            fout.write('\0\0\0\0\0\0\0\0\0\0\0\0')
            for dest in mipData:
                for c in dest:
                    fout.write(chr(c))
            fout.close()
            fin.seek(nextHeader)
    
    elif chunk == "EVP1":
        count, pad, boneCountOffset, weightedIndicesOffset, boneWeightsTableOffset, matrixTableOffset = unpack('>HH4L', fin.read(20))
        
        fin.seek(start+boneCountOffset)
        counts = array('B')
        counts.fromfile(fin, count)
        
        fin.seek(start+weightedIndicesOffset)
        weightedIndices = []
        for i in xrange(count):
            weightedIndices.append(array('H'))
            weightedIndices[i].fromfile(fin, counts[i])
            weightedIndices[i].byteswap()
        numMatrices = max(map(max, weightedIndices))+1 if count > 0 else 0
        
        fin.seek(start+boneWeightsTableOffset)
        weightedWeights = []
        for i in xrange(count):
            weightedWeights.append(array('f'))
            weightedWeights[i].fromfile(fin, counts[i])
            weightedWeights[i].byteswap()
        
        fin.seek(start+matrixTableOffset)
        matrices = []
        for i in xrange(count):
            m = [[0.0]*4]*3
            for j in xrange(3):
                for k in xrange(4):
                    m[j][k], = unpack('>f', fin.read(4))
            m.append([0.0, 0.0, 0.0, 1.0])
            matrices.append(m)
        
    elif chunk == "DRW1":
        count, offsetToIsWeighted, offsetToData = unpack('>H2xLL', fin.read(12))
        fin.seek(start+offsetToIsWeighted)
        bisWeighted = array('B')
        bisWeighted.fromfile(fin, count)
        isWeighted = list(bisWeighted)
        for i in xrange(len(isWeighted)):
            if bisWeighted[i] == 0: isWeighted[i] = False
            elif bisWeighted[i] == 1: isWeighted[i] = True
            else: raise Exception("unexpected value in isWeighted array: %d", bisWeighted[i])
        
        fin.seek(start+offsetToData)
        drwdata = array('H')
        drwdata.fromfile(fin, count)
        drwdata.byteswap()
            
    else:
        warn("Unsupported section \'%s\'" % chunk)
    fin.seek(start+size)

for i, mat in enumerate(materials):
    string = None
    for m in xrange(len(indexToMatIndex)):
        if indexToMatIndex[m] == i:
            string = materialNames[m]
    
    texNames = [None]*len(mat.texStages)
    for i, stage in enumerate(mat.texStages):
        if stage != 0xffff:
            v2 = texStageIndexToTextureIndex[stage]
            texNames[i] = textureNames[v2]

    fout = open(string+".vmt", 'w')
    fout.write("LightmappedGeneric\n")
    fout.write("{\n")
    
    if texNames[0] != None: fout.write("\t$basetexture "+texNames[0]+"\n")
    # TODO: Figure out what determines what a texture does
    #if texNames[1] != None: pass#fout.write("\t$lightwarptexture "+texNames[1]+"\n")
    #if texNames[2] != None: warn("Don't know what to do with 3rd texture "+texNames[2]+" ("+string+")")
    if colorChanInfos[mat.chanControls[0]]["matColorSource"] != 1: fout.write("\t$color \"{ "+' '.join(map(str, color1[mat.color1[0]]))+" }\"\n")
    if mat.cullIndex != 0xff and cullModes[mat.cullIndex] == 0: fout.write("\t$nocull 1\n")
    if mat.zModeIndex != 0xff and zModes[mat.zModeIndex]["enable"] == 0: fout.write("\t$ignorez 1\n")
    print string,
    if mat.alphaCompIndex < len(alphaCompares):
        ac = alphaCompares[mat.alphaCompIndex]
        print ac,
        if ac["alphaOp"] != 0 and ac["alphaOp"] != 1 or (ac["comp0"] != ac["comp1"] or ac["ref0"] != ac["ref1"]) and (ac["comp1"] != 3 or ac["ref1"] != 255):
            pass
        #elif ac["comp0"] != 7:
            #fout.write("\t$alpha "+str(ac["ref0"]/255.0)+"\n")
    if mat.blendIndex != 0xff:
        print blendInfos[mat.blendIndex],
        if blendInfos[mat.blendIndex]["srcFactor"] == 1 and blendInfos[mat.blendIndex]["dstFactor"] == 1:
            fout.write("\t$additive 1\n")
    if i in texturesUseAlpha and texturesUseAlpha[i]:
        fout.write("\t$alphatest 1\n")
    print
    
    fout.write("}\n")
    fout.close()

fin.close()

def bmd2smdcoords(x, y, z):
    return z, x, y

def writeline(smdout, parentbone, pa, hasMatrixIndices, hasPositions, hasNormals, hasColors, hasTexCoords, patchMatrixTable, matrixTable):
    smdout.write(str(parentbone))
    p = positions[pa.posIndex]
    if hasMatrixIndices:
        (sx, sy, sz, rx, ry, rz, tx, ty, tz) = (0.0,)*9
        pa.matrixIndex /= 3
        if pa.matrixIndex < len(weightedIndices):
            pairs = zip(weightedIndices[pa.matrixIndex], weightedWeights[pa.matrixIndex])
            for index, weight in pairs:
                tx += joints[index][6]*weight
                ty += joints[index][7]*weight
                tz += joints[index][8]*weight
        (sx, sy, sz, rx, ry, rz, tx, ty, tz) = joints[parentbone]
    else: (sx, sy, sz, rx, ry, rz, tx, ty, tz) = joints[parentbone]
    if hasPositions:
        smdout.write(" %f %f %f" % bmd2smdcoords(p.v[0]+tx, p.v[1]+ty, p.v[2]+tz))
    else:
        smdout.write(" %f %f %f" % (0, 0, 0))
    if hasNormals:
        smdout.write(" %f %f %f" % bmd2smdcoords(normals[pa.normalIndex].v[0], normals[pa.normalIndex].v[1], normals[pa.normalIndex].v[2]))
    else:
        smdout.write(" %f %f %f" % (0, 0, 0))
    if hasTexCoords[0]:
        smdout.write(" %f %f"%(texCoords[0][pa.texCoordIndex[0]].s, \
        1.0-texCoords[0][pa.texCoordIndex[0]].t))
    else:
        smdout.write(" %f %f" % (0, 0))
    if hasMatrixIndices:
        if pa.matrixIndex < len(weightedIndices):
            smdout.write(" %d" % len(pairs))
            for index, weight in pairs:
                smdout.write(" %d %f" % (index, weight))
    smdout.write('\n')

def localMatrix(i):
    (sx, sy, sz, rx, ry, rz, tx, ty, tz) = joints[i]
    return transformations.compose_matrix((sx, sy, sz), None, (rx, ry, rz), (tx, ty, tz), None)

def updateMatrixTable(patchMatrixTable, matrixTable):
    for n, index in enumerate(patchMatrixTable):
        if index != 0xffff and index < len(isWeighted): #this means keep old entry
            if isWeighted[index]:
                #TODO: the EVP1 data should probably be used here,
                #figure out how this works (most files look ok
                #without this, but models/ji.bdl is for example
                #broken this way)
                #matrixTable[n] = def

                #the following _does_ the right thing...it looks
                #ok for all files, but i don't understand why :-P
                #(and this code is slow as hell, so TODO: fix this)

                #NO idea if this is right this way...
                m = numpy.zeros((4,4))
                mm = weightedIndices[drwdata[index]]
                mmw = weightedWeights[drwdata[index]]
                for r in xrange(len(mm)):
                    sm1 = matrices[mm[r]]
                    sm2 = localMatrix(mm[r])
                    m += mmw[r]*numpy.dot(sm2, sm1)
                m[3][3] = 1

                matrixTable.append(m)
            else:
                sx, sy, sz, rx, ry, rz, tx, ty, tz = joints[drwdata[index]]
                matrixTable.append(transformations.compose_matrix((sx, sy, sz), None, (rx, ry, rz), (tx, ty, tz), None))

def traverseScenegraph(sg, matname="Material", indent=0, starting=0, parentbone=-1, smdout=None):
    i = starting
    newparentbone = parentbone
    while i < len(sg):
        (inftype, index) = sg[i]
        if inftype == 1:
            i = traverseScenegraph(sg, matname, indent+1, i+1, newparentbone, smdout)
        elif inftype == 2:
            return i
        elif inftype == 0x10:
            newparentbone = index
        elif inftype == 0x11:
            matname = materialNames[index]
        elif inftype == 0x12:
            patches, hasMatrixIndices, hasPositions, hasNormals, hasColors, hasTexCoords = batches[index]
            matrixTable = []
            for primitives, patchMatrixTable in patches:
                #updateMatrixTable(patchMatrixTable, matrixTable)
                # draw packet
                for curr in primitives:
                    a = 0
                    b = 1
                    flip = True
                    for c in xrange(2, len(curr.points)):
                        smdout.write(matname+"\n")
                        #smdout.write("tools/toolsnodraw\n")
                        pa, pb, pc = curr.points[a], curr.points[b], curr.points[c]

                        if flip:
                            x = pa
                            pa = pb
                            pb = x
                        
                        writeline(smdout, parentbone, pa, hasMatrixIndices, hasPositions, hasNormals, hasColors, hasTexCoords, patchMatrixTable, matrixTable)
                        writeline(smdout, parentbone, pb, hasMatrixIndices, hasPositions, hasNormals, hasColors, hasTexCoords, patchMatrixTable, matrixTable)
                        writeline(smdout, parentbone, pc, hasMatrixIndices, hasPositions, hasNormals, hasColors, hasTexCoords, patchMatrixTable, matrixTable)
                        
                        if curr.type == 0x98:
                            flip = not flip
                            a = b
                            b = c
                        elif curr.type == 0xa0:
                            b = c
                        else:
                            warn("Unknown primitive type %d"%curr.type)
                            continue
        i += 1
    return i

def traverseScenegraphBones(sg, starting=0, parentbone=-1, smdout=None):
    i = starting
    newparentbone = parentbone
    while i < len(sg):
        (inftype, index) = sg[i]
        if inftype == 1:
            i = traverseScenegraphBones(sg, i+1, newparentbone, smdout)
        elif inftype == 2:
            return i
        elif inftype == 0x10:
            smdout.write('%d "%s" %d\n' % (index, boneNames[index], parentbone))
            newparentbone = index
        i += 1

def writeSMDHeader(smdout):
    smdout.write("version 1\n")

    smdout.write("nodes\n")
    traverseScenegraphBones(scenegraph_temp, smdout=smdout)
    smdout.write("end\n")

    smdout.write("skeleton\ntime 0\n")
    for i, (sx, sy, sz, rx, ry, rz, tx, ty, tz) in enumerate(joints):
        smdout.write("%d %f %f %f %f %f %f\n" % (i, tx,ty,tz, rx,ry,rz))
    smdout.write("end\n")

useMultipleSMD = False#len(materialNames) > 32

smdname = os.path.splitext(sys.argv[1])[0]
if useMultipleSMD:
    smdout=None
else:
    smdout = open(smdname+".smd", 'w')
    writeSMDHeader(smdout)
    smdout.write("triangles\n")
traverseScenegraph(scenegraph_temp, smdout=smdout)
if not useMultipleSMD:
    smdout.write("end\n")
    smdout.close()
