from bmd import *
from ctypes import *
from struct import *
from math import *
from array import array
import string
import os.path
import unityparser
from unityassets import *
from binascii import crc32
from PIL import Image

fmtCTypes = {
    CompSize.U8:  c_ubyte,
    CompSize.S8:  c_byte,
    CompSize.U16: c_ushort,
    CompSize.S16: c_short,
    CompSize.F32: c_float
}

class kVertexFormat:
    Float = 0
    Float16 = 1
    Color = 2
    UNorm8 = 3
    SNorm8 = 4
    UNorm16 = 5
    SNorm16 = 6
    UInt8 = 7
    SInt8 = 8
    UInt16 = 9
    SInt16 = 10
    UInt32 = 11
    SInt32 = 12

fmtUTypes = {
    CompSize.U8:  kVertexFormat.UNorm8,
    CompSize.S8:  kVertexFormat.SNorm8,
    CompSize.U16: kVertexFormat.UNorm16,
    CompSize.S16: kVertexFormat.SNorm16,
    CompSize.F32: kVertexFormat.Float
}

fmtStructTypes = {
    CompSize.U8:  'B',
    CompSize.S8:  'b',
    CompSize.U16: 'H',
    CompSize.S16: 'h',
    CompSize.F32: 'f'
}

def splitVertexArray(arr, count):
    return [tuple([arr[i*count+j] for j in range(count)]) for i in range(len(arr)//count)]

def floatToHalf(v):
    ui, = unpack('I', pack('f', v))
    
    s = (ui >> 16) & 0x8000
    em = ui & 0x7fffffff
    
    # bias exponent and round to nearest; 112 is relative exponent bias (127-15)
    h = (em - (112 << 23) + (1 << 12)) >> 13

    # underflow: flush to zero; 113 encodes exponent -14
    h = 0 if (em < (113 << 23)) else h

    # overflow: infinity; 143 encodes exponent 16
    h = 0x7c00 if (em >= (143 << 23)) else h

    # NaN; note that we convert all types of NaN to qNaN
    h = 0x7e00 if (em > (255 << 23)) else h

    return s | h

# https://stackoverflow.com/questions/6162651/half-precision-floating-point-in-java/6162687#6162687
def halfToFloat(hbits):
    mant = hbits & 0x03ff               # 10 bits mantissa
    exp =  hbits & 0x7c00               # 5 bits exponent
    if exp == 0x7c00:                   # NaN/Inf
        exp = 0x3fc00                   # -> NaN/Inf
    elif exp != 0:                      # normalized value
        exp += 0x1c000                  # exp - 15 + 127
        if mant == 0 and exp > 0x1c400: # smooth transition
            return struct.unpack('f', struct.pack('I', ( hbits & 0x8000 ) << 16 | exp << 13))[0]
    elif mant != 0:                     # && exp==0 -> subnormal
        exp = 0x1c400                   # make it normal
        while True:
            mant <<= 1                  # mantissa * 2
            exp -= 0x400                # decrease exp by 1
            if ( mant & 0x400 ) != 0:   # while not normal
                break
        mant &= 0x3ff                   # discard subnormal bit
                                        # else +/-0 -> +/-0
    return struct.unpack('f',
        struct.pack('I',                # combine all parts
            ( hbits & 0x8000 ) << 16 |  # sign  << ( 31 - 15 )
            ( exp | mant ) << 13        # value << ( 23 - 10 )
        )
    )[0]

def getBatchTriangles(batch, indexMap):
    matrixTable = [(Matrix(), [], []) for i in range(10)]
    for shapeDraw, shapeMatrix in batch.matrixGroups:
        for primitive in shapeDraw.primitives:
            a = 0
            b = 1
            flip = True
            for c in range(2, len(primitive.points)):
                pa, pb, pc = primitive.points[a], primitive.points[b], primitive.points[c]

                if flip:
                    x = pa
                    pa = pb
                    pb = x
                
                yield indexMap[pa.indices]
                yield indexMap[pb.indices]
                yield indexMap[pc.indices]
                
                if primitive.type == PrimitiveType.TRIANGLESTRIP:
                    flip = not flip
                    a = b
                    b = c
                elif primitive.type == PrimitiveType.TRIANGLEFAN:
                    b = c
                else:
                    warn("Unknown primitive type %s"%primitive.type)
                    break

Mesh = unityparser.constants.UnityClassIdMap.get_or_create_class_id(43, 'Mesh')
Material = unityparser.constants.UnityClassIdMap.get_or_create_class_id(21, 'Material')

def transformVerts(bmd, batches, positions, normals=None):
    transformedPositions = [Vector() for p in positions]
    if normals is None:
        transformedNormals = None
    else:
        transformedNormals = [Vector() for p in normals]
    for batch in batches:
        matrixTable = [(Matrix(), [], []) for i in range(10)]
        for mat, mmi, mmw in matrixTable:
            mat.identity()
        for i, (shapeDraw, shapeMatrix) in enumerate(batch.matrixGroups):
            updateMatrixTable(bmd, shapeMatrix, matrixTable)
            mat, mmi, mmw = matrixTable[0]
            for curr in shapeDraw.primitives:
                for p in curr.points:
                    if batch.hasMatrixIndices:
                        mat, mmi, mmw = matrixTable[p.matrixIndex//3]
                    if batch.hasPositions:
                        transformedPositions[p.posIndex] = mat@positions[p.posIndex]
                    if batch.hasNormals:
                        transformedNormals[p.normalIndex] = (mat@normals[p.normalIndex].resized(4)).resized(3)
    return transformedPositions, transformedNormals

def setupChannels(formats, originalData, asFloat, weightedIndices, weightedWeights, transformedPositionsArray, transformedNormalsArray, doBones):
    fields = []
    vertexStruct = ['<']
    uChannels = [{"stream": 0, "offset": 0, "format": 0, "dimension": 0} for i in range(14)]
    dataForArrayType = [None]*21
    
    offset = 0

    for fmt, original, asFloat in zip(formats, originalData, asFloat):
        if fmt is None: continue
        if fmt.arrayType == VtxAttr.POS:
            count = {CompType.POS_XY: 2, CompType.POS_XYZ: 3}[fmt.componentCount]
            channel = 0
        elif fmt.arrayType == VtxAttr.NRM:
            count = {CompType.NRM_XYZ: 3}[fmt.componentCount]
            channel = 1
        elif fmt.arrayType == VtxAttr.CLR0:
            count = {CompType.CLR_RGB: 3, CompType.CLR_RGBA: 4}[fmt.componentCount]
            channel = 3
        elif fmt.arrayType == VtxAttr.CLR1:
            raise NotImplementedError()
        elif fmt.arrayType.value >= VtxAttr.TEX0.value and fmt.arrayType.value <= VtxAttr.TEX7.value:
            count = {CompType.TEX_S: 1, CompType.TEX_ST: 2}[fmt.componentCount]
            channel = 4+(fmt.arrayType.value-VtxAttr.TEX0.value)
        else:
            raise ValueError(fmt.arrayType)
        uChannels[channel]["dimension"] = count
        uChannels[channel]["offset"] = offset
        assert dataForArrayType[fmt.arrayType.value] is None
        if doBones and fmt.arrayType in (VtxAttr.POS, VtxAttr.NRM):
            if fmt.arrayType == VtxAttr.POS:
                if fmt.componentCount != CompType.POS_XYZ: raise ValueError()
                arr = transformedPositionsArray
            elif fmt.arrayType == VtxAttr.NRM:
                assert fmt.componentCount == CompType.NRM_XYZ
                arr = transformedNormalsArray
            ctype = c_float
            vertexStruct.append(str(count)+'f')
            uChannels[channel]["format"] = kVertexFormat.Float
        elif (fmt.arrayType not in (VtxAttr.CLR0, VtxAttr.CLR1) and \
                (\
                 (fmt.dataType == CompSize.F32) or \
                 (fmt.dataType == CompSize.U8 and fmt.decimalPoint == 8) or \
                 (fmt.dataType == CompSize.S8 and fmt.decimalPoint == 7) or \
                 (fmt.dataType == CompSize.U16 and fmt.decimalPoint == 16) or \
                 (fmt.dataType == CompSize.S16 and fmt.decimalPoint == 15) \
                )):
            arr = original
            ctype = fmtCTypes[fmt.dataType]
            vertexStruct.append(str(count)+fmtStructTypes[fmt.dataType])
            uChannels[channel]["format"] = fmtUTypes[fmt.dataType]
        elif fmt.arrayType in (VtxAttr.CLR0, VtxAttr.CLR1) and \
              (fmt.dataType in (CompSize.RGB8, CompSize.RGBX8, CompSize.RGBA8)):
            arr = original
            ctype = c_ubyte
            vertexStruct.append(str(count)+'B')
            uChannels[channel]["format"] = kVertexFormat.Color
        elif (fmt.dataType != CompSize.F32) and \
              (log2(max(original)-min(original)) <= 11):
            arr = list(map(floatToHalf, asFloat))
            ctype = c_ushort
            vertexStruct.append(str(count)+'H')
            uChannels[channel]["format"] = kVertexFormat.Float16
        else:
            arr = asFloat
            ctype = c_float
            vertexStruct.append(str(count)+'f')
            uChannels[channel]["format"] = kVertexFormat.Float
        fields.extend([ctype]*count)
        offset += sizeof(ctype)*count
        
        #formatForArrayType[fmt.arrayType.value] = fmt
        dataForArrayType[fmt.arrayType.value] = splitVertexArray(arr, count)

    if len(weightedIndices) == 0:
        maxWeightCount = 0
    else:
        maxWeightCount = max(map(len, weightedIndices))
    boneIndices = weights = None
    if doBones:
        if maxWeightCount == 0:
            maxWeightCount = 1
            weights = [(1.0,)]*len(weightedIndices)
        else:
            weights = [tuple(v)+(0.0,)*(maxWeightCount-len(v)) for v in weightedWeights]
        boneIndices = [tuple(v)+(0,)*(maxWeightCount-len(v)) for v in weightedIndices]
    
        count = maxWeightCount
        channel = 12
        
        uChannels[channel]["dimension"] = count
        uChannels[channel]["offset"] = offset
        
        arr = weights
        ctype = c_float
        vertexStruct.append(str(count)+'f')
        uChannels[channel]["format"] = kVertexFormat.Float
        
        fields.extend([ctype]*count)
        offset += sizeof(ctype)*count
        
        count = maxWeightCount
        channel = 13
        
        uChannels[channel]["dimension"] = count
        uChannels[channel]["offset"] = offset
        
        arr = boneIndices
        ctype = c_byte
        vertexStruct.append(str(count)+'b')
        uChannels[channel]["format"] = kVertexFormat.SInt8
        
        fields.extend([ctype]*maxWeightCount)
        offset += sizeof(ctype)*count
        #dataForArrayType[0] = splitVertexArray(arr, count)
    elif maxWeightCount == 0:
        maxWeightCount = 1

    vertexStruct = Struct(''.join(vertexStruct))
    class MyVertexFormat(Structure):
        _pack_ = 1
        _fields_ = list(zip(string.ascii_letters, fields))
    assert sizeof(MyVertexFormat) == vertexStruct.size, (MyVertexFormat._fields_, sizeof(MyVertexFormat), vertexStruct.format, vertexStruct.size)
    
    return vertexStruct, uChannels, maxWeightCount, MyVertexFormat, dataForArrayType, boneIndices, weights

def collectVertices(batches, maxWeightCount, dataForArrayType, doBones, isWeighted, weightData, transformedPositions, transformedNormals, boneIndices, weights):
    uniqueVertices = []
    indexMap = {}
    for batch in batches:
        for shapeDraw, shapeMatrix in batch.matrixGroups:
            mmi = [0]*maxWeightCount
            mmw = [1.0]+[0.0]*(maxWeightCount-1)
            for primitive in shapeDraw.primitives:
                for point in primitive.points:
                    if point.indices not in indexMap:
                        uniqueVertex = []
                        for arrayType in range(1, 21):
                            data = dataForArrayType[arrayType]
                            if point.indices[arrayType] == INVALID_INDEX and data is None:
                                pass
                            elif point.indices[arrayType] == INVALID_INDEX and data is not None:
                                uniqueVertex.extend((0,)*len(data[0]))
                            elif data is None:
                                raise ValueError("{} references a vertex format {} that doesn't exist".format(primitive, arrayType))
                            else:
                                if doBones:
                                    isint = isinstance(data[0][0], int)
                                    if arrayType == VtxAttr.POS.value:
                                        data = transformedPositions
                                    elif arrayType == VtxAttr.NRM.value:
                                        data = transformedNormals
                                    if isint and data in (VtxAttr.POS.value, VtxAttr.NRM.value): data = [tuple(map(int, v)) for v in data]
                                uniqueVertex.extend(data[point.indices[arrayType]])
                        if doBones:
                            if batch.hasMatrixIndices:
                                index = shapeMatrix.matrixTable[point.matrixIndex//3]
                            else:
                                index = shapeMatrix.matrixTable[0]
                            if index != 0xffff:
                                if isWeighted[index]:
                                    mmi = boneIndices[weightData[index]]
                                    mmw = weights[weightData[index]]
                                else:
                                    mmi = [weightData[index]]+[0]*(maxWeightCount-1)
                                    mmw = [1.0]+[0.0]*(maxWeightCount-1)
                            uniqueVertex.extend(mmw)
                            uniqueVertex.extend(mmi)
                        uniqueIndex = len(uniqueVertices)
                        uniqueVertices.append(tuple(uniqueVertex))
                        indexMap[point.indices] = uniqueIndex
    return indexMap, uniqueVertices

def makeSubMeshes(count, scenegraph, batches, indexMap, transformedPositions):
    subMeshTriangles = [[] for i in range(count)]
    subMeshVertices = [[] for i in range(count)]
    stack = []
    materialIndex = frameIndex = batchIndex = None
    for node in scenegraph:
        if node.type == 1:
            stack.append((materialIndex, frameIndex, batchIndex))
        elif node.type == 2:
            materialIndex, frameIndex, batchIndex = stack.pop()
        elif node.type == 0x10:
            frameIndex = node.index
        elif node.type == 0x11:
            materialIndex = node.index
        elif node.type == 0x12:
            batchIndex = node.index
            batch = batches[batchIndex]
            subMeshTriangles[materialIndex].extend(getBatchTriangles(batch, indexMap))
            # TODO mesh metrics
            for shapeDraw, shapeMatrix in batch.matrixGroups:
                subMeshVertices[materialIndex].extend([transformedPositions[point.posIndex] for primitive in shapeDraw.primitives for point in primitive.points])
        else:
            raise ValueError(node.type)
    return subMeshTriangles, subMeshVertices

def makeUnityAsset(name, doBones, subMeshTriangles, subMeshVertices, uniqueVertices, uChannels, MyVertexFormat, vertexStruct, jointMatrices, joints, scenegraph):
    mesh = Mesh(str(4300000), '')
    asset = unityparser.UnityDocument([mesh])

    mesh.m_Name = name
    mesh.serializedVersion = 9
    mesh.m_IsReadable = 1
    mesh.m_KeepVertices = int(doBones)
    mesh.m_KeepIndices = int(doBones)
    mesh.m_IndexFormat = 0
    mesh.m_SubMeshes = []

    indexBuffer = array('H')
    
    print("Setting submeshes")

    minXTotal = minYTotal = minZTotal = maxXTotal = maxYTotal = maxZTotal = None
    for triangles, positions in zip(subMeshTriangles, subMeshVertices):
        if len(positions) == 0:
            assert len(triangles) == 0
            mesh.m_SubMeshes.append({
                "firstByte": 0,
                "indexCount": 0,
                "topology": 0,
                "baseVertex": 0,
                "firstVertex": 0,
                "vertexCount": 0,
                "localAABB": {
                    "m_Center": {'x': 0, 'y': 0, 'z': 0},
                    "m_Extent": {'x': 0, 'y': 0, 'z': 0}
                },
                "serializedVersion": 2
            })
        else:
            minX = min([p.x for p in positions]); minXTotal = minX if minXTotal is None else min(minX, minXTotal)
            minY = min([p.y for p in positions]); minYTotal = minY if minYTotal is None else min(minY, minYTotal)
            minZ = min([p.z for p in positions]); minZTotal = minZ if minZTotal is None else min(minZ, minZTotal)
            maxX = max([p.x for p in positions]); maxXTotal = maxX if maxXTotal is None else max(maxX, maxXTotal)
            maxY = max([p.y for p in positions]); maxYTotal = maxY if maxYTotal is None else max(maxY, maxYTotal)
            maxZ = max([p.z for p in positions]); maxZTotal = maxZ if maxZTotal is None else max(maxZ, maxZTotal)
            mesh.m_SubMeshes.append({
                "firstByte": len(indexBuffer)*2,
                "indexCount": len(triangles),
                "topology": 0,
                "baseVertex": 0,
                "firstVertex": min(triangles),
                "vertexCount": max(triangles)-min(triangles)+1,
                "localAABB": {
                    "m_Center": {'x': (minX+maxX)/2, 'y': (minY+maxY)/2, 'z': (minZ+maxZ)/2},
                    "m_Extent": {'x': (maxX-minX)/2, 'y': (maxY-minY)/2, 'z': (maxZ-minZ)/2}
                },
                "serializedVersion": 2
            })
            indexBuffer.extend(triangles)

    mesh.m_VertexData = {
        "serializedVersion": 2,
        "m_VertexCount": len(uniqueVertices),
        "m_Channels": uChannels,
        "m_DataSize": len(uniqueVertices)*sizeof(MyVertexFormat),
        "_typelessdata": (b''.join([vertexStruct.pack(*v) for v in uniqueVertices])).hex()
    }
    mesh.m_IndexBuffer = indexBuffer.tobytes().hex()
    mesh.m_LocalAABB = {
        "m_Center": {'x': (minXTotal+maxXTotal)/2, 'y': (minYTotal+maxYTotal)/2, 'z': (minZTotal+maxZTotal)/2},
        "m_Extent": {'x': (maxXTotal-minXTotal)/2, 'y': (maxYTotal-minYTotal)/2, 'z': (maxZTotal-minZTotal)/2}
    }
    
    if doBones:
        print("Generating armature")
        mesh.m_BindPose = [{'e%d%d'%(i,j): mat[i][j] for i in range(4) for j in range(4)} for mat in jointMatrices]
        boneNames = [None]*len(joints)
        rootIndex = None
        name = None
        nameStack = []
        armName = mesh.m_Name+'_arm'
        for node in scenegraph:
            if node.type == 0x10:
                if rootIndex == None:
                    rootIndex = node.index
                name = joints[node.index].name
                boneNames[node.index] = '/'.join([armName]+nameStack+[name])
            elif node.type == 1:
                nameStack.append(name)
            elif node.type == 2:
                name = nameStack.pop()
        mesh.m_BoneNameHashes = array('I', [crc32(name.encode()) for name in boneNames]).tobytes().hex()
        mesh.m_RootBoneNameHash = crc32(boneNames[rootIndex].encode())
        mesh.m_BonesAABB = [{"m_Min": dict(zip('xyz', frame.bbMin)), "m_Max": dict(zip('xyz', frame.bbMax))} for frame in joints]
    
    return asset

def exportBmd(bmd, outputFolderLocation):
    doBones = len(bmd.jnt1.frames) > 1
    
    if doBones:
        print("Transforming verts")
        transformedPositions, transformedNormals = transformVerts(bmd, bmd.shp1.batches, bmd.vtx1.positions, bmd.vtx1.normals if hasattr(bmd.vtx1, "normals") else None)
        transformedPositionsArray = array('f', [c for v in transformedPositions for c in v])
        if transformedNormals is None:
            transformedNormalsArray = None
        else:
            transformedNormalsArray = array('f', [c for v in transformedNormals for c in v])
    else:
        transformedPositions = bmd.vtx1.positions
        if hasattr(bmd.vtx1, "normals"): transformedNormals = bmd.vtx1.normals
        else: transformedNormals = None
        transformedPositionsArray = transformedNormalsArray = None
    
    print("Setting channels")
    vertexStruct, uChannels, maxWeightCount, MyVertexFormat, dataForArrayType, boneIndices, weights = setupChannels(bmd.vtx1.formats, bmd.vtx1.originalData, bmd.vtx1.asFloat, bmd.evp1.weightedIndices, bmd.evp1.weightedWeights, transformedPositionsArray, transformedNormalsArray, doBones)

    print("Collecting vertices")
    indexMap, uniqueVertices = collectVertices(bmd.shp1.batches, maxWeightCount, dataForArrayType, doBones, bmd.drw1.isWeighted, bmd.drw1.data, transformedPositions, transformedNormals, boneIndices, weights)
    
    print("Making sub-meshes")
    subMeshTriangles, subMeshVertices = makeSubMeshes(len(bmd.mat3.remapTable), bmd.inf1.scenegraph, bmd.shp1.batches, indexMap, transformedPositions)
    
    #import meshoptimizer
    #indices = [i for subMesh in subMeshTriangles for i in subMesh]
    #remap = meshoptimizer.generateVertexRemap(indices, uniqueVertices, MyVertexFormat)
    
    asset = makeUnityAsset(bmd.name, doBones, subMeshTriangles, subMeshVertices, uniqueVertices, uChannels, MyVertexFormat, vertexStruct, bmd.jnt1.matrices, bmd.jnt1.frames, bmd.inf1.scenegraph)
    print("Writing asset")
    assetName = bmd.name+".asset"
    asset.dump_yaml(os.path.join(outputFolderLocation, assetName))
    meshId = writeNativeMeta(assetName, 4300000, outputFolderLocation)
        
    return meshId

filterModes = [0, 1, 0, 1, 0, 2]
blurRadius = sqrt(-1/(2*log(3/240, e)))
def exportTexture(img, bmddir):
    textureSettings = {
        "serializedVersion": 2,
        "wrapU": [1, 0, 2][img.wrapS],
        "wrapV": [1, 0, 2][img.wrapT],
        "wrapW": 0,
        "filterMode": max(filterModes[img.minFilter], filterModes[img.magFilter]),
        "mipBias": img.lodBias/100,
        "aniso": 2**img.maxAniso
    }
    # TODO: use ETC2 for CMPR on mobile
    if img.format in (TexFmt.RGBA8, TexFmt.CMPR) or img.mipmapCount > 1:
        # TODO: Unity doesn't understand the other formats but they're used for textures with mipmaps
        fout = open(os.path.join(bmddir, img.name+".ktx"), 'wb')
        decodeTextureKTX(fout, img.data, img.format, img.width, img.height, img.paletteFormat, img.palette, img.mipmapCount)
        fout.close()
        return writeMeta(img.name+".ktx", {
            "IHVImageFormatImporter": {
                "textureSettings": textureSettings,
                "sRGBTexture": 0
            }
        }, bmddir)
    else:
        # PNG is required to be compressed, but it's the only format Unity can
        # import at all pixel formats :(
        decImg = decodeTexturePIL(img.data, img.format, img.width, img.height, img.paletteFormat, img.palette, img.mipmapCount)[0][0].transpose(method=1)
        if img.format in (TexFmt.I4, TexFmt.IA4):
            from lineblur import bidirLineBlur
            # slightly improves texture compression for EAC.
            # slightly worsens texture compression for BC :(
            decImg = bidirLineBlur(decImg)
        if (img.format in (TexFmt.C4, TexFmt.C8, TexFmt.C14X2) and img.paletteFormat == TlutFmt.IA8) or img.format in (TexFmt.IA4, TexFmt.IA8):
            # unity imports R and G
            intensity, alpha = decImg.split()
            decImg = Image.merge('RGB', (intensity, alpha, Image.new('L', decImg.size)))
        decImg.save(os.path.join(bmddir, img.name+".png"))
        platformSettings = [{
            "serializedVersion": 3,
            "buildTarget": "DefaultTexturePlatform",
            "maxTextureSize": 2048,
            "textureFormat": -1,
            "textureCompression": 2,
            "compressionQuality": 50
        }]
        if img.format == TexFmt.RGBA8:
            # already handled above
            platformSettings[0]["textureFormat"] = 4 # RGBA32
        elif img.format == TexFmt.RGB565:
            platformSettings[0]["textureFormat"] = 7 # RGB565
        elif img.format in (TexFmt.C4, TexFmt.C8, TexFmt.C14X2) and img.paletteFormat == TlutFmt.RGB565:
            platformSettings[0]["textureFormat"] = 7 # RGB565
        elif img.format == TexFmt.I4:
            # actually already seems to be selected automatically
            platformSettings.append({
                "serializedVersion": 3,
                "buildTarget": "Standalone",
                "maxTextureSize": 2048,
                "textureFormat": 26, # BC4
                "textureCompression": 2,
                "compressionQuality": 50,
                "overridden": 0
            })
            platformSettings.append({
                "serializedVersion": 3,
                "buildTarget": "Android",
                "maxTextureSize": 2048,
                "textureFormat": 41, # EAC_R
                "textureCompression": 2,
                "compressionQuality": 50,
                "overridden": 0
            })
        elif img.format == TexFmt.IA4:
            # actually already seems to be selected automatically
            platformSettings.append({
                "serializedVersion": 3,
                "buildTarget": "Standalone",
                "maxTextureSize": 2048,
                "textureFormat": 27, # BC5
                "textureCompression": 2,
                "compressionQuality": 50,
                "overridden": 0
            })
            platformSettings.append({
                "serializedVersion": 3,
                "buildTarget": "Android",
                "maxTextureSize": 2048,
                "textureFormat": 43, # EAC_RG
                "textureCompression": 2,
                "compressionQuality": 50,
                "overridden": 0
            })
        elif img.format == TexFmt.IA8:
            platformSettings[0]["textureFormat"] = 62 # RG16
        elif img.format in (TexFmt.C4, TexFmt.C8, TexFmt.C14X2) and img.paletteFormat == TlutFmt.IA8:
            platformSettings[0]["textureFormat"] = 62 # RG16
        elif img.format == TexFmt.I8:
            platformSettings[0]["textureFormat"] = 63 # R8
        return writeMeta(img.name+".png", {
            "TextureImporter": {
                "serializedVersion": 11,
                "textureSettings": textureSettings,
                "mipmaps": {
                    "mipMapMode": 0,
                    "enableMipMap": 0,
                    "sRGBTexture": 0,
                    "linearTexture": 0
                },
                "textureFormat": 1,
                "maxTextureSize": 2048,
                "lightmap": 0,
                "compressionQuality": 50,
                "alphaUsage": 1,#int(bool(img.transparency)), # all this does is remove the alpha channel when 0
                "alphaIsTransparency": 0, # dilates color around transparent areas
                "textureType": 10 if img.format in (TexFmt.I4, TexFmt.I8) else 0,
                "textureShape": 1,
                "singleChannelComponent": 1,
                "platformSettings": platformSettings
            }
        }, bmddir)

def exportTextures(textures, bmddir):
    # some textures have the same data and name, but differ by settings like
    # transparency.
    # only exporting different data is better for memory use, but needs handling
    # in shader, which means more different shaders, which can increase compile
    # time and state changes
    exported = {}
    exportedOrig = {}
    for img in textures:
        if img.name in exported:
            ex = exportedOrig[img.name]
            if ex != img:
                differ = ", ".join([field if isinstance(field, str) else field[0] for field, a, b in zip(img.fields, img.as_tuple(), ex.as_tuple()) if a != b])
                warn("%r has multiple samplers that differ in %s"%(img.name, differ))
            yield exported[img.name]
        else:
            guid = exportTexture(img, bmddir)
            yield guid
            exported[img.name] = guid
            exportedOrig[img.name] = img

from shadergen2 import UnityShaderGen, ShaderWriter

def exportMaterials(materials, indirectArray, textures, bmddir, textureIds, useColor1):
    gen = UnityShaderGen()
    for i, mat in enumerate(materials):
        assetName = mat.name+".shader"
        indirect = indirectArray[i] if i < len(indirectArray) else None
        with open(os.path.join(bmddir, assetName), 'w') as fout:
            gen.gen(mat, indirect, textures, ShaderWriter(fout), useColor1)
        shader = writeMeta(assetName, {
            "ShaderImporter": {
                "externalObjects": {},
                "defaultTextures": [],
                "nonModifiableTextures": [],
                "userData": None,
                "assetBundleName": None,
                "assetBundleVariant": None
            }
        }, bmddir)
        
        uMat = Material(str(2100000), '')
        uMat.serializedVersion = 6
        uMat.m_Name = mat.name
        if all(colorChan is None or not colorChan.lightingEnabled or colorChan.litMask == 0 for colorChan in mat.colorChans):
            # enable emissive baking
            uMat.m_LightmapFlags = 2
        else:
            uMat.m_LightmapFlags = 0
        colors = {}
        # Declared as Vectors (not Colors) in shader properties, but still go
        # in the m_Colors block
        for i, color in enumerate(mat.matColors):
            if color is not None: colors["_MatColor%d"%i] = {c: v/255 for c, v in zip('rgba', color)}
        # amb color is never animated, so not exposed in material properties
        #for i, color in enumerate(mat.ambColors):
        #    if color is not None: colors["_AmbColor%d"%i] = {c: v/255 for c, v in zip('rgba', color)}
        for i, color in enumerate(mat.tevColors):
            if color is not None: colors["_TevColor%d"%i] = {c: v/255 for c, v in zip('rgba', color)}
        for i, color in enumerate(mat.tevKColors):
            if color is not None: colors["_TevKColor%d"%i] = {c: v/255 for c, v in zip('rgba', color)}
        texEnvs = {}
        for i in range(8):
            texEnv = {}
            
            # note: texMtx and texNo do not necessarily correspond
            texMtx = mat.texMtxs[i] if i < len(mat.texMtxs) else None
            texIdx = mat.texNos[i] if i < len(mat.texNos) else None
            if texMtx is None and texIdx is None: continue
            
            if texMtx is None:
                texEnv["m_Scale"] = {"x": 1, "y": 1}
                texEnv["m_Offset"] = {"x": 0, "y": 0}
            else:
                texEnv["m_Scale"] = {"x": texMtx.scale[0], "y": texMtx.scale[1]}
                texEnv["m_Offset"] = {"x": texMtx.translation[0], "y": texMtx.translation[1]}
            
            if texIdx is None:
                texEnv["m_Texture"] = {"fileID": 0}
            else:
                texEnv["m_Texture"] = {"fileID": 2800000, "guid": textureIds[texIdx], "type": 3}
            
            texEnvs["_Tex%d"%i] = texEnv
        # send texmtx center, rotation
        for i, texMtx in enumerate(mat.texMtxs):
            if texMtx is not None: colors["_Tex%d_CR"%i] = {"r": texMtx.center[0], "g": texMtx.center[1], "b": texMtx.center[2], "a": texMtx.rotation*pi}
        uMat.m_SavedProperties = {
            "serializedVersion": 3,
            "m_TexEnvs": texEnvs,
            "m_Colors": colors
        }
        uMat.m_Shader = getFileRef(shader, id=4800000, type=3)
        asset = unityparser.UnityDocument([uMat])
        assetName = mat.name+".mat"
        asset.dump_yaml(os.path.join(bmddir, assetName))
        yield writeNativeMeta(assetName, 2100000, bmddir)

if __name__ == "__main__":
    import sys
    fixUnityParserFloats()
    fin = open(sys.argv[1], 'rb')
    bmd = BModel()
    outputFolderLocation, bmd.name = os.path.split(sys.argv[1])
    bmd.name = os.path.splitext(bmd.name)[0]
    bmd.read(fin)
    fin.close()
    exportBmd(bmd, outputFolderLocation)

