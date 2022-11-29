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

def getBatchTriangles(bmd, batch, indexMap, targetMmi):
    matrixTable = [(Matrix(), [], []) for i in range(10)]
    for packet in batch.packets:
        if targetMmi is not None:
            assert not batch.hasMatrixIndices
            index = packet.matrixTable[0]
            assert index != 0xffff
            assert not bmd.drw1.isWeighted[index]
            mmi = bmd.drw1.data[index]
            if mmi != targetMmi:
                continue
        for primitive in packet.primitives:
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

def exportBmd(bmd, outputFolderLocation, targetMmi=None):
    vertexData = []
    fields = []
    vertexStruct = ['<']
    uChannels = [{"stream": 0, "offset": 0, "format": 0, "dimension": 0} for i in range(14)]
    offset = 0

    dataForArrayType = [None]*21

    doBones = len(bmd.jnt1.frames) > 1 and targetMmi is None
    
    if doBones:
        print("Transforming verts")

        transformedPositions = [Vector() for p in bmd.vtx1.positions]
        if hasattr(bmd.vtx1, "normals"): transformedNormals = [Vector() for p in bmd.vtx1.normals]
        for batch in bmd.shp1.batches:
            matrixTable = [(Matrix(), [], []) for i in range(10)]
            for mat, mmi, mmw in matrixTable:
                mat.identity()
            for i, packet in enumerate(batch.packets):
                updateMatrixTable(bmd, packet, matrixTable)
                mat, mmi, mmw = matrixTable[0]
                for curr in packet.primitives:
                    for p in curr.points:
                        if batch.hasMatrixIndices:
                            mat, mmi, mmw = matrixTable[p.matrixIndex//3]
                        if batch.hasPositions:
                            transformedPositions[p.posIndex] = mat@bmd.vtx1.positions[p.posIndex]
                        if batch.hasNormals:
                            transformedNormals[p.normalIndex] = (mat@bmd.vtx1.normals[p.normalIndex].resized(4)).resized(3)
        transformedPositionsArray = array('f', [c for v in transformedPositions for c in v])
        if hasattr(bmd.vtx1, "normals"): transformedNormalsArray = array('f', [c for v in transformedNormals for c in v])
    else:
        transformedPositions = bmd.vtx1.positions
    
    print("Setting channels")

    for fmt, original, asFloat in zip(bmd.vtx1.formats, bmd.vtx1.originalData, bmd.vtx1.asFloat):
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
        
        vertexData.append(splitVertexArray(arr, count))
        #formatForArrayType[fmt.arrayType.value] = fmt
        dataForArrayType[fmt.arrayType.value] = splitVertexArray(arr, count)

    if len(bmd.evp1.weightedIndices) == 0:
        maxWeightCount = 0
    else:
        maxWeightCount = max(map(len, bmd.evp1.weightedIndices))
    if doBones:
        if maxWeightCount == 0:
            maxWeightCount = 1
            weights = [(1.0,)]*len(bmd.evp1.weightedIndices)
        else:
            weights = [tuple(v)+(0.0,)*(maxWeightCount-len(v)) for v in bmd.evp1.weightedWeights]
        boneIndices = [tuple(v)+(0,)*(maxWeightCount-len(v)) for v in bmd.evp1.weightedIndices]
    
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
        vertexData.append(splitVertexArray(arr, count))
        
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
        vertexData.append(splitVertexArray(arr, count))
        #dataForArrayType[0] = splitVertexArray(arr, count)
    elif maxWeightCount == 0:
        maxWeightCount = 1

    vertexStruct = Struct(''.join(vertexStruct))
    class MyVertexFormat(Structure):
        _pack_ = 1
        _fields_ = list(zip(string.ascii_letters, fields))
    assert sizeof(MyVertexFormat) == vertexStruct.size, (MyVertexFormat._fields_, sizeof(MyVertexFormat), vertexStruct.format, vertexStruct.size)

    print("Collecting vertices")

    uniqueVertices = []
    indexMap = {}
    for batch in bmd.shp1.batches:
        for packet in batch.packets:
            mmi = [0]*maxWeightCount
            mmw = [1.0]+[0.0]*(maxWeightCount-1)
            if targetMmi is not None:
                assert not batch.hasMatrixIndices
                index = packet.matrixTable[0]
                assert index != 0xffff
                assert not bmd.drw1.isWeighted[index]
                mmi = bmd.drw1.data[index]
                if mmi != targetMmi:
                    continue
            for primitive in packet.primitives:
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
                                    if isint: data = [tuple(map(int, v)) for v in data]
                                uniqueVertex.extend(data[point.indices[arrayType]])
                        if doBones:
                            if batch.hasMatrixIndices:
                                index = packet.matrixTable[point.matrixIndex//3]
                            else:
                                index = packet.matrixTable[0]
                            if index != 0xffff:
                                if bmd.drw1.isWeighted[index]:
                                    mmi = boneIndices[bmd.drw1.data[index]]
                                    mmw = weights[bmd.drw1.data[index]]
                                else:
                                    mmi = [bmd.drw1.data[index]]+[0]*(maxWeightCount-1)
                                    mmw = [1.0]+[0.0]*(maxWeightCount-1)
                            uniqueVertex.extend(mmw)
                            uniqueVertex.extend(mmi)
                        uniqueIndex = len(uniqueVertices)
                        uniqueVertices.append(tuple(uniqueVertex))
                        indexMap[point.indices] = uniqueIndex

    print("Making sub-meshes")

    subMeshTriangles = [[] for i in range(len(bmd.mat3.materials))]
    subMeshVertices = [[] for i in range(len(bmd.mat3.materials))]
    stack = []
    materialIndex = frameIndex = batchIndex = None
    for node in bmd.inf1.scenegraph:
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
            batch = bmd.shp1.batches[batchIndex]
            subMeshTriangles[materialIndex].extend(getBatchTriangles(bmd, batch, indexMap, targetMmi))
            # TODO mesh metrics
            for packet in batch.packets:
                if targetMmi is not None:
                    assert not batch.hasMatrixIndices
                    index = packet.matrixTable[0]
                    assert index != 0xffff
                    assert not bmd.drw1.isWeighted[index]
                    mmi = bmd.drw1.data[index]
                    if mmi != targetMmi:
                        continue
                subMeshVertices[materialIndex].extend([transformedPositions[point.posIndex] for primitive in packet.primitives for point in primitive.points])
        else:
            raise ValueError(node.type)
    
    materials = list(bmd.mat3.materials)
    if targetMmi is not None:
        print("Trimming materials")
        for i in range(len(materials)-1, -1, -1):
            if len(subMeshTriangles[i]) == 0:
                del materials[i]
                del subMeshTriangles[i]
                del subMeshVertices[i]
    
    # FIXME why are cafe and underpass broken :(

    #import meshoptimizer
    #indices = [i for subMesh in subMeshTriangles for i in subMesh]
    #remap = meshoptimizer.generateVertexRemap(indices, uniqueVertices, MyVertexFormat)

    mesh = Mesh(str(4300000), '')
    asset = unityparser.UnityDocument([mesh])

    mesh.m_Name = bmd.name
    mesh.serializedVersion = 9
    mesh.m_IsReadable = 0
    mesh.m_KeepVertices = int(doBones)
    mesh.m_KeepIndices = int(doBones)
    mesh.m_IndexFormat = 0
    mesh.m_SubMeshes = []

    indexBuffer = array('H')
    
    print("Setting submeshes")
    if sum(map(len, subMeshVertices)) == 0: return

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
            minX = min([p.x for p in positions])
            minY = min([p.y for p in positions])
            minZ = min([p.z for p in positions])
            maxX = max([p.x for p in positions])
            maxY = max([p.y for p in positions])
            maxZ = max([p.z for p in positions])
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
    minX = min([p.x for positions in subMeshVertices for p in positions])
    minY = min([p.y for positions in subMeshVertices for p in positions])
    minZ = min([p.z for positions in subMeshVertices for p in positions])
    maxX = max([p.x for positions in subMeshVertices for p in positions])
    maxY = max([p.y for positions in subMeshVertices for p in positions])
    maxZ = max([p.z for positions in subMeshVertices for p in positions])
    mesh.m_LocalAABB = {
        "m_Center": {'x': (minX+maxX)/2, 'y': (minY+maxY)/2, 'z': (minZ+maxZ)/2},
        "m_Extent": {'x': (maxX-minX)/2, 'y': (maxY-minY)/2, 'z': (maxZ-minZ)/2}
    }
    
    if doBones:
        mesh.m_BindPose = [{'e%d%d'%(i,j): mat[i][j] for i in range(4) for j in range(4)} for mat in bmd.jnt1.matrices]
        boneNames = [None]*len(bmd.jnt1.frames)
        rootIndex = None
        name = None
        nameStack = []
        armName = bmd.name+'_arm'
        for node in bmd.inf1.scenegraph:
            if node.type == 0x10:
                if rootIndex == None:
                    rootIndex = node.index
                name = bmd.jnt1.frames[node.index].name
                boneNames[node.index] = '/'.join([armName]+nameStack+[name])
            elif node.type == 1:
                nameStack.append(name)
            elif node.type == 2:
                name = nameStack.pop()
        mesh.m_BoneNameHashes = array('I', [crc32(name.encode()) for name in boneNames]).tobytes().hex()
        mesh.m_RootBoneNameHash = crc32(boneNames[rootIndex].encode())
        mesh.m_BonesAABB = [{"m_Min": dict(zip('xyz', frame.bbMin)), "m_Max": dict(zip('xyz', frame.bbMax))} for frame in bmd.jnt1.frames]
    
    assetName = bmd.name+".asset"
    asset.dump_yaml(os.path.join(outputFolderLocation, assetName))
    meshId = writeNativeMeta(assetName, 4300000, outputFolderLocation)
    
    if targetMmi is None:
        bmddir = os.path.join(outputFolderLocation, bmd.name)
        os.makedirs(bmddir, exist_ok=True)
        #writeMeta(bmddir, {
        #    "folderAsset": "yes",
        #    "DefaultImporter": {
        #        "externalObjects": {}
        #    }
        #}, outputFolderLocation)
        textureIds = list(exportTextures(bmd.tex1.textures, bmddir))
        materialIds = list(exportMaterials(materials, bmddir, textureIds))
        materialIdInSlot = [materialIds[matIndex] for matIndex in bmd.mat3.remapTable]
        return meshId, materialIdInSlot
    else:
        return meshId, []

def exportTextures(textures, bmddir):
    print("Exporting textures")
    for img in textures:
        textureSettings = {
            "serializedVersion": 2,
            "wrapU": [1, 0, 2][img.wrapS],
            "wrapV": [1, 0, 2][img.wrapT],
            "wrapW": [1, 0, 2][img.wrapS],
            "filterMode": [0, 1, 0, 1, 0, 1][img.magFilter],
            "mipBias": img.lodBias/100
        }
        if img.format in (TexFmt.RGBA8, TexFmt.CMPR) or img.mipmapCount > 1:
            fout = open(os.path.join(bmddir, img.name+".dds"), 'wb')
            decodeTextureDDS(fout, img.data, img.format, img.width, img.height, img.paletteFormat, img.palette, img.mipmapCount)
            fout.close()
            yield writeMeta(img.name+".dds", {
                "IHVImageFormatImporter": {
                    "textureSettings": textureSettings,
                    "sRGBTexture": 0
                }
            }, bmddir)
        else:
            decodeTexturePIL(img.data, img.format, img.width, img.height, img.paletteFormat, img.palette, img.mipmapCount)[0][0].save(os.path.join(bmddir, img.name+".png"))
            yield writeMeta(img.name+".png", {
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
                    "alphaUsage": 1,
                    "textureType": 10 if img.format in (TexFmt.I4, TexFmt.I8) else 0,
                    "textureShape": 1,
                    "singleChannelComponent": 1,
                    "platformSettings": [{
                        "serializedVersion": 3,
                        "buildTarget": "DefaultTexturePlatform",
                        "maxTextureSize": 2048,
                        "textureFormat": 7 if img.format == TexFmt.RGB565 or (img.format in (TexFmt.C4, TexFmt.C8, TexFmt.C14X2) and img.paletteFormat == TlutFmt.RGB565) else -1,
                        "textureCompression": 2,
                        "compressionQuality": 50
                    }]
                }
            }, bmddir)
    
def exportMaterials(materials, bmddir, textureIds):
    print("Exporting materials")
    
    for mat in materials:
        uMat = Material(str(2100000), '')
        uMat.serializedVersion = 6
        uMat.m_Name = mat.name
        colors = {}
        for i, color in enumerate(mat.matColors):
            colors["_ColorMatReg%d"%i] = {c: v/255 for c, v in zip('rgba', color)}
        for i, color in enumerate(mat.ambColors):
            colors["_ColorAmbReg%d"%i] = {c: v/255 for c, v in zip('rgba', color)}
        for i, color in enumerate(mat.tevKColors):
            colors["_KonstColor%d"%i] = {c: v/255 for c, v in zip('rgba', color)}
        for i, color in enumerate(mat.tevColors):
            colors["_Color%d"%i] = {c: v/255 for c, v in zip('rgba', color)}
        textures = {}
        for i, texIdx in enumerate(mat.texNos):
            texEnv = {"m_Scale": {"x": 1, "y": 1}, "m_Offset": {"x": 0, "y": 0}} # TODO
            if texIdx is None:
                texEnv["m_Texture"] = {"fileID": 0}
            else:
                texEnv["m_Texture"] = {"fileID": 2800000, "guid": textureIds[texIdx], "type": 3}
            textures["_Tex%d"%i] = texEnv
        uMat.m_SavedProperties = {
            "serializedVersion": 3,
            "m_TexEnvs": textures,
            "m_Colors": colors
        }
        uMat.m_Shader = {"fileID": 4800000, "guid": "3e8e64449a2c52eb9b3267898b76ade0", "type": 3}
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
    if False and bmd.name == "map":
        outputFolderLocation = os.path.join(outputFolderLocation, bmd.name)
        os.makedirs(outputFolderLocation, exist_ok=True)
        for targetMmi, targetFrame in enumerate(bmd.jnt1.frames):
            print(targetFrame.name)
            bmd.name = targetFrame.name
            exportBmd(bmd, outputFolderLocation, targetMmi)
    else:
        exportBmd(bmd, outputFolderLocation)

