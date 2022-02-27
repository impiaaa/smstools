import unityparser, sys, os.path, uuid, array, yaml
from col import ColReader

Mesh = unityparser.constants.UnityClassIdMap.get_or_create_class_id(43, 'Mesh')

def writeMeta(name, importer, outputFolderLocation):
    guid = str(uuid.uuid4()).replace('-', '')
    meta = {
        "fileFormatVersion": 2,
        "guid": guid
    }
    meta.update(importer)
    yaml.dump(meta, open(os.path.join(outputFolderLocation, name+".meta"), 'w'))
    return guid

def writeNativeMeta(name, mainObjectFileID, outputFolderLocation):
    return writeMeta(name, {
        "NativeFormatImporter": {
            "mainObjectFileID": mainObjectFileID
        }
    }, outputFolderLocation)

def exportCol(col, outputFolderLocation, physNameBase):
    for groupIdx, group in enumerate(col.groups):
        if len(group.tribuf3):
            triangles = list(zip(zip(group.indexBuffer[0::3], group.indexBuffer[1::3], group.indexBuffer[2::3]), group.terrainTypes, group.tribuf2, group.tribuf3))
        else:
            triangles = list(zip(zip(group.indexBuffer[0::3], group.indexBuffer[1::3], group.indexBuffer[2::3]), group.terrainTypes, group.tribuf2, [None]*group.numTriIndices))
        connectedPieces = []
        while len(triangles) > 0:
            connectedTriIndices, connectedTerrainType, connectedUnk2, connectedUnk3 = triangles.pop(0)
            connectedTris = [connectedTriIndices]
            connectedIndices = set(connectedTriIndices)
            i = 0
            while i < len(triangles):
                triIndices, terrainType, unk2, unk3 = triangles[i]
                
                if len(connectedIndices.intersection(triIndices)) > 0 and \
                   terrainType == connectedTerrainType and \
                   unk2 == connectedUnk2 and \
                   unk3 == connectedUnk3:
                    
                    del triangles[i]
                    connectedTris.append(triIndices)
                    connectedIndices.update(triIndices)
                    i = 0
                
                else:
                    i += 1
            
            connectedPieces.append((connectedTris, connectedTerrainType, connectedUnk2, connectedUnk3))
        
        for connectedIdx, (oldTriangles, terrainType, unk2, unk3) in enumerate(connectedPieces):
            usedIndices = list({i for tri in oldTriangles for i in tri})
            usedIndices.sort() # keep original order - optimal?
            newVertexBuffer = array.array('f', [col.vertexBuffer[i*3+j] for i in usedIndices for j in range(3)])
            newIndexBuffer = array.array('H', [usedIndices.index(i) for tri in oldTriangles for i in tri])
            del usedIndices
            
            #newVertexBuffer = col.vertexBuffer
            #newIndexBuffer = group.indexBuffer
            
            if unk3 is None:
                physName = '%s-%04x-%d-%d.%d'%(physNameBase, group.surfaceId, terrainType, unk2, connectedIdx)
            else:
                physName = '%s-%04x-%d-%d-%d.%d'%(physNameBase, group.surfaceId, terrainType, unk2, unk3, connectedIdx)

            mesh = Mesh(str(4300000), '')
            asset = unityparser.UnityDocument([mesh])

            mesh.m_Name = physName
            mesh.serializedVersion = 9
            mesh.m_IsReadable = 1
            mesh.m_KeepVertices = 1
            mesh.m_KeepIndices = 1
            mesh.m_IndexFormat = 0
            mesh.m_SubMeshes = []

            minX = min([newVertexBuffer[i*3+0] for i in newIndexBuffer])
            minY = min([newVertexBuffer[i*3+1] for i in newIndexBuffer])
            minZ = min([newVertexBuffer[i*3+2] for i in newIndexBuffer])
            maxX = max([newVertexBuffer[i*3+0] for i in newIndexBuffer])
            maxY = max([newVertexBuffer[i*3+1] for i in newIndexBuffer])
            maxZ = max([newVertexBuffer[i*3+2] for i in newIndexBuffer])
            mesh.m_SubMeshes.append({
                "firstByte": 0,
                "indexCount": len(newIndexBuffer),
                "topology": 0,
                "baseVertex": 0,
                "firstVertex": 0,
                "vertexCount": len(newVertexBuffer)//3,
                "serializedVersion": 2,
                "localAABB": {
                    "m_Center": {'x': (minX+maxX)/2, 'y': (minY+maxY)/2, 'z': (minZ+maxZ)/2},
                    "m_Extent": {'x': maxX-minX, 'y': maxY-minY, 'z': maxZ-minZ}
                }
            })

            channels = [
                { # position
                    "stream": 0,
                    "offset": 0,
                    "format": 0, # kVertexFormatFloat
                    "dimension": 3
                },
                { # normal
                    "stream": 0,
                    "offset": 0,
                    "format": 0,
                    "dimension": 0
                },
                { # tangent
                    "stream": 0,
                    "offset": 0,
                    "format": 0,
                    "dimension": 0
                },
                { # color
                    "stream": 0,
                    "offset": 0,
                    "format": 0,
                    "dimension": 0
                }
            ]
            for i in range(8):
                channels.append({ # uv
                    "stream": 0,
                    "offset": 0,
                    "format": 0,
                    "dimension": 0
                })
            channels.append({ # blend weight
                "stream": 0,
                "offset": 0,
                "format": 0,
                "dimension": 0
            })
            channels.append({ # blend indices
                "stream": 0,
                "offset": 0,
                "format": 0,
                "dimension": 0
            })
            if sys.byteorder != 'little': newVertexBuffer.byteswap()
            mesh.m_VertexData = {
                "serializedVersion": 2,
                "m_VertexCount": len(newVertexBuffer)//3,
                "m_Channels": channels,
                "m_DataSize": len(newVertexBuffer)*4,
                "_typelessdata": newVertexBuffer.tobytes().hex()
            }
            if sys.byteorder != 'little': newIndexBuffer.byteswap()
            mesh.m_IndexBuffer = newIndexBuffer.tobytes().hex()
            mesh.m_LocalAABB = {
                "m_Center": {'x': (minX+maxX)/2, 'y': (minY+maxY)/2, 'z': (minZ+maxZ)/2},
                "m_Extent": {'x': maxX-minX, 'y': maxY-minY, 'z': maxZ-minZ}
            }
            assetName = physName+".asset"
            asset.dump_yaml(os.path.join(outputFolderLocation, assetName))
            yield writeNativeMeta(assetName, 4300000, outputFolderLocation)

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <col>\n"%sys.argv[0])
    exit(1)

if __name__ == '__main__':
    import re
    # for whatever reason, unityparser adds explicit type markers to floats with no
    # fraction. this restores pyyaml's default behavior
    unityparser.resolver.Resolver.add_implicit_resolver(
            'tag:yaml.org,2002:float',
            re.compile(r'''^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?
                        |\.[0-9_]+(?:[eE][-+][0-9]+)?
                        |[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*
                        |[-+]?\.(?:inf|Inf|INF)
                        |\.(?:nan|NaN|NAN))$''', re.X),
            list('-+0123456789.'))

    outputFolderLocation, physNameBase = os.path.split(sys.argv[1])
    fin = open(sys.argv[1], 'rb')
    col = ColReader()
    col.read(fin)
    fin.close()
    for uid in exportCol(col, outputFolderLocation, physNameBase): pass

