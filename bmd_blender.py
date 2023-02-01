import bpy, bmesh
from functools import reduce
import operator
from bpy_extras.io_utils import ImportHelper
from bpy.props import StringProperty, BoolProperty, EnumProperty, CollectionProperty
from bpy.types import Operator, OperatorFileListElement
import os.path
import tempfile, os
from bmd import *
import math


def flipY(vec):
    return vec#Vector((vec.x, 1.0-vec.y))

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
        mat.identity()
    for i, (shapeDraw, shapeMatrix) in enumerate(batch.matrixGroups):
        # draw packet
        updateMatrixTable(bmd, shapeMatrix, matrixTable)
        mat, mmi, mmw = matrixTable[0]
        for curr in shapeDraw.primitives:
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
                    warn("Unsupported primitive type %s"%curr.type)
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
        material = bmd.mat3.materials[bmd.mat3.remapTable[sg.index]]
        onDown = material.materialMode == 1
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
        self.margin = 40
    
    def nextColumn(self):
        if self.colIdx >= len(self.columns)-1:
            self.columns.append(Column())
        lastCol = self.columns[self.colIdx]
        self.colIdx += 1
        self.columns[self.colIdx].x = lastCol.x+lastCol.maxWidth+self.margin
    
    def previousColumn(self):
        self.colIdx -= 1
    
    def goToColumn(self, tgt):
        while self.colIdx < tgt:
            self.nextColumn()
        while self.colIdx > tgt:
            self.previousColumn()
    
    def newColumn(self):
        self.goToColumn(len(self.columns))
    
    def addNode(self, type):
        col = self.columns[self.colIdx]
        node = self.tree.nodes.new(type)
        node.location = (col.x, col.bottom)
        node.select = False
        node.hide = True
        col.bottom -= node.bl_height_max+self.margin
        if col.maxWidth < node.bl_width_default: col.maxWidth = node.bl_width_default
        return node
    
    def alignRows(self, startCol):
        bottom = min(col.bottom for col in self.columns[startCol:])
        for col in self.columns[startCol:]:
            col.bottom = bottom-self.margin

def placeColorChannel(colorChannel, placer, tree, frame, matReg, ambReg, vtxColor):
    matSource = {ColorSrc.REG: matReg, ColorSrc.VTX: vtxColor}[colorChannel.matColorSource]
    ambSource = {ColorSrc.REG: ambReg, ColorSrc.VTX: vtxColor}[colorChannel.ambColorSource]
    if colorChannel.lightingEnabled and colorChannel.litMask != 0:
        if colorChannel.attenuationFunction == 0:
            node = placer.addNode('ShaderNodeBsdfGlossy')
            if matSource is not None: tree.links.new(matSource, node.inputs['Color'])
            node.distribution = 'SHARP'
            node.inputs['Roughness'].default_value = 0.0
            out = node.outputs['BSDF']
        else:
            if colorChannel.diffuseFunction == DiffuseFunction.NONE:
                out = matSource
            else:
                node = placer.addNode('ShaderNodeBsdfDiffuse')
                if matSource is not None: tree.links.new(matSource, node.inputs['Color'])
                out = node.outputs['BSDF']
        node.parent = frame
        placer.nextColumn()

        node = placer.addNode('ShaderNodeAddShader')
        node.parent = frame
        tree.links.new(out, node.inputs[0])
        if ambSource is not None: tree.links.new(ambSource, node.inputs[1])
        out = node.outputs['Shader']
        placer.nextColumn()

        node = placer.addNode('ShaderNodeShaderToRGB')
        node.parent = frame
        tree.links.new(out, node.inputs['Shader'])
        out = node.outputs['Color']
        placer.nextColumn()

        node = placer.addNode('ShaderNodeMixRGB')
        node.parent = frame
        tree.links.new(out, node.inputs[1])
        node.use_clamp = True
        node.inputs[0].default_value = 0
        return node.outputs['Color']
    else:
        node = placer.addNode('NodeReroute')
        node.parent = frame
        if matSource is not None: tree.links.new(matSource, node.inputs[0])
        return node.outputs[0]

def placeTexMatrix(out, matrix, placer, tree, frame, mat):
    if matrix >= TexGenMatrix.PNMTX0 and matrix <= TexGenMatrix.PNMTX9:
        node = placer.addNode('ShaderNodeVectorTransform')
        node.parent = frame
        node.lable = "Position/normal matrix "+str(matrix-TexGenMatrix.PNMTX0)
        node.vector_type = 'POINT'
        node.convert_from = 'OBJECT'
        node.convert_to = 'WORLD'
        if out is not None: tree.links.new(out, node.inputs[0])
        return node.outputs[0]
    elif (matrix >= TexGenMatrix.TEXMTX0 and matrix <= TexGenMatrix.TEXMTX9) or \
         (matrix >= TexGenMatrix.DTTMTX0 and matrix <= TexGenMatrix.DTTMTX19):
        node = placer.addNode('ShaderNodeMapping')
        node.parent = frame
        node.vector_type = 'POINT'
        if matrix >= TexGenMatrix.TEXMTX0 and matrix <= TexGenMatrix.TEXMTX9:
            node.label = "Texture matrix "+str(matrix-TexGenMatrix.TEXMTX0)
            texMtx = mat.texMtxs[(matrix-TexGenMatrix.TEXMTX0)//3]
        elif matrix >= TexGenMatrix.DTTMTX0 and matrix <= TexGenMatrix.DTTMTX19:
            node.label = "Post-transform texture matrix "+str(matrix-TexGenMatrix.DTTMTX0)
            texMtx = mat.postTexMtxs[(matrix-TexGenMatrix.DTTMTX0)//3]
        if texMtx is not None:
            node.inputs['Location'].default_value = texMtx.translation+(0,)
            node.inputs['Rotation'].default_value = (0,0,texMtx.rotation*math.pi)
            node.inputs['Scale'].default_value = texMtx.scale+(1,)
        if out is not None: tree.links.new(out, node.inputs[0])
        return node.outputs[0]
    elif matrix == TexGenMatrix.IDENTITY or matrix == TexGenMatrix.DTTIDENTITY:
        node = placer.addNode('NodeReroute')
        node.parent = frame
        if matrix == TexGenMatrix.IDENTITY:
            node.label = "Identity texture matrix"
        elif matrix == TexGenMatrix.DTTIDENTITY:
            node.label = "Identity post-transform texture matrix"
        if out is not None: tree.links.new(out, node.inputs[0])
        return node.outputs[0]
    else:
        return None

def placeTexture(texSlot, mat, bmd, placer, btextures):
    texture = bmd.tex1.textures[mat.texNos[texSlot]]
    node = placer.addNode('ShaderNodeTexImage')
    if texture.wrapS == 0: node.extension = 'EXTEND'
    elif texture.wrapS == 1: node.extension = 'REPEAT'
    #elif texture.wrapS == 2: node.extension = 'CHECKER'
    node.interpolation = 'Linear' if texture.magFilter%2 == 1 else 'Closest'
    node.image = btextures[mat.texNos[texSlot]]
    return node

def importMesh(filePath, bmd, mesh, bm):
    btextures = []
    if hasattr(bmd, "tex1"):
        print("Importing textures")
        for texture in bmd.tex1.textures:
            if texture.name in bpy.data.images:
                image = bpy.data.images[texture.name]
            else:
                imgs = decodeTexturePIL(texture.data, texture.format, texture.width, texture.height, texture.paletteFormat, texture.palette, mipmapCount=texture.mipmapCount)
                # in PIL, only PNG, Targa, and TIFF support all required pixel formats. PNG is required to be compressed (waste of time), and Blender doesn't load the alpha channel in monochrome TGAs
                f = tempfile.NamedTemporaryFile(suffix=".tif", delete=False)
                imgs[0][0].transpose(method=1).save(f)
                f.close()
                image = bpy.data.images.load(f.name)
                image.pack()
                image.name = texture.name
                image.filepath = "//textures/"+texture.name+".tif"
                image.packed_files[0].filepath = "//textures/"+texture.name+".tif"
                os.remove(f.name)
            btextures.append(image)

    if hasattr(bmd, "mat3"):
        print("Importing materials")
        usedMatCount = max(bmd.mat3.remapTable)+1
        bmats = [None]*usedMatCount
        for i, mat in enumerate(bmd.mat3.materials):
            if i >= usedMatCount: break
            bmat = bpy.data.materials.new(mat.name)
            bmats[i] = bmat
            
            # Render attributes
            if mat.cullMode is not None:
                bmat.use_backface_culling = mat.cullMode == CullMode.BACK
            if mat.blend is not None:
                if mat.blend.blendMode == BlendMode.NONE:
                    if mat.alphaComp is not None and (mat.alphaComp.comp0 in (CompareType.GREATER, CompareType.GEQUAL) or mat.alphaComp.comp1 in (CompareType.GREATER, CompareType.GEQUAL)):
                        bmat.blend_method = 'CLIP'
                    else:
                        bmat.blend_method = 'OPAQUE'
                elif mat.blend.blendMode == BlendMode.BLEND:
                    bmat.blend_method = 'BLEND'
            if mat.alphaComp is not None:
                if mat.alphaComp.comp0 == CompareType.GREATER:
                    bmat.alpha_threshold = mat.alphaComp.ref0/255
                elif mat.alphaComp.comp0 == CompareType.GEQUAL:
                    bmat.alpha_threshold = (mat.alphaComp.ref0-1)/255
                elif mat.alphaComp.comp1 == CompareType.GREATER:
                    bmat.alpha_threshold = mat.alphaComp.ref1/255
                elif mat.alphaComp.comp1 == CompareType.GEQUAL:
                    bmat.alpha_threshold = (mat.alphaComp.ref1-1)/255
            bmat.shadow_method = 'NONE'
            
            # preview
            if len(mat.tevColors) > 0 and mat.tevColors[0] is not None:
                bmat.diffuse_color = color8ToLinear(mat.tevColors[0])
            
            bmat.use_nodes = True
            tree = bmat.node_tree
            tree.nodes.clear()
            
            placer = NodePlacer(tree)
            
            # Light channels
            colorChannels = []
            alphaChannels = []
            colIdx = placer.colIdx
            for j in range(2):
                placer.goToColumn(colIdx)
                frame = tree.nodes.new('NodeFrame')
                frame.label = "Light channel %d"%j
                if j < len(mat.matColors) and mat.matColors[j] is not None:
                    node = placer.addNode('ShaderNodeRGB')
                    node.outputs[0].default_value = color8ToLinear(mat.matColors[j])
                    node.label = 'Material color'
                    node.parent = frame
                    matColorReg = node.outputs[0]
                    
                    node = placer.addNode('ShaderNodeValue')
                    node.outputs[0].default_value = mat.matColors[j][3]/255
                    node.label = 'Material alpha'
                    node.parent = frame
                    matAlphaReg = node.outputs[0]
                else:
                    matColorReg = matAlphaReg = None
                if j < len(mat.ambColors) and mat.ambColors[j] is not None:
                    node = placer.addNode('ShaderNodeRGB')
                    node.outputs[0].default_value = color8ToLinear(mat.ambColors[j])
                    node.label = 'Ambient color'
                    node.parent = frame
                    ambColorReg = node.outputs[0]
                    
                    node = placer.addNode('ShaderNodeValue')
                    node.outputs[0].default_value = mat.ambColors[j][3]/255
                    node.label = 'Ambient alpha'
                    node.parent = frame
                    ambAlphaReg = node.outputs[0]
                else:
                    ambColorReg = ambAlphaReg = None
                if j < len(bmd.vtx1.colors) and bmd.vtx1.colors[j] is not None:
                    node = placer.addNode('ShaderNodeVertexColor')
                    node.layer_name = str(j)
                    node.parent = frame
                    vtxColor = node.outputs['Color']
                    vtxAlpha = node.outputs['Alpha']
                else:
                    vtxColor = vtxAlpha = None
                placer.nextColumn()
                if j < mat.colorChanNum and mat.colorChans[j*2] is not None:
                    colorChannels.append(placeColorChannel(mat.colorChans[j*2], placer, tree, frame, matColorReg, ambColorReg, vtxColor))
                else:
                    colorChannels.append(None)
                if j < mat.colorChanNum and mat.colorChans[j*2+1] is not None:
                    alphaChannels.append(placeColorChannel(mat.colorChans[j*2+1], placer, tree, frame, matAlphaReg, ambAlphaReg, vtxAlpha))
                else:
                    alphaChannels.append(None)
                placer.alignRows(colIdx)
            
            placer.newColumn()
            
            # Texgen stages
            colIdx = placer.colIdx
            texGens = []
            for j, texGen in enumerate(mat.texCoords[:mat.texGenNum]):
                placer.goToColumn(colIdx)
                frame = tree.nodes.new('NodeFrame')
                frame.label = "Texture coordinate generator " + str(j)
                if texGen is None:
                    texGens.append(None)
                    continue
                if texGen.source == TexGenSrc.POS:
                    node = placer.addNode('ShaderNodeNewGeometry')
                    texGenSrc = node.outputs['Position']
                elif texGen.source == TexGenSrc.NRM:
                    node = placer.addNode('ShaderNodeNewGeometry')
                    texGenSrc = node.outputs['Normal']
                elif texGen.source == TexGenSrc.BINRM:
                    node1 = placer.addNode('ShaderNodeNewGeometry')
                    node1.parent = frame
                    placer.nextColumn()
                    node = placer.addNode('ShaderNodeVectorMath')
                    tree.links.new(node1.outputs['Normal'], node.inputs[0])
                    tree.links.new(node1.outputs['Tangent'], node.inputs[1])
                    node.operation = 'CROSS_PRODUCT'
                    texGenSrc = node.outputs['Vector']
                elif texGen.source == TexGenSrc.TANGENT:
                    node = placer.addNode('ShaderNodeNewGeometry')
                    texGenSrc = node.outputs['Tangent']
                elif texGen.source >= TexGenSrc.TEX0 and texGen.source <= TexGenSrc.TEX7:
                    node = placer.addNode('ShaderNodeUVMap')
                    node.uv_map = str(texGen.source-TexGenSrc.TEX0)
                    texGenSrc = node.outputs['UV']
                elif texGen.source >= TexGenSrc.TEXCOORD0 and texGen.source <= TexGenSrc.TEXCOORD6:
                    node = placer.addNode('NodeReroute')
                    if texGens[texGen.source-TexGenSrc.TEXCOORD0] is not None: tree.links.new(texGens[texGen.source-TexGenSrc.TEXCOORD0], node.inputs[0])
                    texGenSrc = node.outputs[0]
                elif texGen.source >= TexGenSrc.COLOR0 and texGen.source <= TexGenSrc.COLOR1:
                    node = placer.addNode('NodeReroute')
                    if colorChannels[texGen.source-TexGenSrc.COLOR0] is not None: tree.links.new(colorChannels[texGen.source-TexGenSrc.COLOR0], node.inputs[0])
                    texGenSrc = node.outputs[0]
                else:
                    texGenSrc = None
                node.parent = frame
                placer.nextColumn()
                if texGen.type == TexGenType.MTX3x4 or texGen.type == TexGenType.MTX2x4:
                    if texGen.type == TexGenType.MTX2x4:
                        node = placer.addNode('ShaderNodeVectorMath')
                        node.parent = frame
                        node.operation = 'MULTIPLY_ADD'
                        if texGenSrc is not None: tree.links.new(texGenSrc, node.inputs[0])
                        node.inputs[1].default_value = (1,1,0)
                        node.inputs[2].default_value = (0,0,1)
                        out = node.outputs[0]
                        placer.nextColumn()
                    else:
                        out = texGenSrc
                    out = placeTexMatrix(out, texGen.matrix, placer, tree, frame, mat)
                elif texGen.type >= TexGenType.BUMP0 and texGen.type <= TexGenType.BUMP7:
                    print("emboss maps currently not supported")
                    out = None
                    # TODO
                    # two diffuse bsdf to approximate "N dot L"
                    # except one is tangent dot L, and one is bitangent dot L
                    # (need to calculate bidangent as normal cross tangent)
                    # shader to rgb each
                    # create vector, use rgb from first as X, second as Y, zero as Z
                    # vector add with texGenSrc
                elif texGen.type == TexGenType.SRTG:
                    out = texGenSrc
                else:
                    out = None
                
                postTexGen = mat.postTexGens[j]
                if postTexGen is not None:
                    placer.nextColumn()
                    out = placeTexMatrix(out, postTexGen.matrix, placer, tree, frame, mat)
                
                if texGen.type == TexGenType.MTX3x4:
                    placer.nextColumn()
                    node1 = placer.addNode('ShaderNodeSeparateXYZ')
                    node1.parent = frame
                    if out is not None: tree.links.new(out, node1.inputs[0])
                    placer.nextColumn()
                    node = placer.addNode('ShaderNodeVectorMath')
                    node.parent = frame
                    node.operation = 'DIVIDE'
                    if out is not None: tree.links.new(out, node.inputs[0])
                    tree.links.new(node1.outputs[2], node.inputs[1])
                    out = node.outputs[0]
                
                texGens.append(out)
                placer.alignRows(colIdx)
            
            placer.newColumn()
            
            # Indirect
            indTexCoords = []
            hasIndirect = i < len(bmd.mat3.indirectArray) and bmd.mat3.indirectArray[i] is not None and bmd.mat3.indirectArray[i].hasIndirect
            if hasIndirect:
                indirect = bmd.mat3.indirectArray[i]
                colIdx = placer.colIdx
                for j in range(indirect.indTexStageNum):
                    indTexOrder = indirect.indTexOrder[j]
                    indTexCoordScale = indirect.indTexCoordScale[j]
                    
                    placer.goToColumn(colIdx)
                    frame = tree.nodes.new('NodeFrame')
                    frame.label = "Indirect texture stage " + str(j)
                    
                    node = placer.addNode('ShaderNodeVectorMath')
                    if texGens[indTexOrder.texCoordId] is not None: tree.links.new(texGens[indTexOrder.texCoordId], node.inputs[0])
                    node.operation = 'DIVIDE'
                    node.inputs[1].default_value = (2**indTexCoordScale.scaleS, 2**indTexCoordScale.scaleT, 1)
                    out = node.outputs[0]
                    
                    placer.nextColumn()
                    imgNode = placeTexture(indTexOrder.texture, mat, bmd, placer, btextures)
                    imgNode.parent = frame
                    tree.links.new(out, imgNode.inputs[0])
                    
                    placer.nextColumn()
                    sepNode = placer.addNode('ShaderNodeSeparateRGB')
                    sepNode.parent = frame
                    tree.links.new(imgNode.outputs['Color'], sepNode.inputs[0])
                    
                    placer.nextColumn()
                    joinNode = placer.addNode('ShaderNodeCombineXYZ')
                    joinNode.parent = frame
                    tree.links.new(imgNode.outputs['Alpha'], joinNode.inputs[0])
                    tree.links.new(sepNode.outputs[2], joinNode.inputs[1])
                    tree.links.new(sepNode.outputs[1], joinNode.inputs[2])
                    
                    indTexCoords.append(sepNode.outputs[0])
                placer.newColumn()
            
            # TEV registers
            konstColorReg = []
            colorReg = []
            for values, name, out in [
                (mat.tevKColors, "Constant", konstColorReg),
                (mat.tevColors, "Initial", colorReg)
            ]:
                for j, color in enumerate(values):
                    if color is None:
                        out.append(None)
                    else:
                        node = placer.addNode('ShaderNodeRGB')
                        node.outputs[0].default_value = color8ToLinear(color)
                        node.label = name + ' ' + str(j)
                        out.append(node.outputs[0])
            node = placer.addNode('ShaderNodeCombineXYZ')
            tevTexCoord = node.outputs[0]
            
            placer.nextColumn()
            
            # TEV stages
            for j in range(0 if mat.tevStageNum is None else mat.tevStageNum):
                tevStage = mat.tevStages[j]
                tevOrder = mat.tevOrders[j]
                kColorSel = mat.tevKColorSels[j]
                kAlphaSel = mat.tevKAlphaSels[j]
                tevSwapMode = mat.tevSwapModes[j]
                if tevSwapMode is None:
                    rasSwapTable = (0, 1, 2, 3)
                    texSwapTable = (0, 1, 2, 3)
                else:
                    rasSwapTable = mat.tevSwapModeTables[tevSwapMode.rasSel].as_tuple()
                    texSwapTable = mat.tevSwapModeTables[tevSwapMode.texSel].as_tuple()
                
                frame = tree.nodes.new('NodeFrame')
                frame.label = "TEV stage " + str(j)
                
                if hasIndirect:
                    indTevStage = bmd.mat3.indirectArray[i].indTevStage[j]
                    indTexCoords[indTevStage.indTexId]
                    # TODO
                
                if tevStage is None:
                    colorSources = [None]*4
                else:
                    colorSources = []
                    for colorSrc in (tevStage.colorInA, tevStage.colorInB, tevStage.colorInC, tevStage.colorInD):
                        if colorSrc in (TevColorArg.CPREV, TevColorArg.C0, TevColorArg.C1, TevColorArg.C2):
                            colorSources.append(colorReg[colorSrc.value//2])
                        elif colorSrc in (TevColorArg.TEXC, TevColorArg.TEXA):
                            node = placeTexture(tevOrder.texMap, mat, bmd, placer, btextures)
                            if texGens[tevOrder.texCoordId] is not None: tree.links.new(texGens[tevOrder.texCoordId], node.inputs[0])
                            if colorSrc == TevColorArg.TEXC:
                                colorSources.append(node.outputs[0])
                            else:
                                colorSources.append(node.outputs[1])
                        elif colorSrc == TevColorArg.RASC:
                            if tevOrder.chanId == ColorChannelID.COLOR0:
                                colorSources.append(colorChannels[0])
                            elif tevOrder.chanId == ColorChannelID.COLOR1:
                                colorSources.append(colorChannels[1])
                            elif tevOrder.chanId == ColorChannelID.ALPHA0:
                                colorSources.append(alphaChannels[0])
                            elif tevOrder.chanId == ColorChannelID.ALPHA1:
                                colorSources.append(alphaChannels[1])
                            elif tevOrder.chanId == ColorChannelID.COLOR0A0:
                                colorSources.append(colorChannels[0])
                            elif tevOrder.chanId == ColorChannelID.COLOR1A1:
                                colorSources.append(colorChannels[1])
                            else:
                                #assert False, tevOrder.chanId
                                colorSources.append(None)
                        elif colorSrc == TevColorArg.ONE:
                            colorSources.append(1.0)
                        elif colorSrc == TevColorArg.HALF:
                            colorSources.append(0.5)
                        elif colorSrc == TevColorArg.KONST:
                            constColorSel = mat.tevKColorSels[j]
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
                            elif constColorSel >= TevKColorSel.K0 and constColorSel <= TevKColorSel.K3:
                                colorSources.append(konstColorReg[constColorSel-TevKColorSel.K0])
                            else:
                                #sep = placer.addNode('ShaderNodeSeparateRGB')
                                #tree.links.new(konstColorReg[constColorSel.value%4], sep.inputs[0])
                                #colorSources.append(sep.outputs[(constColorSel.value-0x10)//4])
                                colorSources.append(konstColorReg[constColorSel.value%4])
                        elif colorSrc == TevColorArg.ZERO:
                            colorSources.append(0.0)
                        else:
                            #assert False, colorSrc
                            colorSources.append(None)
                assert len(colorSources) == 4, (tevStage.colorInA, tevStage.colorInB, tevStage.colorInC, tevStage.colorInD, colorSources)
                
                placer.nextColumn()
                if tevStage is not None and tevStage.colorOp in (TevOp.ADD, TevOp.SUB):
                    node = placer.addNode('ShaderNodeMixShader')
                    if isinstance(colorSources[2], float):
                        node.inputs['Fac'].default_value = colorSources[2]
                    elif colorSources[2] is not None:
                        tree.links.new(colorSources[2], node.inputs['Fac'])
                    if isinstance(colorSources[0], float):
                        #node.inputs[1].default_value = (colorSources[0],colorSources[0],colorSources[0],1)
                        rgb = placer.addNode('ShaderNodeRGB')
                        rgb.outputs[0].default_value = (colorSources[0],colorSources[0],colorSources[0],1)
                        tree.links.new(rgb.outputs[0], node.inputs[1])
                    elif colorSources[0] is not None:
                        tree.links.new(colorSources[0], node.inputs[1])
                    if isinstance(colorSources[1], float):
                        #node.inputs[2].default_value = (colorSources[1],colorSources[1],colorSources[1],1)
                        rgb = placer.addNode('ShaderNodeRGB')
                        rgb.outputs[0].default_value = (colorSources[1],colorSources[1],colorSources[1],1)
                        tree.links.new(rgb.outputs[0], node.inputs[2])
                    elif colorSources[1] is not None:
                        tree.links.new(colorSources[1], node.inputs[2])
                    
                    placer.nextColumn()
                    node2 = placer.addNode('ShaderNodeAddShader')
                    #node2.blend_type = 'ADD' if tevStage.colorOp == TevOp.ADD else 'SUBTRACT'
                    #node2.inputs['Fac'].default_value = 1.0
                    tree.links.new(node.outputs[0], node2.inputs[0])
                    if isinstance(colorSources[3], float):
                        #node2.inputs[2].default_value = (colorSources[3],colorSources[3],colorSources[3],1)
                        rgb = placer.addNode('ShaderNodeRGB')
                        rgb.outputs[0].default_value = (colorSources[3],colorSources[3],colorSources[3],1)
                        tree.links.new(rgb.outputs[0], node2.inputs[1])
                    elif colorSources[3] is not None:
                        tree.links.new(colorSources[3], node2.inputs[1])
                    placer.previousColumn()
                    colorReg[0] = node2.outputs[0]
                placer.nextColumn()
                placer.nextColumn()
                

            shout = placer.addNode('ShaderNodeOutputMaterial')
            if colorReg[0] is not None: tree.links.new(colorReg[0], shout.inputs[0])
        
        for i, matIndex in enumerate(bmd.mat3.remapTable):
            mesh.materials.append(bmats[matIndex])

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
        #bone = arm.edit_bones[f.name]
        bone = arm.edit_bones.new(name=f.name)
        bone.head = Vector((0,0,0))
        bone.tail = Vector((0,10,0))
        childBones = sg.children
        while not (len(childBones) == 0 or any(node.type == 0x10 for node in childBones)):
            childBones = [child for node in childBones for child in node.children]
        ts = [bmd.jnt1.frames[node.index].translation for node in childBones if node.type == 0x10]
        if len(ts) > 0:
            bone.tail = reduce(operator.add, ts)/len(ts)
            if bone.tail.magnitude < 0.01:
                bone.tail = Vector((0,10,0))
        # from X-pointing to Y-pointing
        bone.matrix = effP@Matrix(((0,1,0,0),(0,0,1,0),(1,0,0,0),(0,0,0,1)))
        if parent is not None:
            bone.parent = parent
            bone.use_connect = parent.tail == bone.head
        bone.inherit_scale = 'NONE' if f.calcFlags & 1 else 'FULL'
        # edit bones don't have a scale, so save it here for later animations
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

def importFile(filepath, context):
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
    context.scene.collection.objects.link(meshObject)
    context.scene.collection.objects.link(armObject)

    if hasattr(bmd, "jnt1"):
        context.view_layer.objects.active = armObject
        bpy.ops.object.mode_set(mode='EDIT')

        for i, f in enumerate(bmd.jnt1.frames):
            meshObject.vertex_groups.new(name=f.name)
            #arm.edit_bones.new(name=f.name)

        importSkeleton(bmd, arm)
    
        bpy.ops.object.mode_set(mode='OBJECT')
    
    #armObject["scenegraph"] = repr(bmd.scenegraph.to_dict(bmd))
    
    bm = bmesh.new()
    bm.from_object(meshObject, context.evaluated_depsgraph_get())
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
        context.scene.collection.objects.link(meshObject)

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
            importFile(os.path.join(self.directory, file.name), context)
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

