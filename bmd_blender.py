import bpy, bmesh
from functools import reduce
import operator
from bpy_extras.io_utils import ImportHelper
from bpy.props import StringProperty, BoolProperty, EnumProperty, CollectionProperty
from bpy.types import Operator, OperatorFileListElement
import os.path
from bmd import *


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
        mat.identity()
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
        onDown = mat.materialMode == 1
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
                    imgs = decodeTexturePIL(texture.data, texture.format, texture.width, texture.height, texture.paletteFormat, texture.palette, mipmapCount=texture.mipmapCount)
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
            if mat.blend == BlendMode.NONE:
                bmat.blend_method = 'OPAQUE'
            elif mat.blend == BlendMode.BLEND:
                bmat.blend_method = 'BLEND'
            if len(mat.tevColors) > 0 and mat.tevColors[0] is not None:
                bmat.diffuse_color = color8ToLinear(mat.tevColors[0])
            
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
                (mat.ambColors, "Ambient", colorAmbReg),
                (mat.tevKColors, "Constant", konstColorReg),
                (mat.tevColors, "Base", colorReg)
            ]:
                for j, color in enumerate(values):
                    node = placer.addNode('ShaderNodeRGB')
                    node.outputs[0].default_value = color8ToLinear(color)
                    node.label = name + ' ' + str(j)
                    out.append(node.outputs[0])
            colorVtxReg = []
            for j in range(mat.colorChanNum):
                node = placer.addNode('ShaderNodeVertexColor')
                node.layer_name = str(j)
                colorVtxReg.append(node.outputs['Color']) # TODO alpha
            placer.nextColumn()
            
            # Light channels
            colorChannels = []
            for j in range(mat.colorChanNum):
                colorChannel = safeGet(mat.colorChans, j*2)
                #alphaChannel = safeGet(mat.colorChans, j*2+1)
                matSource = {ColorSrc.REG: colorMatReg, ColorSrc.VTX: colorVtxReg}[colorChannel.matColorSource][j]
                ambSource = {ColorSrc.REG: colorAmbReg, ColorSrc.VTX: colorVtxReg}[colorChannel.ambColorSource][j]
                if colorChannel.lightingEnabled and colorChannel.litMask != 0:
                    if colorChannel.attenuationFunction in (0, 1):
                        node = placer.addNode('ShaderNodeEeveeSpecular')
                        tree.links.new(matSource, node.inputs['Specular'])
                        tree.links.new(ambSource, node.inputs['Emissive Color'])
                        #if colorChannel.diffuseFunction == DiffuseFunction.NONE:
                        node.inputs['Base Color'].default_value = (0,0,0,0)
                        #else:
                        #    tree.links.new(matSource, node.inputs['Base Color'])
                        node.inputs['Roughness'].default_value = 0.0
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
            for j, texGen in enumerate(mat.texCoords[:mat.texGenNum]):
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
                    node = placer.addNode('ShaderNodeShaderToRGB')
                    out = node.outputs[0]
                    tree.links.new(colorChannels[texGen.source-TexGenSrc.COLOR0], node.inputs[0])
                node.label = "Texture coordinate generation source %d"%j
                placer.nextColumn()
                if texGen.type == TexGenType.MTX3x4 or texGen.type == TexGenType.MTX2x4:
                    node = placer.addNode('ShaderNodeMapping')
                    node.vector_type = 'POINT'
                    if texGen.matrix >= TexGenMatrix.TEXMTX0 and texGen.matrix <= TexGenMatrix.TEXMTX9 and mat.texMtxs[texGen.matrix-TexGenMatrix.TEXMTX0] is not None:
                        texMtx = mat.texMtxs[texGen.matrix-TexGenMatrix.TEXMTX0]
                        node.inputs['Location'].default_value = texMtx.translation+(0,)
                        node.inputs['Rotation'].default_value = (0,0,texMtx.rotation) # TODO what units
                        node.inputs['Scale'].default_value = texMtx.scale+(1,)
                    tree.links.new(out, node.inputs[0])
                    out = node.outputs[0]
                placer.previousColumn()
                texGens.append(out)
            placer.nextColumn()
            placer.nextColumn()
            
            for j in range(mat.tevStageNum):
                tevOrderInfo = mat.tevOrders[j]
                tevStage = mat.tevStages[j]
                
                colorSources = []
                for colorSrc in (tevStage.colorInA, tevStage.colorInB, tevStage.colorInC, tevStage.colorInD):
                    if colorSrc in (TevColorArg.CPREV, TevColorArg.C0, TevColorArg.C1, TevColorArg.C2):
                        colorSources.append(colorReg[colorSrc.value//2])
                    elif colorSrc in (TevColorArg.TEXC, TevColorArg.TEXA):
                        texture = bmd.tex1.textures[mat.texNos[tevOrderInfo.texMap]]
                        node = placer.addNode('ShaderNodeTexImage')
                        if texture.wrapS == 0: node.extension = 'EXTEND'
                        elif texture.wrapS == 1: node.extension = 'REPEAT'
                        #elif texture.wrapS == 2: node.extension = 'CHECKER'
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
                            colorSources.append(colorChannels[1])
                        elif tevOrderInfo.chanId == ColorChannelID.COLOR0A0:
                            colorSources.append(colorChannels[0])
                        elif tevOrderInfo.chanId == ColorChannelID.COLOR1A1:
                            colorSources.append(colorChannels[1])
                        else:
                            assert False, tevOrderInfo.chanId
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
                        assert False, colorSrc
                        colorSources.append(None)
                assert len(colorSources) == 4, (tevStage.colorInA, tevStage.colorInB, tevStage.colorInC, tevStage.colorInD, colorSources)
                
                placer.nextColumn()
                if tevStage.colorOp in (TevOp.ADD, TevOp.SUB):
                    node = placer.addNode('ShaderNodeMixShader')
                    if isinstance(colorSources[2], float):
                        node.inputs['Fac'].default_value = colorSources[2]
                    else:
                        tree.links.new(colorSources[2], node.inputs['Fac'])
                    if isinstance(colorSources[0], float):
                        #node.inputs[1].default_value = (colorSources[0],colorSources[0],colorSources[0],1)
                        rgb = placer.addNode('ShaderNodeRGB')
                        rgb.outputs[0].default_value = (colorSources[0],colorSources[0],colorSources[0],1)
                        tree.links.new(rgb.outputs[0], node.inputs[1])
                    else:
                        tree.links.new(colorSources[0], node.inputs[1])
                    if isinstance(colorSources[1], float):
                        #node.inputs[2].default_value = (colorSources[1],colorSources[1],colorSources[1],1)
                        rgb = placer.addNode('ShaderNodeRGB')
                        rgb.outputs[0].default_value = (colorSources[1],colorSources[1],colorSources[1],1)
                        tree.links.new(rgb.outputs[0], node.inputs[2])
                    else:
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
                    else:
                        tree.links.new(colorSources[3], node2.inputs[1])
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

def drawSkeleton(bmd, sg, arm, onDown=True, p=None, parent=None, indent=0):
    if p is None: p = Matrix.Identity(4)
    effP = p
    
    if sg.type == 0x10:
        f = bmd.jnt1.frames[sg.index]
        effP = updateMatrix(f, p)
        #bone = arm.edit_bones[f.name]
        bone = arm.edit_bones.new(name=f.name)
        bone.head = Vector((0,0,0))
        bone.tail = Vector((0,0,10))
        ts = [bmd.jnt1.frames[node.index].translation for node in sg.children if node.type == 0x10]
        if len(ts) > 0:
            bone.tail = reduce(operator.add, ts)/len(sg.children)
            if bone.tail.magnitude < 0.0001:
                bone.tail = Vector((0,0,10))
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

    if hasattr(bmd, "jnt1"):
        bpy.context.view_layer.objects.active = armObject
        bpy.ops.object.mode_set(mode='EDIT')

        for i, f in enumerate(bmd.jnt1.frames):
            meshObject.vertex_groups.new(name=f.name)
            #arm.edit_bones.new(name=f.name)

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

