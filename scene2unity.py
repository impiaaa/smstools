from scenebin import *
import unityparser, transforms3d
from math import radians
import pathlib, sys
from col2unity import exportCol
from col import ColReader

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

lastId = 0
def getId():
    global lastId
    lastId += 1
    return str(lastId)

GameObject = unityparser.constants.UnityClassIdMap.get_or_create_class_id(1, 'GameObject')
Transform = unityparser.constants.UnityClassIdMap.get_or_create_class_id(4, 'Transform')
Camera = unityparser.constants.UnityClassIdMap.get_or_create_class_id(20, 'Camera')
Material = unityparser.constants.UnityClassIdMap.get_or_create_class_id(21, 'Material')
MeshRenderer = unityparser.constants.UnityClassIdMap.get_or_create_class_id(23, 'MeshRenderer')
MeshFilter = unityparser.constants.UnityClassIdMap.get_or_create_class_id(33, 'MeshFilter')
Rigidbody = unityparser.constants.UnityClassIdMap.get_or_create_class_id(54, 'Rigidbody')
MeshCollider = unityparser.constants.UnityClassIdMap.get_or_create_class_id(64, 'MeshCollider')
BoxCollider = unityparser.constants.UnityClassIdMap.get_or_create_class_id(65, 'BoxCollider')
AudioSource = unityparser.constants.UnityClassIdMap.get_or_create_class_id(82, 'AudioSource')
Light = unityparser.constants.UnityClassIdMap.get_or_create_class_id(108, 'Light')

def getObjRef(obj):
    return {'fileID': int(obj.anchor)}

def getFileRef(guid, id, type=2):
    return {'fileID': id, 'guid': guid, 'type': type}

OcclusionCullingSettings = unityparser.constants.UnityClassIdMap.get_or_create_class_id(29, 'OcclusionCullingSettings')
RenderSettings = unityparser.constants.UnityClassIdMap.get_or_create_class_id(104, 'RenderSettings')
LightmapSettings = unityparser.constants.UnityClassIdMap.get_or_create_class_id(157, 'LightmapSettings')
NavMeshSettings = unityparser.constants.UnityClassIdMap.get_or_create_class_id(196, 'NavMeshSettings')

def setupObject(o):
    objObj = GameObject(getId(), '')
    scene.entries.append(objObj)
    objObj.m_Name = o.description
    objObj.m_IsActive = 1
    objObj.serializedVersion = 6
    objXfm = Transform(getId(), '')
    scene.entries.append(objXfm)
    objObj.m_Component = [{'component': getObjRef(objXfm)}]
    objXfm.m_GameObject = getObjRef(objObj)
    return objObj, objXfm

SCALE = 1/100 # approximate, according to mario's height

def setupPosition(objXfm, o):
    objXfm.m_LocalPosition = {'x': SCALE*o.x, 'y': SCALE*o.y, 'z': -1*SCALE*o.z}

def setup3d(objXfm, o):
    setupPosition(objXfm, o)
    objXfm.m_LocalEulerAnglesHint = {'x': o.rx, 'y': o.ry, 'z': o.rz}
    objXfm.m_LocalRotation = dict(zip('wxyz', transforms3d.euler.euler2quat(radians(o.rx), radians(o.ry), radians(o.rz)).tolist()))
    objXfm.m_LocalScale = {'x': SCALE*o.sx, 'y': SCALE*o.sy, 'z': -1*SCALE*o.sz}


scenedirpath = pathlib.Path(sys.argv[1])
assert scenedirpath.is_dir()
outpath = pathlib.Path(sys.argv[2])
assert outpath.is_dir()

cols = {}
for colpath in scenedirpath.glob("**/*.col"):
    colpath_rel = colpath.relative_to(scenedirpath)
    col = ColReader()
    with colpath.open('rb') as fin:
        col.read(fin)
    outcoldir = outpath / colpath_rel.parent
    outcoldir.mkdir(parents=True, exist_ok=True)
    cols[colpath_rel.stem.lower()] = list(exportCol(col, outcoldir, colpath_rel.stem))

if "kibako" in cols: cols["woodbox"] = cols["kibako"]

scene = readsection(open(scenedirpath / "map" / "scene.bin", 'rb'))

ocs = OcclusionCullingSettings(getId(), '')
rs = RenderSettings(getId(), '')
lms = LightmapSettings(getId(), '')
nms = NavMeshSettings(getId(), '')

for o in scene.objects:
    if o.namehash == 0x3c2e: # MarScene
        marScene = o
        break

for o in marScene.objects:
    if o.namehash == 0x6e9e and len(o.objects) > 0: # AmbAry
        ambColor = o.objects[0]
        assert ambColor.namehash == 0xe529 # AmbColor
        rs.m_AmbientSkyColor = {'r': ambColor.r/255, 'g': ambColor.g/255, 'b': ambColor.b/255, 'a': ambColor.a/255}
        rs.m_AmbientMode = 3
        rs.m_AmbientIntensity = 1
        if len(o.objects) > 1:
            ambColor = o.objects[1]
            assert ambColor.namehash == 0xe529 # AmbColor
            rs.m_SubtractiveShadowColor = {'r': ambColor.r/255, 'g': ambColor.g/255, 'b': ambColor.b/255, 'a': ambColor.a/255}
        break

scene = unityparser.UnityDocument([ocs, rs, lms, nms])

for o in marScene.objects:
    if o.namehash == 0x4746: # LightAry
        lightgrpObj, lightgrpXfm = setupObject(o)
        lightgrpXfm.m_Children = []
        for o2 in o.objects:
            assert o2.namehash == 0x286a # Light
            objObj, objXfm = setupObject(o2)
            light = Light(getId(), '')
            scene.entries.append(light)
            objObj.m_Component.append({'component': getObjRef(light)})
            light.m_GameObject = getObjRef(objObj)
            setupPosition(objXfm, o2)
            light.m_Color = {'r': o2.r/255, 'g': o2.g/255, 'b': o2.b/255, 'a': o2.a/255}
            light.m_Intensity = o2.intensity
            lightgrpXfm.m_Children.append(getObjRef(objXfm))
            objXfm.m_Father = getObjRef(lightgrpXfm)
    if o.namehash == 0xabc3: # Strategy
        strategy = o

def addCol(colname, objObj):
    for uuid in cols[colname]:
        coll = MeshCollider(getId(), '')
        scene.entries.append(coll)
        objObj.m_Component.append({'component': getObjRef(coll)})
        coll.m_GameObject = getObjRef(objObj)
        coll.serializedVersion = 3
        coll.m_Enabled = 1
        coll.m_Mesh = getFileRef(uuid, id=4300000)

for group in strategy.objects:
    assert group.namehash == 0x2682
    grpObj, grpXfm = setupObject(group)
    grpXfm.m_Children = []
    for o in group.objects:
        objObj, objXfm = setupObject(o)
        grpXfm.m_Children.append(getObjRef(objXfm))
        objXfm.m_Father = getObjRef(grpXfm)
        if hasattr(o, "rx"):
            setup3d(objXfm, o)
        if hasattr(o, "model"):
            lowername = o.model.lower()
            if lowername in cols:
                addCol(colname, objObj)
            if (scenedirpath / "mapobj" / (lowername+".bmd")).exists():
                renderer = MeshRenderer(getId(), '')
                scene.entries.append(renderer)
                objObj.m_Component.append({'component': getObjRef(renderer)})
                renderer.m_GameObject = getObjRef(objObj)
                meshFilter = MeshFilter(getId(), '')
                scene.entries.append(meshFilter)
                objObj.m_Component.append({'component': getObjRef(meshFilter)})
                meshFilter.m_GameObject = getObjRef(objObj)
        if o.namehash == 0x0448: # Map
            addCol("map", objObj)
            objXfm.m_LocalScale = {'x': SCALE, 'y': SCALE, 'z': -1*SCALE}

scene.dump_yaml(outpath / "map" / "scene.unity")

