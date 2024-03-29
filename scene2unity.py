from scenebin import *
from classes import *
import unityparser, transforms3d, numpy
from math import radians, degrees, tan, log
import pathlib, sys, inspect
from unityassets import writeMeta, writeNativeMeta, fixUnityParserFloats, getFileRef, getObjRef

fixUnityParserFloats()

SCALE = 1/100 # game units measure centimeters

gocci = unityparser.constants.UnityClassIdMap.get_or_create_class_id

Material = gocci(21, 'Material')

Transform = gocci(4, 'Transform')
Camera = gocci(20, 'Camera')
MeshRenderer = gocci(23, 'MeshRenderer')
MeshFilter = gocci(33, 'MeshFilter')
OcclusionPortal = gocci(41, 'OcclusionPortal')
Skybox = gocci(45, 'Skybox')
Rigidbody = gocci(54, 'Rigidbody')
Collider = gocci(56, 'Collider')
Joint = gocci(57, 'Joint')
HingeJoint = gocci(59, 'HingeJoint')
MeshCollider = gocci(64, 'MeshCollider')
BoxCollider = gocci(65, 'BoxCollider')
ConstantForce = gocci(75, 'ConstantForce')
AudioSource = gocci(82, 'AudioSource')
Animator = gocci(95, 'Animator')
TrailRenderer = gocci(96, 'TrailRenderer')
TextMesh = gocci(102, 'TextMesh')
Light = gocci(108, 'Light')
MonoBehaviour = gocci(114, 'MonoBehaviour')
Projector = gocci(119, 'Projector')
LineRenderer = gocci(120, 'LineRenderer')
Halo = gocci(122, 'Halo')
LensFlare = gocci(123, 'LensFlare')
FlareLayer = gocci(124, 'FlareLayer')
PhysicMaterial = gocci(134, 'PhysicMaterial')
SphereCollider = gocci(135, 'SphereCollider')
CapsuleCollider = gocci(136, 'CapsuleCollider')
SkinnedMeshRenderer = gocci(137, 'SkinnedMeshRenderer')
FixedJoint = gocci(138, 'FixedJoint')
CharacterJoint = gocci(144, 'CharacterJoint')
SpringJoint = gocci(145, 'SpringJoint')
WheelCollider = gocci(146, 'WheelCollider')
ConfigurableJoint = gocci(153, 'ConfigurableJoint')
TerrainCollider = gocci(154, 'TerrainCollider')
AudioReverbFilter = gocci(164, 'AudioReverbFilter')
AudioHighPassFilter = gocci(165, 'AudioHighPassFilter')
AudioChorusFilter = gocci(166, 'AudioChorusFilter')
AudioReverbZone = gocci(167, 'AudioReverbZone')
AudioEchoFilter = gocci(168, 'AudioEchoFilter')
AudioLowPassFilter = gocci(169, 'AudioLowPassFilter')
AudioDistortionFilter = gocci(170, 'AudioDistortionFilter')
WindZone = gocci(182, 'WindZone')
Cloth = gocci(183, 'Cloth')
OffMeshLink = gocci(191, 'OffMeshLink')
OcclusionArea = gocci(192, 'OcclusionArea')
Tree = gocci(193, 'Tree')
NavMeshAgent = gocci(195, 'NavMeshAgent')
ParticleSystem = gocci(198, 'ParticleSystem')
ParticleSystemRenderer = gocci(199, 'ParticleSystemRenderer')
LODGroup = gocci(205, 'LODGroup')
NavMeshObstacle = gocci(208, 'NavMeshObstacle')
SpriteRenderer = gocci(212, 'SpriteRenderer')
ReflectionProbe = gocci(215, 'ReflectionProbe')
Terrain = gocci(218, 'Terrain')
LightProbeGroup = gocci(220, 'LightProbeGroup')
CanvasRenderer = gocci(222, 'CanvasRenderer')
Canvas = gocci(223, 'Canvas')
RectTransform = gocci(224, 'RectTransform')
CanvasGroup = gocci(225, 'CanvasGroup')
BillboardRenderer = gocci(227, 'BillboardRenderer')
LightProbeProxyVolume = gocci(259, 'LightProbeProxyVolume')
PlayableDirector = gocci(320, 'PlayableDirector')
VideoPlayer = gocci(328, 'VideoPlayer')
SpriteMask = gocci(331, 'SpriteMask')
Grid = gocci(156049354, 'Grid')
TilemapRenderer = gocci(483693784, 'TilemapRenderer')
GridLayout = gocci(1742807556, 'GridLayout')
Tilemap = gocci(1839735485, 'Tilemap')

OcclusionCullingSettings = gocci(29, 'OcclusionCullingSettings')
RenderSettings = gocci(104, 'RenderSettings')
LightmapSettings = gocci(157, 'LightmapSettings')
NavMeshSettings = gocci(196, 'NavMeshSettings')

lastId = 0
def getId():
    global lastId
    lastId += 1
    return str(lastId)

_GameObject = gocci(1, 'GameObject')
class GameObject(_GameObject):
    def getOrCreateComponent(self, type):
        component = type(getId(), '')
        scene.entries.append(component)
        self.m_Component.append({'component': getObjRef(component)})
        component.m_GameObject = getObjRef(self)
        return component

class ComponentProxy:
    def __init__(self, prefabGuid, prefabInstance, targetComponentId, type):
        self._modification = prefabInstance.m_Modification
        self._modifications = dict()
        self._prefabId = int(prefabInstance.anchor)
        self._targetComponentId = targetComponentId
        self._prefabGuid = prefabGuid
        self._strippedComponent = None
        self._type = type
    
    def __getattr__(self, attr):
        if attr == 'anchor':
            if self._strippedComponent is None:
                self._strippedComponent = self._type(getId(), ' stripped')
                self._strippedComponent.m_CorrespondingSourceObject = {'fileID': self._targetComponentId, 'guid': self._prefabGuid, 'type': 3}
                self._strippedComponent.m_PrefabInstance = {'fileID': self._prefabId}
                self._strippedComponent.m_PrefabAsset: {'fileID': 0}
                scene.entries.append(self._strippedComponent)
            return self._strippedComponent.anchor
        elif attr in self._modifications:
            if self._modifications[attr]['objectReference']['fileID'] != 0:
                return self._modifications[attr]['objectReference']
            else:
                return self._modifications[attr]['value']
        else:
            return super().__getattr__(attr)
    
    def _addModification(self, attr, value='', objectReference=None):
        if objectReference is None: objectReference = {'fileID': 0}
        if attr in self._modifications:
            self._modifications[attr]['value'] = value
            self._modifications[attr]['objectReference'] = objectReference
        else:
            m = {
                'target': {'fileID': self._targetComponentId, 'guid': self._prefabGuid, 'type': 3},
                'propertyPath': attr,
                'value': value,
                'objectReference': objectReference
            }
            self._modifications[attr] = m
            self._modification['m_Modifications'].append(m)
    
    def _addOverride(self, attr, value):
        if isinstance(value, dict):
            if 'fileID' in value:
                if attr == 'm_Father':
                    self._modification['m_TransformParent'] = value
                else:
                    # FIXME: objectReference.fileID changes, not sure how
                    self._addModification(attr, objectReference=value)
            else:
                for k, sub in value.items():
                    self._addOverride(attr+'.'+k, sub)
        elif isinstance(value, list):
            self._addModification(attr+'.Array.size', len(value))
            for i, sub in enumerate(value):
                self._addOverride('%s.Array.data[%d]'%(attr,i), sub)
        else:
            self._addModification(attr, value)
    
    def __setattr__(self, attr, value):
        if attr.startswith('_'):
            return super().__setattr__(attr, value)
        else:
            self._addOverride(attr, value)

_PrefabInstance = gocci(1001, 'PrefabInstance')
class PrefabInstance(_PrefabInstance):
    def __init__(self, prefabGuid, prefabYaml):
        super().__init__(getId(), '')
        self._prefabGuid = prefabGuid
        self.m_SourcePrefab = {'fileID': 100100000, 'guid': self._prefabGuid, 'type': 3}
        self.m_Modification = {'m_TransformParent': {'fileID': 0}, 'm_Modifications': [], 'm_RemovedComponents': []}
        anchorKey = 0
        self._componentPrefabs = []
        while True:
            isVariant = None
            for componentPrefab in prefabYaml.entries:
                if isinstance(componentPrefab, Transform) and componentPrefab.m_Father == {'fileID': 0}:
                    gameObjectId = componentPrefab.m_GameObject['fileID']
                    isVariant = False
                    break
                elif isinstance(componentPrefab, _PrefabInstance) and componentPrefab.m_Modification['m_TransformParent'] == {'fileID': 0}:
                    rootPrefabInstance = componentPrefab
                    gameObjectProxies = [subComp for subComp in prefabYaml.entries if isinstance(subComp, _GameObject) and subComp.extra_anchor_data == ' stripped' and subComp.m_PrefabInstance == {'fileID': int(componentPrefab.anchor)}]
                    if len(gameObjectProxies) == 0:
                        gameObjectId = None
                    elif len(gameObjectProxies) == 1:
                        gameObjectId = int(gameObjectProxies[0].anchor)
                    else:
                        assert False, gameObjectProxies
                    isVariant = True
                    break
            assert isVariant is not None
            # NOTE does not support children
            self._componentPrefabs.extend((subComp, anchorKey) for subComp in prefabYaml.entries if hasattr(subComp, "m_GameObject") and subComp.m_GameObject['fileID'] == gameObjectId)
            if isVariant:
                anchorKey ^= int(rootPrefabInstance.anchor)
                prefabYaml = prefabsByGuid[rootPrefabInstance.m_SourcePrefab['guid']]
            else:
                break
        self._strippedGameObject = ComponentProxy(self._prefabGuid, self, gameObjectId^anchorKey, GameObject)
    
    def __setattr__(self, attr, value):
        if attr.startswith('_') or attr in {'m_ObjectHideFlags', 'serializedVersion', 'm_Modification', 'm_SourcePrefab', 'anchor', 'extra_anchor_data'}:
            return super().__setattr__(attr, value)
        else:
            setattr(self._strippedGameObject, attr, value)
    
    def getOrCreateComponent(self, type):
        for componentPrefab, anchorKey in self._componentPrefabs:
            if isinstance(componentPrefab, type):
                newComponent = ComponentProxy(self._prefabGuid, self, int(componentPrefab.anchor)^anchorKey, type)
                return newComponent
        newComponent = type(getId(), '')
        newComponent.m_GameObject = getObjRef(self._strippedGameObject)
        scene.entries.append(newComponent)
        return newComponent

    def get_attrs(self):
        # get attribute set except those belonging to the Python class
        return super().get_attrs() - {'_prefabGuid', '_componentPrefabs', '_strippedGameObject'}

    def get_serialized_properties_dict(self):
        # return a copy of the objects attributes but not the ones we don't want
        d = super().get_serialized_properties_dict()
        del d['_prefabGuid']
        del d['_componentPrefabs']
        del d['_strippedGameObject']
        return d

def setupObject(o):
    if o.name in prefabs:
        objObj = PrefabInstance(*prefabs[o.name])
        objObj.serializedVersion = 2
    else:
        objObj = None
        for superclass in inspect.getmro(type(o)):
            if superclass == object: break
            for name in superclass.names:
                if name in prefabs:
                    objObj = PrefabInstance(*prefabs[name])
                    objObj.serializedVersion = 2
                    break
        if objObj is None:
            objObj = GameObject(getId(), '')
            objObj.serializedVersion = 6
            objObj.m_Component = []
            objObj.m_IsActive = 1
    scene.entries.append(objObj)
    objObj.m_Name = o.description
    objXfm = objObj.getOrCreateComponent(Transform)
    objXfm.m_Children = []
    return objObj, objXfm

UndergroundShift = 528
def setupPosition(objXfm, o):
    x, y, z = SCALE*o.pos[0], SCALE*o.pos[1], -1*SCALE*o.pos[2]
    if y > 84 and y < 120 and abs(x) < 120 and abs(z) < 77:
        # put the rooms in the sky underground
        z += UndergroundShift
    objXfm.m_LocalPosition = {'x': x, 'y': y, 'z': z}

def setup3d(objXfm, o):
    setupPosition(objXfm, o)
    if hasattr(o, "scale"):
        rot = transforms3d.euler.euler2quat(radians(o.rot[0]), radians(180-o.rot[1]), radians(o.rot[2]))
        objXfm.m_LocalScale = {'x': SCALE*o.scale[0], 'y': SCALE*o.scale[1], 'z': -SCALE*o.scale[2]}
    else:
        rot = transforms3d.euler.euler2quat(radians(o.rot[0]), radians(o.rot[1]), radians(o.rot[2]))
    rot = transforms3d.quaternions.qmult(rot, [0,0,1,0])
    euler = transforms3d.euler.quat2euler(rot)
    objXfm.m_LocalEulerAnglesHint = {'x': euler[0], 'y': euler[1], 'z': euler[2]}
    objXfm.m_LocalRotation = dict(zip('wxyz', rot.tolist()))

def addCol(uuid, objObj):
    coll = objObj.getOrCreateComponent(MeshCollider)
    coll.serializedVersion = 3
    coll.m_Enabled = 1
    coll.m_Mesh = getFileRef(uuid, id=4300000)
    return coll

def lookAt(direction):
    up = numpy.array([0, 1, 0])
    right = numpy.cross(up, direction)
    res = right*numpy.dot(right, right)**-0.5
    mat = numpy.array([res,
                       numpy.cross(direction, res),
                       direction]).transpose()
    return list(map(degrees, transforms3d.euler.mat2euler(mat))), transforms3d.quaternions.mat2quat(mat)

def GammaToLinearSpaceExact(value):
    if value <= 0.04045:
        return value / 12.92
    elif value < 1.0:
        return ((value + 0.055) * (1.0 / 1.055)) ** 2.4
    else:
        return value ** 2.2

def color8ToLinear(c):
    res = GammaToLinearSpaceExact(c[0]/255), GammaToLinearSpaceExact(c[1]/255), GammaToLinearSpaceExact(c[2]/255)
    if len(c) == 4:
        res += (c[3]/255,)
    return res

def doColor(c):
    # XXX are these stored as linear?
    return dict(zip('rgba', (x/255 for x in c)))

import csv, os
AudioRes = pathlib.Path(os.getcwd()) / "AudioRes"
print("Loading sound table")
soundInfos = {int(row["InternalID"], 16): row for row in csv.DictReader(open(AudioRes / "msound.csv"))}
scenetime = pathlib.Path(__file__).stat().st_mtime
sounds = {}
from xml.dom import minidom
import shutil
def parseCommands(commands, category):
    labels = {}
    loop = False
    bank = inst = 0
    volume = 1.0
    notes = []
    transpose = 0
    for i, command in enumerate(commands):
        command = command.strip()
        if len(command) == 0 or command[0] == '#': continue
        if command[0] == ':':
            labels[command[1:]] = i
        else:
            command = command.split()
            command = [int(p[1:], 16) if p[0] == 'h' else int(p) if p.isdigit() else p for p in command]
            if command[0] == 'NOTEON2':
                key, flags, velocity = command[1:4]
                volume *= velocity/0x7F
                notes.append(key)
            elif command[0] == 'SET_BANK_INST':
                bank, inst = command[1:]
            elif command[0] == 'JMP':
                label = command[2]
                if label in labels and labels[label] < i:
                    loop = True
            elif command[0] == 'TRANSPOSE':
                #assert command[1] == 0x3C, command
                transpose = command[1]
            elif command[0] == 'SIMPLEADSR':
                attackTime, decayTime, decayTime2, sustainLevel, releaseTime = command[1:]
                volume *= sustainLevel/0xFFFF
            elif command[0] == '$REFERENCE':
                return parseCommands(open(AudioRes / "se" / category / (command[1]+".txt")), category)
    for i in range(len(notes)): notes[i] += transpose
    return loop, bank, inst, volume, notes[0]

def getSound(soundKey):
    if soundKey in sounds:
        return sounds[soundKey]
    soundInfo = soundInfos[soundKey]
    print(soundInfo["Name"])
    loop, bank, inst, volume, note = parseCommands(open(AudioRes / "se" / soundInfo["Category"] / (soundInfo["Name"]+".txt")), soundInfo["Category"])
    
    keys = ["C-", "C#", "D-", "Eb", "E-", "F-", "F#", "G-", "G#", "A-", "Bb", "B-"]
    ibnk = minidom.parse(open(AudioRes / "IBNK" / ("%d.xml"%bank)))
    for instrument in ibnk.firstChild.getElementsByTagName("instrument"):
        if int(instrument.getAttribute("program")) == inst:
            lastRegion = -1
            for keyRegion in instrument.getElementsByTagName("key-region"):
                if "key" in keyRegion.attributes:
                    regionKey = keyRegion.getAttribute("key")
                    regionKey = keys.index(regionKey[:2])+12*int(regionKey[2:])
                else:
                    regionKey = None
                if regionKey is None or (note > lastRegion and note <= regionKey):
                    if regionKey is None: regionKey = 0x3C
                    pitch = 2**((note-regionKey)/12.0)
                    velocityRegions = keyRegion.getElementsByTagName("velocity-region")
                    assert len(velocityRegions) == 1, velocityRegions
                    waveId = int(velocityRegions[0].getAttribute("wave-id"))
                    break
                lastRegion = regionKey
    for drumset in ibnk.firstChild.getElementsByTagName("drum-set"):
        if int(drumset.getAttribute("program")) == inst:
            pitch = 1.0
            key = (keys[note%12])+str(note//12)
            for percussion in drumset.getElementsByTagName("percussion"):
                if percussion.getAttribute("key") == key:
                    velocityRegions = percussion.getElementsByTagName("velocity-region")
                    assert len(velocityRegions) == 1, velocityRegions
                    waveId = int(velocityRegions[0].getAttribute("wave-id"))
                    break

    (outpath / "audio").mkdir(parents=True, exist_ok=True)
    metapath = outpath / "audio" / (soundInfo["Name"]+".wav.meta")
    destpath = outpath / "audio" / (soundInfo["Name"]+".wav")
    if metapath.exists() and metapath.stat().st_mtime >= scenetime:
        parsedInfo = (volume, pitch, loop, unityparser.UnityDocument.load_yaml(metapath).entry['guid'])
        sounds[soundKey] = parsedInfo
        return parsedInfo
    
    origPath = list((AudioRes / "waves").glob("w2ndLoad_0_%05d.*.wav"%waveId))[0]
    shutil.copy(origPath, destpath)
    guid = writeMeta(soundInfo["Name"]+".wav", {
        "AudioImporter": {
            "serializedVersion": 6,
            "defaultSettings": {
                "loadType": 1,
                "sampleRateSetting": 0,
                "compressionFormat": 2,
                "quality": 1,
                "conversionMode": 0
            },
            "forceToMono": 0,
            "normalize": 0,
            "preloadAudioData": 1,
            "loadInBackground": 0,
            "ambisonic": 0,
            "3D": 1
        }
    }, outpath / "audio")
    parsedInfo = (volume, pitch, loop, guid)
    sounds[soundKey] = parsedInfo
    return parsedInfo

scenedirpath = pathlib.Path(sys.argv[1])
assert scenedirpath.is_dir()
outpath = pathlib.Path(sys.argv[2])
assert outpath.is_dir()

prefabsByGuid = {}
prefabs = {}
for assetPath in (outpath / "prefabs").glob("*.prefab"):
    print(assetPath.stem)
    metapath = assetPath.with_suffix(".prefab.meta")
    guid = unityparser.UnityDocument.load_yaml(metapath).entry['guid']
    prefabData = unityparser.UnityDocument.load_yaml(assetPath)
    prefabsByGuid[guid] = prefabData
    prefabs[assetPath.stem] = guid, prefabData

import texture, bti
btitime = max(pathlib.Path(texture.__file__).stat().st_mtime, pathlib.Path(bti.__file__).stat().st_mtime)
from bti import Image
from bmd2unity import exportTexture

btis = {}
for btipath in scenedirpath.rglob("*.bti"):
    btipath_rel = btipath.relative_to(scenedirpath)
    print(btipath_rel)
    outbtidir = outpath / btipath_rel.parent
    metapathDds = outbtidir / (btipath_rel.stem+".ktx.meta")
    metapathPng = outbtidir / (btipath_rel.stem+".png.meta")
    if metapathPng.exists() and metapathPng.stat().st_mtime >= btitime:
        btis[btipath.stem.lower()] = unityparser.UnityDocument.load_yaml(metapathPng).entry['guid']
    elif metapathDds.exists() and metapathDds.stat().st_mtime >= btitime:
        btis[btipath.stem.lower()] = unityparser.UnityDocument.load_yaml(metapathDds).entry['guid']
    else:
        bti = Image()
        with btipath.open('rb') as fin:
            bti.read(fin, 0, 0, 0)
        bti.name = btipath_rel.stem

        outbtidir.mkdir(parents=True, exist_ok=True)
        btis[btipath.stem.lower()] = exportTexture(bti, outbtidir)

import col2unity, col
coltime = max(pathlib.Path(col2unity.__file__).stat().st_mtime, pathlib.Path(col.__file__).stat().st_mtime)
from col import ColReader
from col2unity import exportCol

cols = {}
for colpath in scenedirpath.rglob("*.col"):
    colpath_rel = colpath.relative_to(scenedirpath)
    print(colpath_rel)
    outcoldir = outpath / colpath_rel.parent
    metapaths = list(outcoldir.glob(colpath_rel.stem+"-*.asset.meta"))
    if len(metapaths) > 0 and all(metapath.stat().st_mtime >= coltime for metapath in metapaths):
        cols[str(colpath_rel.with_suffix('')).lower()] = [(metapath.stem[:-5], unityparser.UnityDocument.load_yaml(metapath).entry['guid'], unityparser.UnityDocument.load_yaml(metapath.with_suffix('')).entry.m_LocalAABB['m_Center']) for metapath in metapaths]
    else:
        col = ColReader()
        with colpath.open('rb') as fin:
            col.read(fin)
        outcoldir.mkdir(parents=True, exist_ok=True)
        cols[str(colpath_rel.with_suffix('')).lower()] = list(exportCol(col, outcoldir, colpath_rel.stem, colpath_rel.stem == "map"))

import bmd2unity, bmd, shadergen2
bmdtime = max(pathlib.Path(bmd2unity.__file__).stat().st_mtime, pathlib.Path(bmd.__file__).stat().st_mtime, pathlib.Path(shadergen2.__file__).stat().st_mtime, btitime)
from bmd import BModel, VtxDesc, VtxAttr, VtxAttrIn, CompType, CompSize, ArrayFormat
from bmd2unity import exportBmd, exportTextures, exportMaterials, splitByVertexFormat, addNormals, splitByConnectedPieces, buildMesh, exportAsset, kVertexFormat
import xatlas

def getChannelData(uChannels, uniqueVertices, ch):
    if uChannels[ch]["dimension"] > 0:
        start = sum(channel["dimension"] for channel in uChannels[:ch] if channel["stream"] == uChannels[ch]["stream"])
        end = start+uChannels[ch]["dimension"]
        return [vert[start:end] for vert in uniqueVertices[uChannels[ch]["stream"]]]
    else:
        return None

bmds = {}
for bmdpath in scenedirpath.rglob("*.bmd"):
    bmdpath_rel = bmdpath.relative_to(scenedirpath)
    print(bmdpath_rel)
    outbmddir = outpath / bmdpath_rel.parent
    bmd = BModel()
    bmd.name = bmdpath_rel.stem.lower()
    with bmdpath.open('rb') as fin:
        bmd.read(fin)
    bmddatadir = outbmddir / bmdpath_rel.stem
    bmddatadir.mkdir(parents=True, exist_ok=True)
    bmdkey = str(bmdpath_rel).lower()
    if bmd.name in ("map", "sky"):
        #print("Exporting textures")
        textureIds = list(exportTextures(bmd.tex1.textures, bmddatadir))
        
        #print("Exporting materials")
        useColor1 = all(map(bool, bmd.vtx1.colors))
        materialIds = list(exportMaterials(bmd.mat3.materials[:max(bmd.mat3.remapTable)+1], bmd.mat3.indirectArray, bmd.tex1.textures, bmddatadir, textureIds, useColor1, 1/SCALE, True))
        
        meshes = []
        for subBmd in splitByVertexFormat(bmd):
            for i, subSubBmd in enumerate([subBmd]):#splitByConnectedPieces(subBmd) if bmd.name == "map" else [subBmd]):
                meshes.append((subSubBmd, buildMesh(subSubBmd)))
        atlas = xatlas.Atlas()
        for subSubBmd, (subMeshTriangles, subMeshVertices, uniqueVertices, uChannels, vertexStruct, bboxes) in meshes:
            if uChannels[5]["dimension"] > 0:
                continue
            positions = getChannelData(uChannels, uniqueVertices, 0)
            # only seed with normals if they weren't generated
            if 'NRM' in subSubBmd.name:
                normals = getChannelData(uChannels, uniqueVertices, 1)
            else:
                normals = None
            uvs = getChannelData(uChannels, uniqueVertices, 4)
            #materialIndices = [i for i, indices in enumerate(subMeshTriangles) for j in range(len(indices)//3)]
            indices = [idx for indices in subMeshTriangles for idx in indices]
            indices = list(zip(indices[0::3], indices[1::3], indices[2::3]))
            # parameter order does not match documentation!!!
            atlas.add_mesh(positions, indices, normals, uvs)
        print("Generating atlas")
        packOpt = xatlas.PackOptions()
        packOpt.padding = 2
        # largest mesh size is 125967.453125
        #packOpt.texels_per_unit = 40/100
        packOpt.resolution = 4096
        atlas.generate(pack_options=packOpt, verbose=True)
        atlasIdx = 0
        bmds[bmdkey] = []
        for subSubBmd, (subMeshTriangles, subMeshVertices, uniqueVertices, uChannels, vertexStruct, bboxes) in meshes:
            if 0:#uChannels[5]["dimension"] == 0:
                vmapping, newIndices, uvs = atlas[atlasIdx]
                assert len(newIndices)*3 == sum(map(len, subMeshTriangles))
                assert len(uvs) == len(vmapping)
                scaleInLightmap = float(max(uvs[:,0].max()-uvs[:,0].min(), uvs[:,1].max()-uvs[:,1].min()))
                scaleInLightmap /= 4095/4096
                scaleInLightmap = min(scaleInLightmap, 1)
                
                groupedTriangles = [set(zip(indices[0::3], indices[1::3], indices[2::3])) for indices in subMeshTriangles]
                # set is not equivalent to list
                # meaning some tris are duplicate
                # bug in splitByConnected? or the index mapping func?
                newSubMeshTriangles = [[] for x in subMeshTriangles]
                for newTriangle in newIndices:
                    oldTriangle = tuple(vmapping[idx] for idx in newTriangle)
                    found = False
                    for triGrpIdx, oldTriGrp in enumerate(groupedTriangles):
                        if oldTriangle in oldTriGrp:
                            assert not found, "triangle {} {} in two different submeshes".format(newTriangle, oldTriangle)
                            found = True
                            newSubMeshTriangles[triGrpIdx].extend(map(int, newTriangle))
                    assert found, "can't find new {} old {}".format(newTriangle, oldTriangle)
                subMeshTriangles = newSubMeshTriangles
                
                isOpaque = all(subSubBmd.mat3.materials[matIdx].zCompLoc and subSubBmd.mat3.materials[matIdx].materialMode != 4 for matIdx in subSubBmd.mat3.remapTable)
                stream = 2 if isOpaque else 1

                uniqueVertices = [[vertexStream[oldIdx] for oldIdx in vmapping] for vertexStream in uniqueVertices]
                uniqueVertices[stream] = [uniqueVertex+tuple(uv) for uniqueVertex, uv in zip(uniqueVertices[stream], uvs)]
                
                uChannels[5]["stream"] = stream
                uChannels[5]["offset"] = vertexStruct[stream].size
                uChannels[5]["format"] = kVertexFormat.Float
                uChannels[5]["dimension"] = 2

                vertexStruct[stream] = struct.Struct(vertexStruct[stream].format+'2f')
                
                atlasIdx += 1
            else:
                scaleInLightmap = 1
            materialIdInSlot = [materialIds[matIndex] for matIndex in subSubBmd.mat3.remapTable]
            bmds[bmdkey].append((subSubBmd.name, exportAsset(subSubBmd, outbmddir, subMeshTriangles, subMeshVertices, uniqueVertices, uChannels, vertexStruct, bboxes), materialIdInSlot, scaleInLightmap))
        del meshes
    else:
        metapath = outbmddir / (bmdpath_rel.stem+".asset.meta")
        armmetapath = outbmddir / (bmdpath_rel.stem+"_arm.prefab.meta")
        if metapath.exists() and metapath.stat().st_mtime >= bmdtime:
            if armmetapath.exists():
                armYaml = unityparser.UnityDocument.load_yaml(armmetapath.with_suffix(""))
                armInfo = (
                    unityparser.UnityDocument.load_yaml(armmetapath).entry['guid'],
                    armYaml,
                    [go.m_Component[0]['component']['fileID'] for joint in bmd.jnt1.frames for go in armYaml.entries if isinstance(go, _GameObject) and go.m_Name == joint.name]
                )
            else:
                armInfo = None
            bmds[bmdkey] = bmd.name, (
                unityparser.UnityDocument.load_yaml(metapath).entry['guid'],
                armInfo,
                unityparser.UnityDocument.load_yaml(metapath.with_suffix("")).entry.m_LocalAABB
            ), [unityparser.UnityDocument.load_yaml(bmddatadir / (bmd.mat3.materials[matIdx].name+".mat.meta")).entry['guid'] for matIdx in bmd.mat3.remapTable], 1
        else:
            #print("Exporting textures")
            textureIds = list(exportTextures(bmd.tex1.textures, bmddatadir))
            
            #print("Exporting materials")
            useColor1 = all(map(bool, bmd.vtx1.colors))
            materialIds = list(exportMaterials(bmd.mat3.materials[:max(bmd.mat3.remapTable)+1], bmd.mat3.indirectArray, bmd.tex1.textures, bmddatadir, textureIds, useColor1, 1/SCALE, False))
            materialIdInSlot = [materialIds[matIndex] for matIndex in bmd.mat3.remapTable]
            bmds[bmdkey] = bmd.name, exportBmd(bmd, outbmddir), materialIdInSlot, 1

materials = {}
for bmtpath in scenedirpath.rglob("*.bmt"):
    bmtpath_rel = bmtpath.relative_to(scenedirpath)
    print(bmtpath_rel)
    outbmtdir = outpath / bmtpath_rel.parent
    bmt = BModel()
    bmt.name = bmtpath_rel.stem.lower()
    with bmtpath.open('rb') as fin:
        bmt.read(fin)
    bmtdatadir = outbmtdir / bmtpath_rel.stem
    bmtdatadir.mkdir(parents=True, exist_ok=True)
    bmtkey = str(bmtpath_rel).lower()
    #print("Exporting textures")
    textureIds = list(exportTextures(bmt.tex1.textures, bmtdatadir))
    
    #print("Exporting materials")
    if hasattr(bmt, "mat3"):
        materialIds = list(exportMaterials(bmt.mat3.materials[:max(bmt.mat3.remapTable)+1], bmt.mat3.indirectArray, bmt.tex1.textures, bmtdatadir, textureIds, True, 1/SCALE, bmt.name in ("map", "sky")))
        materialIdInSlot = [materialIds[matIndex] for matIndex in bmt.mat3.remapTable]
        materials[bmtkey] = bmt.name, materialIdInSlot

from sObjDataTable import sObjDataTable, end_data

physMaterials = {}
physDir = (outpath / "physics")
physDir.mkdir(parents=True, exist_ok=True)
for name, objData in sObjDataTable.items():
    physicalInfo = objData.get('physicalInfo')
    if physicalInfo is not None:
        print(name)
        physicalData = physicalInfo['physicalData']
        physMat = PhysicMaterial(str(13400000), '')
        physMat.m_Name = name
        physMat.dynamicFriction = physicalData[4]**30 # floorFriction
        physMat.staticFriction = max(physicalData[3]/5, physMat.dynamicFriction) # sleepVelocityThreshold
        physMat.bounciness = physicalData[1] # floorBounceSpeed
        physMat.frictionCombine = 3 # maximum
        physMat.bounceCombine = 3 # maximum
        asset = unityparser.UnityDocument([physMat])
        assetName = name+".physicMaterial"
        asset.dump_yaml(physDir / assetName)
        physMaterials[name] = writeNativeMeta(assetName, 13400000, physDir)

print("Opening scene")
scene = readsection(open(scenedirpath / "map" / "scene.bin", 'rb'))

ocs = OcclusionCullingSettings(getId(), '')
rs = RenderSettings(getId(), '')
lms = LightmapSettings(getId(), '')
nms = NavMeshSettings(getId(), '')

# color of dynamic shadows on static objects
# probably never used
rs.m_SubtractiveShadowColor = {'r': 16/255, 'g': 40/255, 'b': 109/255, 'a': 255/255}
rs.serializedVersion = 9

# Subtractive light mode. Only works if the main light is set to realtime-only.
lms.m_UseShadowmask = 0
lms.m_LightmapEditorSettings = {"serializedVersion": 12, "m_MixedBakeMode": 1, "m_AtlasSize": 4096}

managers = scene.search("コンダクター初期化用")
for o in managers.objects:
    if isinstance(o, TMapObjBaseManager):
        o.lodClipSize = 1/(tan(radians(25))*o.farClip)

for o in scene.objects:
    if o.name == 'MarScene':
        marScene = o
        break

for o in marScene.objects:
    if o.name == 'AmbAry' and len(o.objects) > 0:
        ambColor = o.search("太陽アンビエント（オブジェクト）")
        assert ambColor.name == 'AmbColor'
        # it seems that sky color and equator color are picked up by light
        # probes, ground color is not
        rs.m_AmbientSkyColor = {'r': 0/255, 'g': 113/255, 'b': 188/255, 'a': 255/255}
        rs.m_AmbientEquatorColor = {'r': 205/255, 'g': 215/255, 'b': 255/255, 'a': 255/255}
        rs.m_AmbientGroundColor = doColor(ambColor.color)
        rs.m_AmbientMode = 1 # gradient mode. no skybox, and single color would affect light probes
        rs.m_AmbientIntensity = 1
        rs.m_SkyboxMaterial = {'fileID': 0}

scene = unityparser.UnityDocument([ocs, rs, lms, nms])

print("Adding base colliders")
for baseColliderName in ["map/map", "map/map/building01", "map/map/building02"]:
    if baseColliderName not in cols: continue
    grpObj = GameObject(getId(), '')
    scene.entries.append(grpObj)
    grpObj.m_Name = baseColliderName
    grpObj.m_IsActive = 1
    grpObj.serializedVersion = 6
    grpObj.m_Component = []
    grpXfm = grpObj.getOrCreateComponent(Transform)
    grpXfm.m_Children = []
    colliderGroups = {}
    for physName, uuid, center in cols[baseColliderName]:
        baseName = physName.split('.')[0]
        assert baseName.startswith(baseColliderName.split('/')[-1])
        baseName = baseName[len(baseColliderName.split('/')[-1])+1:]
        if baseColliderName == "map/map":
            if center['y'] >= 8400 and center['y'] < 12002 and abs(center['x']) < 12031 and abs(center['z']) < 7696:
                # put the rooms in the sky underground
                baseName += "-interior"
        if baseName in colliderGroups:
            objObj = colliderGroups[baseName]
        else:
            objObj = GameObject(getId(), '')
            scene.entries.append(objObj)
            objObj.m_Name = baseName
            objObj.m_IsActive = 1
            objObj.serializedVersion = 6
            objObj.m_Component = []
            objXfm = objObj.getOrCreateComponent(Transform)
            objXfm.m_RootOrder = len(grpXfm.m_Children)
            grpXfm.m_Children.append(getObjRef(objXfm))
            objXfm.m_Father = getObjRef(grpXfm)
            objXfm.m_LocalScale = {'x': SCALE, 'y': SCALE, 'z': -1*SCALE}
            if baseName.endswith("-interior"):
                objXfm.m_LocalPosition = {'x': 0.0, 'y': 0.0, 'z': float(UndergroundShift)}
            colliderGroups[baseName] = objObj
        addCol(uuid, objObj)

for o in marScene.objects:
    if o.name == 'LightAry':
        lightgrpObj, lightgrpXfm = setupObject(o)
        o2 = o.search("太陽（オブジェクト）")
        assert o2.name == 'Light'
        objObj, objXfm = setupObject(o2)
        
        setupPosition(objXfm, o2)
        
        euler, quat = lookAt(numpy.array([-o2.pos[0], -o2.pos[1], o2.pos[2]]))
        objXfm.m_LocalEulerAnglesHint = dict(zip('xyz', euler))
        objXfm.m_LocalRotation = dict(zip('wxyz', quat.tolist()))
        
        objXfm.m_RootOrder = len(lightgrpXfm.m_Children)
        lightgrpXfm.m_Children.append(getObjRef(objXfm))
        objXfm.m_Father = getObjRef(lightgrpXfm)
        
        light = objObj.getOrCreateComponent(Light)
        light.serializedVersion = 10
        light.m_Color = doColor(o2.color)
        light.m_Intensity = 1
        light.m_Type = 1 # directional
        light.m_Shadows = {"m_Type": 1} # hard shadows
        light.m_Lightmapping = 4 # realtime (required for subtractive GI)
    if o.name == 'Strategy':
        strategy = o

actorDataTable = {
    "SeaIndirect": {"modelName": "SeaIndirect", "unk9": 0x11210000, "unk15": 0, "flags16": 0x41},
    "ReflectParts": {"modelName": "ReflectParts", "unk9": 0x10210000, "unk15": 0, "flags16": 0x10},
    "ReflectSky": {"modelName": "ReflectSky", "unk9": 0x10210000, "unk15": 0, "flags16": 0x08},
    "sun_mirror": {"modelName": "sun_mirror", "unk9": 0x10220000, "unk15": 0, "flags16": 0x62},
    "sea": {"groupName": "マップグループ", "modelName": "sea", "unk9": 0x10220000, "unk15": 0, "flags16": 0x80},
    "falls": {"unk9": 0x10210000, "soundKey": 0x3022, "unk15": 0, "flags16": 0x00},
    "fountain": {"unk9": 0x10210000, "soundKey": 0x3000, "unk15": 0, "flags16": 0x00},
    "TopOfCorona": {"hitFlags": 0x40000024, "unk9": 0x10210000, "particle": "/scene/mapObj/ms_coronasmoke.jpa", "particleId": 0x146, "unk15": 1, "flags16": 0x00},
    "BiancoRiver": {"modelName": "BiancoRiver", "unk9": 0x10210000, "unk15": 0, "flags16": 0x40},
    "SoundObjRiver": {"unk9": 0x10210000, "soundKey": 0x500f, "unk15": 0, "flags16": 0x00},
    "SoundObjWaterIntoWater": {"unk9": 0x10210000, "soundKey": 0x5010, "unk15": 0, "flags16": 0x00},
    "BiancoAirWall": {"unk9": 0x10210000, "collisionManagerName": "BiaAirWall", "unk15": 0, "flags16": 0x02},
    "BiancoBossEffectLight": {"unk9": 0x10210000, "particle": "/scene/map/map/ms_wmlin_light.jpa", "particleId": 0x151, "unk15": 1, "flags16": 0x00},
    "BiaWaterPollution": {"modelName": "BiaWaterPollution", "unk9": 0x11220000, "unk15": 0, "flags16": 0x40},
    "riccoSea": {"unk9": 0x10210000, "collisionManagerName": "riccoSea", "unk15": 0, "flags16": 0x00},
    "riccoSeaPollutionS0": {"modelName": "riccoSeaPollutionS0", "unk9": 0x11210000, "collisionManagerName": "riccoSeaPollutionS0", "unk15": 0, "flags16": 0x40},
    "riccoSeaPollutionS1": {"modelName": "riccoSeaPollutionS1", "unk9": 0x11210000, "collisionManagerName": "riccoSeaPollutionS1", "unk15": 0, "flags16": 0x40},
    "riccoSeaPollutionS2": {"modelName": "riccoSeaPollutionS2", "unk9": 0x11210000, "collisionManagerName": "riccoSeaPollutionS2", "unk15": 0, "flags16": 0x40},
    "riccoSeaPollutionS3": {"modelName": "riccoSeaPollutionS3", "unk9": 0x11210000, "collisionManagerName": "riccoSeaPollutionS3", "unk15": 0, "flags16": 0x40},
    "riccoSeaPollutionS4": {"modelName": "riccoSeaPollutionS4", "unk9": 0x11210000, "collisionManagerName": "riccoSeaPollutionS4", "unk15": 0, "flags16": 0x40},
    "MareFalls": {"unk9": 0x10210000, "soundKey": 0x3000, "unk15": 0, "flags16": 0x00},
    "mareSeaPollutionS0": {"modelName": "mareSeaPollutionS0", "unk9": 0x10210000, "collisionManagerName": "mareSeaPollutionS0", "unk15": 0, "flags16": 0x00},
    "mareSeaPollutionS12": {"modelName": "mareSeaPollutionS12", "unk9": 0x10210000, "collisionManagerName": "mareSeaPollutionS12", "unk15": 0, "flags16": 0x00},
    "mareSeaPollutionS34567": {"unk9": 0x10210000, "collisionManagerName": "mareSeaPollutionS34567", "unk15": 0, "flags16": 0x00},
    "Mare5ExGate": {"modelName": "Mare5ExGate", "unk9": 0x10210000, "unk15": 0, "flags16": 0x40},
    "MonteRiver": {"modelName": "MonteRiver", "unk9": 0x10210000, "collisionManagerName": "MonteRiver", "unk15": 0, "flags16": 0x40},
    "IndirectObj": {"modelName": "IndirectObj", "unk9": 0x11210000, "unk15": 0, "flags16": 0x41},
    "TargetArrow": {"modelName": "TargetArrow", "unk9": 0x10210000, "unk15": 0, "flags16": 0x04},
}

def addMeshRenderer(bmdFilename, objObj, objXfm):
    if isinstance(bmdFilename, tuple):
        name, (asset, armInfo, aabb), materialIds, scaleInLightmap = bmdFilename
    else:
        name, (asset, armInfo, aabb), materialIds, scaleInLightmap = bmds[bmdFilename]
    if armInfo is None:
        renderer = objObj.getOrCreateComponent(MeshRenderer)

        meshFilter = objObj.getOrCreateComponent(MeshFilter)
        if asset is not None:
            meshFilter.m_Mesh = getFileRef(asset, id=4300000)
    else:
        prefabGuid, prefabYaml, bones = armInfo
        meshObj = GameObject(getId(), '')
        meshObj.serializedVersion = 6
        meshObj.m_Component = []
        meshObj.m_IsActive = 1
        scene.entries.append(meshObj)
        meshObj.m_Name = name+"_mesh"
        meshXfm = meshObj.getOrCreateComponent(Transform)
        meshXfm.m_RootOrder = len(objXfm.m_Children)
        objXfm.m_Children.append(getObjRef(meshXfm))
        meshXfm.m_Father = getObjRef(objXfm)
        renderer = meshObj.getOrCreateComponent(SkinnedMeshRenderer)
        if asset is not None:
            renderer.m_Mesh = getFileRef(asset, id=4300000)
        renderer.m_AABB = {'m_Center': aabb['m_Center'], 'm_Extent': aabb['m_Extent']}
        
        armObj = PrefabInstance(prefabGuid, prefabYaml)
        armObj.serializedVersion = 2
        scene.entries.append(armObj)
        armXfm = armObj.getOrCreateComponent(Transform)
        armXfm.m_RootOrder = len(objXfm.m_Children)
        objXfm.m_Children.append(getObjRef(armXfm))
        armXfm.m_Father = getObjRef(objXfm)
    
        renderer.m_Bones = [getObjRef(ComponentProxy(prefabGuid, armObj, origFileID, Transform)) for origFileID in bones]
        renderer.m_RootBone = dict(renderer.m_Bones[0]) # XXX assumption

    if materialIds is not None:
        renderer.m_Materials = [getFileRef(materialId, id=2100000) for materialId in materialIds]
    renderer.m_Enabled = 1
    renderer.m_CastShadows = 1
    renderer.m_ReceiveShadows = 0
    renderer.m_ReceiveGI = 2
    renderer.m_ScaleInLightmap = scaleInLightmap

    return renderer

def doActor(o, grpXfm):
    objObj, objXfm = setupObject(o)
    objXfm.m_RootOrder = len(grpXfm.m_Children)
    grpXfm.m_Children.append(getObjRef(objXfm))
    objXfm.m_Father = getObjRef(grpXfm)
    if isinstance(o, TActor):
        setup3d(objXfm, o)
    elif isinstance(o, TPlacement):
        setupPosition(objXfm, o)
    if isinstance(o, TMapObjBase):
        objData = sObjDataTable.get(o.model, end_data)
        
        animInfo = objData.get('animInfo')
        if animInfo is None:
            modelName = objData['mdlName']+".bmd"
        else:
            animData = animInfo.get('animData')
            if animData is None:
                modelName = None
            else:
                modelName = animData[0]['modelName']
                if animData[0].get('basName'):
                    audioSource = objObj.getOrCreateComponent(AudioSource)
                    audioSource.serializedVersion = 4
                    audioSource.m_Enabled = 1
                    audioSource.m_PlayOnAwake = 1
                    audioSource.rolloffMode = 0
        if modelName is not None:
            renderer = addMeshRenderer("mapobj/"+modelName.lower(), objObj, objXfm)
            
            manager = managers.search(objData['managerName'])
            lod = objObj.getOrCreateComponent(LODGroup)
            lod.m_FadeMode = 0
            lod.serializedVersion = 2
            aabb = bmds["mapobj/"+modelName.lower()][1][2]
            size = max(aabb["m_Extent"].values())
            lod.m_LODs = [{"screenRelativeHeight": size*manager.lodClipSize, "renderers": [{"renderer": getObjRef(renderer)}]}]
            lod.m_Size = size*2
            lod.m_LocalReferencePoint = aabb["m_Center"]
            # TODO: also do LOD for TLiveActor/TLiveManager. sometimes (TBoardNPCManager, TEnemyManager) clip params are from prm file
            
            if animInfo is not None and animData is not None:
                material = animData[0].get('material')
                if material is not None:
                    name, materialIds = materials["mapobj/"+material.lower()+".bmt"]
                    if materialIds is not None:
                        renderer.m_Materials = [getFileRef(materialId, id=2100000) for materialId in materialIds]
        
        mapCollisionInfo = objData.get('mapCollisionInfo')
        hitInfo = objData.get('objHitInfo')
        colliders = []
        if mapCollisionInfo is not None:
            colName = mapCollisionInfo['collisionData'][0]['name']
            for physName, uuid, center in cols["mapobj/"+colName.lower()]:
                # different terrain types ok?
                colliders.append(addCol(uuid, objObj))
        elif hitInfo is not None:
            hitData = hitInfo['hitDataTable'][0]
            if hitData['receiveRadius'] <= 0:
                hitRadius = hitData['attackRadius']
                hitHeight = hitData['attackHeight']
            else:
                hitRadius = hitData['receiveRadius']
                hitHeight = hitData['receiveHeight']
            if hitRadius > 0 or hitHeight > 0:
                if hitHeight > hitRadius*2:
                    collider = objObj.getOrCreateComponent(CapsuleCollider)
                    collider.m_Radius = hitRadius
                    collider.m_Height = hitHeight-2*hitRadius
                    collider.m_Center = {'x': 0, 'y': hitHeight/2, 'z': 0}
                elif hitHeight > hitRadius*0.5:
                    collider = objObj.getOrCreateComponent(SphereCollider)
                    collider.m_Radius = hitRadius
                    collider.m_Center = {'x': 0, 'y': hitHeight/2, 'z': 0}
                else:
                    collider = objObj.getOrCreateComponent(BoxCollider)
                    collider.m_Center = {'x': 0, 'y': hitHeight/2, 'z': 0}
                    collider.m_Size = {'x': hitRadius*2, 'y': hitHeight, 'z': hitRadius*2}
                colliders.append(collider)
        
        if isinstance(o, TResetFruit):
            if objData['objectID'] == 0x40000394:
                for collider in colliders:
                    collider.m_Center = {'x': 0, 'y': 50, 'z': 0}
            elif objData['objectID'] != 0x40000395:
                for collider in colliders:
                    collider.m_Center = {'x': 0, 'y': 0, 'z': 0}
            yPos = o.pos[1]
            yPos += hitHeight/2
            objXfm.m_LocalPosition = {'x': SCALE*o.pos[0], 'y': SCALE*yPos, 'z': -1*SCALE*o.pos[2]}
        
        physicalInfo = objData.get('physicalInfo')
        if physicalInfo is not None:
            rigidbody = objObj.getOrCreateComponent(Rigidbody)
            rigidbody.serializedVersion = 2
            physicalData = physicalInfo['physicalData']
            if physicalData[11] > 0.1: # throw distance
                rigidbody.m_Mass = 5/physicalData[11]
            elif objData['objectID'] == 0x400000D0:
                rigidbody.m_Mass = 0.4/0.5 # kick power
            else:
                rigidbody.m_Mass = 0.4/0.9
            rigidbody.m_Drag = -1*log(physicalData[6]**30) if physicalData[6] > 0 else float('inf') # horizDrag
            rigidbody.m_AngularDrag = -1*log(physicalData[5]**30) if physicalData[5] > 0 else float('inf') # rollBrakeFactor
            rigidbody.m_UseGravity = int(physicalData[0] > 0.1) # gravity
            #rigidbody.m_IsKinematic
            for collider in colliders:
                collider.m_Material = getFileRef(physMaterials[o.model], id=13400000)
        
        soundInfo = objData.get('soundInfo')
        if soundInfo is not None:
            audioSource = objObj.getOrCreateComponent(AudioSource)
            audioSource.serializedVersion = 4
            audioSource.m_Enabled = 1
            audioSource.m_PlayOnAwake = 1
            audioSource.rolloffMode = 0
            for soundKey in soundInfo['soundKeys']:
                if soundKey != -1: getSound(soundKey)
    if isinstance(o, TMapStaticObj):
        # not "static" in the unity sense
        modelEntry = actorDataTable.get(o.baseName, None)
        if modelEntry is None:
            warn("No static model for %r"%o.baseName)
        else:
            if 'modelName' in modelEntry:
                if modelEntry['flags16'] & 2 == 0:
                    if modelEntry['flags16'] & 4 == 0:
                        prefix = "map/map"
                    else:
                        prefix = "mapobj"
                else:
                    prefix = "map"
                    # todo: common arc
                bmdFilename = prefix+"/"+modelEntry['modelName'].lower()+".bmd"
                addMeshRenderer(bmdFilename, objObj, objXfm)
            if 'collisionManagerName' in modelEntry:
                for prefix in ("map/map/", "mapobj/"):
                    for physName, uuid, center in cols[prefix+modelEntry['collisionManagerName'].lower()]:
                        # different terrain types ok?
                        addCol(uuid, objObj)
            if 'soundKey' in modelEntry:
                audioSource = objObj.getOrCreateComponent(AudioSource)
                audioSource.serializedVersion = 4
                audioSource.m_Enabled = 1
                audioSource.m_PlayOnAwake = 1
                audioSource.rolloffMode = 0
                volume, pitch, loop, clipGuid = getSound(modelEntry['soundKey'])
                audioSource.m_audioClip = getFileRef(clipGuid, id=8300000, type=3)
                audioSource.m_Volume = volume
                audioSource.m_Pitch = pitch
                audioSource.Loop = int(loop)
            if 'particle' in modelEntry:
                objObj.getOrCreateComponent(ParticleSystemRenderer)
                objObj.getOrCreateComponent(ParticleSystem)
    if 0 and isinstance(o, TMapObjSoundGroup):
        audioSource = objObj.getOrCreateComponent(AudioSource)
        soundKey = {"ms_sea": 0x5000, "ms_harbor": 0x5003}.get(o.graphName, 0)
        if soundKey != 0:
            # arbitrary increment - the 2nd environment sounds are the longest
            # don't want to figure out the listen cone stuff
            volume, pitch, loop, clipGuid = getSound(soundKey+1)
            audioSource.m_audioClip = getFileRef(clipGuid, id=8300000, type=3)
            audioSource.serializedVersion = 4
            audioSource.m_Enabled = 1
            audioSource.m_PlayOnAwake = 1
            audioSource.rolloffMode = 0
            audioSource.m_Volume = volume
            audioSource.m_Pitch = pitch
            audioSource.Loop = int(loop)
    if isinstance(o, TMap):
        objObj.m_StaticEditorFlags = 0xFFFFFFFF
        objXfm.m_LocalScale = {'x': SCALE, 'y': SCALE, 'z': -SCALE}
        for assetAndMaterials in bmds["map/map/map.bmd"]:
            meshObj = GameObject(getId(), '')
            meshObj.serializedVersion = 6
            meshObj.m_Component = []
            meshObj.m_IsActive = 1
            meshObj.m_StaticEditorFlags = 0xFFFFFFFF
            meshObj.m_Name = assetAndMaterials[0]
            scene.entries.append(meshObj)
            meshXfm = meshObj.getOrCreateComponent(Transform)
            meshXfm.m_Father = getObjRef(objXfm)
            meshXfm.m_RootOrder = len(objXfm.m_Children)
            objXfm.m_Children.append(getObjRef(meshXfm))
            
            center = assetAndMaterials[1][2]["m_Center"]
            if center['y'] >= 9250 and center['y'] < 12002 and abs(center['x']) < 12031 and abs(center['z']) < 7696:
                # put the rooms in the sky underground
                meshXfm.m_LocalPosition = {'x': 0.0, 'y': 0.0, 'z': -float(UndergroundShift)/SCALE}
            
            renderer = addMeshRenderer(assetAndMaterials, meshObj, meshXfm)
            if center['x']**2 + center['y']**2 > 30430**2:
                renderer.m_CastShadows = 0
                meshObj.m_StaticEditorFlags &= ~0x01
                
        waveDistantView = TMapStaticObj()
        waveDistantView.name = "MapStaticObj"
        waveDistantView.description = "波（遠景）"
        waveDistantView.baseName = "sea"
        waveObj, waveXfm = doActor(waveDistantView, objXfm)
        waveXfm.m_LocalScale['x'] /= SCALE
        waveXfm.m_LocalScale['y'] /= SCALE
        waveXfm.m_LocalScale['z'] /= -SCALE
        
        indirectWave = TMapStaticObj()
        indirectWave.name = "MapStaticObj"
        indirectWave.description = "インダイレクト波"
        indirectWave.baseName = "SeaIndirect"
        waveObj, waveXfm = doActor(indirectWave, objXfm)
        waveXfm.m_LocalScale['x'] /= SCALE
        waveXfm.m_LocalScale['y'] /= SCALE
        waveXfm.m_LocalScale['z'] /= -SCALE
    if isinstance(o, TSky):
        objObj.m_StaticEditorFlags = 0xFFFFFFFF
        objXfm.m_LocalScale = {'x': SCALE, 'y': SCALE, 'z': -SCALE}
        for assetAndMaterials in bmds["map/map/sky.bmd"]:
            meshObj = GameObject(getId(), '')
            meshObj.serializedVersion = 6
            meshObj.m_Component = []
            meshObj.m_IsActive = 1
            meshObj.m_StaticEditorFlags = 0xFFFFFFFF
            meshObj.m_Name = assetAndMaterials[0]
            scene.entries.append(meshObj)
            meshXfm = meshObj.getOrCreateComponent(Transform)
            meshXfm.m_Father = getObjRef(objXfm)
            meshXfm.m_RootOrder = len(objXfm.m_Children)
            objXfm.m_Children.append(getObjRef(meshXfm))
            
            renderer = addMeshRenderer(assetAndMaterials, meshObj, meshXfm)
            renderer.m_CastShadows = 0
            name, materialIds = materials["map/map/sky.bmt"]
            #if materialIds is not None:
            #    renderer.m_Materials = [getFileRef(materialId, id=2100000) for materialId in materialIds]
    if isinstance(o, TSunModel):
        objObj.m_StaticEditorFlags = 0xFFFFFFFF
        objXfm.m_LocalScale = {'x': SCALE*2, 'y': SCALE*2, 'z': -2*SCALE}
        objXfm.m_LocalPosition = {k: v/4 for k, v in objXfm.m_LocalPosition.items()}
        
        # remove when adding billboard shader
        euler, quat = lookAt(numpy.array([o.pos[0], o.pos[1], -o.pos[2]]))
        objXfm.m_LocalEulerAnglesHint = dict(zip('xyz', euler))
        objXfm.m_LocalRotation = dict(zip('wxyz', quat.tolist()))
        
        renderer = addMeshRenderer("sun/model.bmd", objObj, objXfm)
        renderer.m_CastShadows = 0
    return objObj, objXfm

print("Adding actors")
for group in strategy.objects:
    assert group.name == 'IdxGroup'
    grpObj, grpXfm = setupObject(group)
    for o in group.objects:
        doActor(o, grpXfm)

print("Reading tables")
tables = readsection(open(scenedirpath / "map" / "tables.bin", 'rb'))
assert tables.name == "NameRefGrp"
for group in tables.objects:
    grpObj, grpXfm = setupObject(group)
    if group.name == "PositionHolder":
        for o in group.objects:
            assert o.name == "StagePositionInfo"
            objObj, objXfm = setupObject(o)
            objXfm.m_RootOrder = len(grpXfm.m_Children)
            grpXfm.m_Children.append(getObjRef(objXfm))
            objXfm.m_Father = getObjRef(grpXfm)
            setupPosition(objXfm, o)
    elif group.name == "CameraMapToolTable":
        cameraGameObjects = {}
        for o in group.objects:
            assert o.name == "CameraMapInfo"
            objObj, objXfm = setupObject(o)
            objXfm.m_RootOrder = len(grpXfm.m_Children)
            grpXfm.m_Children.append(getObjRef(objXfm))
            objXfm.m_Father = getObjRef(grpXfm)
            setup3d(objXfm, o)
            cameraGameObjects[o.description] = objObj.getOrCreateComponent(MonoBehaviour)
    elif group.name in ("CubeGeneralInfoTable", "StreamGeneralInfoTable"):
        for o in group.objects:
            objObj, objXfm = setupObject(o)
            objXfm.m_RootOrder = len(grpXfm.m_Children)
            grpXfm.m_Children.append(getObjRef(objXfm))
            objXfm.m_Father = getObjRef(grpXfm)
            setup3d(objXfm, o)
            
            if isinstance(o, TCubeCameraInfo) and o.cameraObject in cameraGameObjects:
                script = objObj.getOrCreateComponent(MonoBehaviour)
                script.publicVariablesUnityEngineObjects = [getObjRef(cameraGameObjects[o.cameraObject])]
                # I tried to make this part of the prefab...
                script.serializedPublicVariablesBytesString = """
Ai8AAAAAATIAAABWAFIAQwAuAFUAZABvAG4ALgBDAG8AbQBtAG8AbgAuAFUAZABvAG4AVgBhAHIAaQBh
AGIAbABlAFQAYQBiAGwAZQAsACAAVgBSAEMALgBVAGQAbwBuAC4AQwBvAG0AbQBvAG4AAAAAAAYBAAAA
AAAAACcBBAAAAHQAeQBwAGUAAWgAAABTAHkAcwB0AGUAbQAuAEMAbwBsAGwAZQBjAHQAaQBvAG4AcwAu
AEcAZQBuAGUAcgBpAGMALgBMAGkAcwB0AGAAMQBbAFsAVgBSAEMALgBVAGQAbwBuAC4AQwBvAG0AbQBv
AG4ALgBJAG4AdABlAHIAZgBhAGMAZQBzAC4ASQBVAGQAbwBuAFYAYQByAGkAYQBiAGwAZQAsACAAVgBS
AEMALgBVAGQAbwBuAC4AQwBvAG0AbQBvAG4AXQBdACwAIABtAHMAYwBvAHIAbABpAGIAAQEJAAAAVgBh
AHIAaQBhAGIAbABlAHMALwEAAAABaAAAAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBz
AC4ARwBlAG4AZQByAGkAYwAuAEwAaQBzAHQAYAAxAFsAWwBWAFIAQwAuAFUAZABvAG4ALgBDAG8AbQBt
AG8AbgAuAEkAbgB0AGUAcgBmAGEAYwBlAHMALgBJAFUAZABvAG4AVgBhAHIAaQBhAGIAbABlACwAIABW
AFIAQwAuAFUAZABvAG4ALgBDAG8AbQBtAG8AbgBdAF0ALAAgAG0AcwBjAG8AcgBsAGkAYgABAAAABgEA
AAAAAAAAAi8CAAAAAWQAAABWAFIAQwAuAFUAZABvAG4ALgBDAG8AbQBtAG8AbgAuAFUAZABvAG4AVgBh
AHIAaQBhAGIAbABlAGAAMQBbAFsAQwBpAG4AZQBtAGEAYwBoAGkAbgBlAC4AQwBpAG4AZQBtAGEAYwBo
AGkAbgBlAFYAaQByAHQAdQBhAGwAQwBhAG0AZQByAGEALAAgAEMAaQBuAGUAbQBhAGMAaABpAG4AZQBd
AF0ALAAgAFYAUgBDAC4AVQBkAG8AbgAuAEMAbwBtAG0AbwBuAAIAAAAGAgAAAAAAAAAnAQQAAAB0AHkA
cABlAAEXAAAAUwB5AHMAdABlAG0ALgBTAHQAcgBpAG4AZwAsACAAbQBzAGMAbwByAGwAaQBiACcBCgAA
AFMAeQBtAGIAbwBsAE4AYQBtAGUAARAAAABjAGEAbQBlAHIAYQBUAG8AQQBjAHQAaQB2AGEAdABlACcB
BAAAAHQAeQBwAGUAATEAAABDAGkAbgBlAG0AYQBjAGgAaQBuAGUALgBDAGkAbgBlAG0AYQBjAGgAaQBu
AGUAVgBpAHIAdAB1AGEAbABDAGEAbQBlAHIAYQAsACAAQwBpAG4AZQBtAGEAYwBoAGkAbgBlAAsBBQAA
AFYAYQBsAHUAZQAAAAAABwUHBQcF""".replace('\n', '')

print("Writing scene")
scene.dump_yaml(outpath / "map" / "scene.unity")

# game far plane is 3000, but 1530 *should* be good enough in dolpic10

# to do:
# use actual object size for lods
# particles
# animations
# more objects
# objects should check if in shadow
# circle shadow caster, for players and objects
# fix sky materials
# use the game's boxes for detecting interiors
# disable shadow casting for OOB, interior covers
# integrate dxt5 conversion
# integrate etc2 creation
# walking sfx, particles
# collision effects
# warp collision
# make mesh collision bouncy, slippery
# http://smswiki.shoutwiki.com/wiki/Docs/Collision
# handle samplers in shader
# add VRC_SpatialAudioSource to all audio sources
# make audio sources 3d
# make interior covers work with occlusion
# fix effect matrix, hook up to grabpass
# scale main map in lightmap - unity seems to fix this itself
# place light probes
# place reflection probes (use box projection for rooms)
# add background tag to sky
# make sky and sun vertices immovable and/or at max depth
# float3 viewpos = mul((float3x3)UNITY_MATRIX_MV, v.vertex);
# make sun billboard
# enable instancing on coin, fruit materials?
# disable GI for the meshes that cover up OOB but not interior covers
# fix vrc_world spawns
# dedupe
# optimize all
# add world/movement params

