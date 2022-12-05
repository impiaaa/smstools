from scenebin import *
from classes import *
import unityparser, transforms3d, numpy
from math import radians, degrees
import pathlib, sys, inspect
from unityassets import writeMeta, fixUnityParserFloats

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
        else:
            raise
    
    def _addOverride(self, attr, value):
        if isinstance(value, dict):
            if 'fileID' in value:
                if attr == 'm_Father':
                    self._modification['m_TransformParent'] = value
                else:
                    self._modification['m_Modifications'].append({
                        'target': {'fileID': self._targetComponentId, 'guid': self._prefabGuid, 'type': 3},
                        'propertyPath': attr,
                        'value': '',
                        'objectReference': value
                    })
            else:
                for k, sub in value.items():
                    self._addOverride(attr+'.'+k, sub)
        elif isinstance(value, list):
            self._modification['m_Modifications'].append({
                'target': {'fileID': self._targetComponentId, 'guid': self._prefabGuid, 'type': 3},
                'propertyPath': attr+'.Array.size',
                'value': len(value),
                'objectReference': {'fileID': 0}
            })
            for i, sub in enumerate(value):
                self._addOverride('%s.Array.data[%d]'%(attr,i), sub)
        else:
            self._modification['m_Modifications'].append({
                'target': {'fileID': self._targetComponentId, 'guid': self._prefabGuid, 'type': 3},
                'propertyPath': attr,
                'value': value,
                'objectReference': {'fileID': 0}
            })
    
    def __setattr__(self, attr, value):
        if attr.startswith('_'):
            return super().__setattr__(attr, value)
        else:
            self._addOverride(attr, value)

    def get_attrs(self):
        # get attribute set except those belonging to the Python class
        return super().get_attrs() - {'_modification', '_prefabId', '_targetComponentId', '_prefabGuid', '_strippedComponent'}

    def get_serialized_properties_dict(self):
        # return a copy of the objects attributes but the ones we don't want
        d = super().get_serialized_properties_dict()
        del d['_modification']
        del d['_prefabId']
        del d['_targetComponentId']
        del d['_prefabGuid']
        del d['_strippedComponent']
        return d

class PrefabInstance(gocci(1001, 'PrefabInstance')):
    def __init__(self, prefabGuid, prefabYaml):
        super().__init__(getId(), '')
        self._prefabGuid = prefabGuid
        self._componentPrefabs = prefabYaml.entries
        self._gameObjectId = None
        while self._gameObjectId is None:
            for componentPrefab in reversed(self._componentPrefabs):
                if isinstance(componentPrefab, _GameObject):
                    if componentPrefab.extra_anchor_data == '':
                        self._gameObjectId = int(componentPrefab.anchor)
                        break
                    elif componentPrefab.extra_anchor_data == ' stripped':
                        raise NotImplemented("prefab variants not working at the moment")
                        self._componentPrefabs.extend(prefabsByGuid[componentPrefab.m_CorrespondingSourceObject['guid']].entries)
                        break
        self._strippedGameObject = None
        self.m_SourcePrefab = {'fileID': 100100000, 'guid': self._prefabGuid, 'type': 3}
        self.m_Modification = {'m_Modifications': []}
    
    def __setattr__(self, attr, value):
        if attr.startswith('_') or attr in {'m_ObjectHideFlags', 'serializedVersion', 'm_Modification', 'm_SourcePrefab', 'anchor', 'extra_anchor_data'}:
            return super().__setattr__(attr, value)
        else:
            self.m_Modification['m_Modifications'].append({
                'target': {'fileID': self._gameObjectId, 'guid': self._prefabGuid, 'type': 3},
                'propertyPath': attr,
                'value': value,
                'objectReference': {'fileID': 0}
            })
    
    def getOrCreateComponent(self, type):
        for componentPrefab in reversed(self._componentPrefabs):
            if isinstance(componentPrefab, type):
                newComponent = ComponentProxy(self._prefabGuid, self, int(componentPrefab.anchor), type)
                return newComponent
        if self._strippedGameObject is None:
            self._strippedGameObject = GameObject(getId(), ' stripped')
            self._strippedGameObject.m_CorrespondingSourceObject = {'fileID': self._gameObjectId, 'guid': self._prefabGuid, 'type': 3}
            self._strippedGameObject.m_PrefabInstance = getObjRef(self)
            self._strippedGameObject.m_PrefabAsset: {'fileID': 0}
            scene.entries.append(self._strippedGameObject)
        newComponent = type(getId(), '')
        scene.entries.append(newComponent)
        newComponent.m_GameObject = getObjRef(self._strippedGameObject)
        return newComponent

    def get_attrs(self):
        # get attribute set except those belonging to the Python class
        return super().get_attrs() - {'_prefabGuid', '_componentPrefabs', '_gameObjectId', '_strippedGameObject'}

    def get_serialized_properties_dict(self):
        # return a copy of the objects attributes but the ones we don't want
        d = super().get_serialized_properties_dict()
        del d['_prefabGuid']
        del d['_componentPrefabs']
        del d['_gameObjectId']
        del d['_strippedGameObject']
        return d

def getObjRef(obj):
    return {'fileID': int(obj.anchor)}

def getFileRef(guid, id, type=2):
    return {'fileID': id, 'guid': guid, 'type': type}

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
    return objObj, objXfm

def setupPosition(objXfm, o):
    x, y, z = SCALE*o.pos[0], SCALE*o.pos[1], -1*SCALE*o.pos[2]
    if y > 80 and abs(x) < 1000 and abs(z) < 1000:
        # put the rooms in the sky underground
        y -= 200
    objXfm.m_LocalPosition = {'x': x, 'y': y, 'z': z}

def setup3d(objXfm, o):
    setupPosition(objXfm, o)
    if hasattr(o, "scale"):
        rot = transforms3d.euler.euler2quat(radians(o.rot[0]), radians(180-o.rot[1]), radians(o.rot[2]))
        objXfm.m_LocalScale = {'x': SCALE*o.scale[0], 'y': SCALE*o.scale[1], 'z': -SCALE*o.scale[2]}
    else:
        rot = transforms3d.euler.euler2quat(radians(-o.rot[0]), radians(o.rot[1]), radians(o.rot[2]))
    rot = transforms3d.quaternions.qmult(rot, [0,0,1,0])
    euler = transforms3d.euler.quat2euler(rot)
    objXfm.m_LocalEulerAnglesHint = {'x': euler[0], 'y': euler[1], 'z': euler[2]}
    objXfm.m_LocalRotation = dict(zip('wxyz', rot.tolist()))

def addCol(uuid, objObj):
    coll = objObj.getOrCreateComponent(MeshCollider)
    coll.serializedVersion = 3
    coll.m_Enabled = 1
    coll.m_Mesh = getFileRef(uuid, id=4300000)

def lookAt(direction):
    up = numpy.array([0, 1, 0])
    right = numpy.cross(up, direction)
    res = right*numpy.dot(right, right)**-0.5
    mat = numpy.array([res,
                       numpy.cross(direction, res),
                       direction]).transpose()
    return list(map(degrees, transforms3d.euler.mat2euler(mat))), transforms3d.quaternions.mat2quat(mat)

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

def doColor(c):
    return dict(zip('rgba', color8ToLinear(c)))

scenedirpath = pathlib.Path(sys.argv[1])
assert scenedirpath.is_dir()
outpath = pathlib.Path(sys.argv[2])
assert outpath.is_dir()

import texture, bti
btitime = max(pathlib.Path(texture.__file__).stat().st_mtime, pathlib.Path(bti.__file__).stat().st_mtime)
from texture import decodeTextureDDS
from bti import Image
from bmd2unity import exportTexture

btis = {}
for btipath in scenedirpath.rglob("*.bti"):
    btipath_rel = btipath.relative_to(scenedirpath)
    outbtidir = outpath / btipath_rel.parent
    metapathDds = outbtidir / (btipath_rel.stem+".dds.meta")
    metapathPng = outbtidir / (btipath_rel.stem+".png.meta")
    if metapathPng.exists() and metapathPng.stat().st_mtime >= btitime:
        btis[btipath.stem.lower()] = unityparser.UnityDocument.load_yaml(metapathPng).entry['guid']
    elif metapathDds.exists() and metapathDds.stat().st_mtime >= btitime:
        btis[btipath.stem.lower()] = unityparser.UnityDocument.load_yaml(metapathDds).entry['guid']
    else:
        # TODO switch to KTX?
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
        cols[colpath.stem.lower()] = [(metapath.stem[:-5], unityparser.UnityDocument.load_yaml(metapath).entry['guid']) for metapath in metapaths]
    else:
        col = ColReader()
        with colpath.open('rb') as fin:
            col.read(fin)
        outcoldir.mkdir(parents=True, exist_ok=True)
        cols[colpath_rel.stem.lower()] = list(exportCol(col, outcoldir, colpath_rel.stem))

import bmd2unity, bmd
bmdtime = max(pathlib.Path(bmd2unity.__file__).stat().st_mtime, pathlib.Path(bmd.__file__).stat().st_mtime, btitime)
from bmd import BModel
from bmd2unity import exportBmd

bmds = {}
for bmdpath in scenedirpath.rglob("*.bmd"):
    bmdpath_rel = bmdpath.relative_to(scenedirpath)
    print(bmdpath_rel)
    outbmddir = outpath / bmdpath_rel.parent
    bmd = BModel()
    bmd.name = bmdpath_rel.stem.lower()
    try:
        with bmdpath.open('rb') as fin:
            bmd.read(fin)
    except ValueError as e:
        print(e)
        continue
    if 0:#bmd.name == "map":
        pass
    else:
        metapath = outbmddir / (bmdpath_rel.stem+".asset.meta")
        if metapath.exists() and metapath.stat().st_mtime >= bmdtime:
            bmds[str(bmdpath_rel).lower()] = unityparser.UnityDocument.load_yaml(metapath).entry['guid'], [unityparser.UnityDocument.load_yaml(outbmddir / bmdpath_rel.stem / (bmd.mat3.materials[matIdx].name+".mat.meta")).entry['guid'] for matIdx in bmd.mat3.remapTable]
        else:
            outbmddir.mkdir(parents=True, exist_ok=True)
            try:
                bmds[str(bmdpath_rel).lower()] = exportBmd(bmd, outbmddir)
            except ValueError as e:
                print(bmdpath_rel, e)
                continue

# bpy.ops.import_scene.bmd("EXEC_DEFAULT", directory="/media/spencer/ExtraData/Game extracts/sms/mario/watergun2/normal_wg/", files=[{"name": "normal_wg.bmd"}])
# bpy.ops.export_scene.fbx("EXEC_DEFAULT", filepath="/media/spencer/ExtraData/Game extracts/sms/mario/watergun2/normal_wg/normal_wg.fbx", apply_unit_scale=False)

scene = readsection(open(scenedirpath / "map" / "scene.bin", 'rb'))

ocs = OcclusionCullingSettings(getId(), '')
rs = RenderSettings(getId(), '')
lms = LightmapSettings(getId(), '')
nms = NavMeshSettings(getId(), '')

for o in scene.objects:
    if o.name == 'MarScene':
        marScene = o
        break

for o in marScene.objects:
    if o.name == 'AmbAry' and len(o.objects) > 0:
        ambColor = o.search("太陽アンビエント（オブジェクト）")
        assert ambColor.name == 'AmbColor'
        rs.m_AmbientSkyColor = doColor(ambColor.color)
        rs.m_AmbientMode = 3
        rs.m_AmbientIntensity = 1
        rs.m_SkyboxMaterial = {'fileID': 0}
        
        ambColor = o.search("影アンビエント（オブジェクト）")
        assert ambColor.name == 'AmbColor'
        rs.m_SubtractiveShadowColor = doColor(ambColor.color)

scene = unityparser.UnityDocument([ocs, rs, lms, nms])

for baseColliderName in ["map", "building01", "building02"]:
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
    for physName, uuid in cols[baseColliderName]:
        baseName = physName.split('.')[0]
        assert baseName.startswith(baseColliderName)
        baseName = baseName[len(baseColliderName)+1:]
        if baseColliderName == "map":
            assetPath = outpath / "map" / (physName+"asset")
            if not assetPath.exists():
                assetPath = outpath / "map" / (physName+".asset")
            center = unityparser.UnityDocument.load_yaml(assetPath).entry.m_LocalAABB['m_Center']
            if center['y'] > 8000 and abs(center['x']) < 100000 and abs(center['z']) < 100000:
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
            grpXfm.m_Children.append(getObjRef(objXfm))
            objXfm.m_Father = getObjRef(grpXfm)
            objXfm.m_LocalScale = {'x': SCALE, 'y': SCALE, 'z': -1*SCALE}
            if baseName.endswith("-interior"):
                objXfm.m_LocalPosition = {'x': 0.0, 'y': -200.0, 'z': 0.0}
            colliderGroups[baseName] = objObj
        addCol(uuid, objObj)

prefabsByGuid = {}
prefabs = {}
for assetPath in (outpath / "prefabs").glob("*.prefab"):
    metapath = assetPath.with_suffix(".prefab.meta")
    guid = unityparser.UnityDocument.load_yaml(metapath).entry['guid']
    prefabData = unityparser.UnityDocument.load_yaml(assetPath)
    prefabsByGuid[guid] = prefabData
    prefabs[assetPath.stem] = guid, prefabData

for o in marScene.objects:
    if o.name == 'LightAry':
        lightgrpObj, lightgrpXfm = setupObject(o)
        lightgrpXfm.m_Children = []
        o2 = o.search("太陽（オブジェクト）")
        assert o2.name == 'Light'
        objObj, objXfm = setupObject(o2)
        
        setupPosition(objXfm, o2)
        
        euler, quat = lookAt(numpy.array([-o2.pos[0], -o2.pos[1], o2.pos[2]]))
        objXfm.m_LocalEulerAnglesHint = dict(zip('xyz', euler))
        objXfm.m_LocalRotation = dict(zip('wxyz', quat.tolist()))
        
        lightgrpXfm.m_Children.append(getObjRef(objXfm))
        objXfm.m_Father = getObjRef(lightgrpXfm)
        
        light = objObj.getOrCreateComponent(Light)
        light.m_Color = doColor(o2.color)
        light.m_Intensity = 1
        light.m_Type = 1
    if o.name == 'Strategy':
        strategy = o

modelLookup = {
"AirportPole": {},
"amiking": {'m': 'amiking_model1.bmd'},
"ArrowBoardDown": {'t': 'ArrowBoard'},
"ArrowBoardLR": {'t': 'ArrowBoard'},
"ArrowBoardUp": {'t': 'ArrowBoard'},
"balloonKoopaJr": {'m': 'balloonKoopaJr.bmd', 'n': 'balloonkoopajr_wait', 'u': 0},
"baloonball": {'m': 'soccerball.bmd'},
"bambooRailFence": {'m': 'bambooFence_rail.bmd'},
"BananaTree": {'m': 'BananaTree.bmd'},
"barrel_oil": {'m': 'barrel_oil.bmd'},
"BasketReverse": {'m': 'Basket.bmd'},
"bath": {'m': 'bath.bmd'},
"belldolpic": {'m': 'BellDolpic.bmd'},
"BiaBell": {'m': 'BiaBell.bmd'},
"BiaWatermill00": {'m': 'BiaWatermill00.bmd'},
"bigWindmill": {'t': 'bianco', 'm': 'bigWindmill.bmd'},
"billboard_dolphin": {'m': 'billboardDol.bmd'},
"billboard_fish": {'m': 'billboardFish.bmd'},
"billboard_restaurant": {'m': 'billboardRestaurant.bmd'},
"billboard_sun": {'m': 'billboardSun.bmd'},
"breakable_block": {'m': 'breakable_block.bmd'},
"BrickBlock": {'t': 'BrickBlock', 'm': 'BrickBlock.bmd'},
"castella": {'m': 'castella.bmd'},
"ChangeStage": {},
"ChangeStageMerrygoround": {},
"ChestRevolve": {'m': 'ChestRevolve.bmd'},
"ChipShine": {'m': 'chip_shine_model1.bmd'},
"Closet": {'m': 'closet.bmd', 'n': 'ClosetOpen', 'u': 0},
"cloud": {'m': 'cloud.bmd', 'n': 'cloud_wait', 'u': 0},
"cluster_block": {'m': 'test_cluster.bmd'},
"coconut_ball": {'m': 'soccerball.bmd'},
"cogwheel": {'m': 'cogwheel_wheel.bmd'},
"CoinFish": {'m': 'CoinFish.bmd', 'n': 'coinfish', 'u': 0},
"DokanGate": {'m': 'efDokanGate.bmd', 'n': 'efdokangate', 'u': 4},
"doorHotel": {'m': 'doorHotel.bmd'},
"dptlight": {'m': 'dptlight.bmd'},
"dptWeathercock": {'m': 'DptWeathercock.bmd', 'n': 'dptweathercock', 'u': 0},
"drum_can": {'m': 'drum_can_model.bmd'},
"eggYoshiEvent": {'m': 'eggYoshi_normal.bmd', 'n': 'eggyoshi_wait', 'u': 0},
"eggYoshi": {'m': 'eggYoshi_normal.bmd', 'n': 'eggyoshi_wait', 'u': 0},
"ex1_turn_lift": {'m': 'TurnLift.bmd'},
"exkickboard": {'m': 'EXKickBoard.bmd'},
"expand_block": {'m': 'breakable_block.bmd'},
"exrollcube": {'m': 'EXRollCube.bmd'},
"fall_slow_block": {'m': 'breakable_block.bmd'},
"fence3x3": {'m': 'fence_half.bmd'},
"fence_revolve": {'m': 'fence_revolve_outer.bmd'},
"FerrisLOD": {'m': 'FerrisLOD.bmd', 'n': 'ferrislod', 'u': 0},
"FerrisWheel": {'m': 'FerrisWheel.bmd', 'n': 'ferriswheel', 'u': 0},
"FileLoadBlockA": {'m': 'FileLoadBlockA.bmd'},
"FileLoadBlockB": {'m': 'FileLoadBlockB.bmd'},
"FileLoadBlockC": {'m': 'FileLoadBlockC.bmd'},
"flowerOrange": {'t': 'flower', 'm': 'flowerOrange.bmd'},
"flowerPink": {'t': 'flower', 'm': 'flowerPink.bmd'},
"flowerPurple": {'t': 'flower', 'm': 'flowerPurple.bmd'},
"flowerRed": {'t': 'flower', 'm': 'flowerRed.bmd'},
"flowerSunflower": {'t': 'flower', 'm': 'flowerSunflower.bmd'},
"flowerYellow": {'t': 'flower', 'm': 'flowerYellow.bmd'},
"FluffManager": {},
"Fluff": {'m': 'Watage.bmd'},
"football_goal": {'m': 'soccergoal_model.bmd'},
"football": {'m': 'soccerball.bmd'},
"FruitBasket": {'m': 'Basket.bmd'},
"FruitCoverPine": {'m': 'FruitPine.bmd'},
"FruitHitHideObj": {},
"GateManta": {'m': 'GateManta.bmd', 'n': 'gatemanta', 'u': 0},
"Gateshell": {'m': 'Gateshell.bmd', 'n': 'gateshell', 'u': 0},
"GeneralHitObj": {},
"GesoSurfBoard": {'m': 'surf_geso.bmd'},
"GesoSurfBoardStatic": {'m': 'surf_geso.bmd'},
"getag": {'m': 'getaGreen.bmd'},
"getao": {'m': 'getaOrange.bmd'},
"GlassBreak": {'m': 'GlassBreak.bmd'},
"GoalWatermelon": {},
"HangingBridge": {},
"HangingBridgeBoard": {'m': 'mon_bri.bmd'},
"HatoPop": {'m': 'hatopop_model1.bmd'},
"HideObj": {},
"hikidashi": {'m': 'hikidashi.bmd'},
"HipDropHideObj": {},
"ice_car": {'m': 'yatai.bmd'},
"invisible_coin": {},
"joint_coin": {'m': 'coin.bmd'},
"jumpbase": {'m': 'jumpbase.bmd'},
"JumpMushroom": {'m': 'JumpKinoko.bmd'},
"kamaboko": {'m': 'kamaboko.bmd'},
"KoopaJrSignM": {'m': 'koopa_jr_sign.bmd'},
"lampBianco": {'m': 'lampBianco.bmd'},
"LampSeesaw": {'m': 'lampBianco.bmd'},
"lamptrapiron": {'m': 'lamptrapiron.bmd'},
"lamptrapspike": {'m': 'lamptrapspike.bmd'},
"LeafBoatRotten": {'t': 'LeafBoat'},
"LeafBoat": {'t': 'LeafBoat'},
"lean_block": {'m': 'breakable_block.bmd'},
"lean_direct_block": {'m': 'breakable_block.bmd'},
"lean_indirect_block": {'m': 'breakable_block.bmd'},
"manhole": {'m': 'manhole.bmd', 'n': 'manhole', 'u': 0},
"MapObjNail": {'m': 'kugi.bmd'},
"MapObjPachinkoNail": {'m': 'PachinkoKugi.bmd'},
"MapSmoke": {},
"MareEventBumpyWall": {},
"mareFall": {'m': 'MareFall.bmd', 'n': 'marefall', 'u': 4},
"maregate": {'m': 'maregate.bmd', 'n': 'maregate', 'u': 4},
"mario_cap": {'m': 'mariocap.bmd'},
"merry": {'m': 'merry.bmd', 'n': 'merry', 'u': 0},
"merry_pole": {},
"MiniWindmillL": {'t': 'bianco'},
"MiniWindmillS": {'t': 'bianco'},
"monte_chair": {'m': 'monte_chair_model.bmd'},
"MonteGoalFlag": {'m': 'monteflag.bmd', 'n': 'monteflag_wait', 'u': 0},
"MonteRoot": {'m': 'nekko.bmd'},
"monumentshine": {'m': 'monumentshine.bmd'},
"move_block": {'m': 'breakable_block.bmd'},
"MoveCoin": {'m': 'SandMoveCoin.bmd', 'n': 'sandmovecoin', 'u': 0},
"Moyasi": {'m': 'Moyasi.bmd', 'n': 'moyasi_wait', 'u': 0},
"MuddyBoat": {'m': 'MuddyBoat.bmd'},
"mushroom1up": {'m': 'mushroom1up.bmd'},
"mushroom1upR": {'m': 'mushroom1up.bmd'},
"mushroom1upX": {'m': 'mushroom1up.bmd'},
"no_data": {},
"normallift": {'m': 'NormalBlock.bmd'},
"normal_nozzle_item": {'t': 'nozzleItem'},
"NozzleBox": {'t': 'nozzleBox', 'm': 'nozzleBox.bmd'},
"nozzleDoor": {'m': 'nozzleDoor.bmd'},
"palmLeaf": {'m': 'palmLeaf.bmd'},
"palmNormal": {'m': 'palmNormal.bmd'},
"PanelBreak": {'m': 'PanelBreak.bmd'},
"PanelRevolve": {'m': 'PanelRevolve.bmd'},
"PinnaHangingBridgeBoard": {'m': 'PinnaBoard.bmd'},
"PoleNormal": {},
"Puncher": {'m': 'puncher_model1.bmd'},
"railblockb": {'m': 'AllPurposeBoardB.bmd'},
"railblockr": {'m': 'AllPurposeBoardR.bmd'},
"railblocky": {'m': 'AllPurposeBoardY.bmd'},
"RailFence": {'m': 'fence_normal.bmd'},
"riccoBoatL": {'t': 'riccoShip'},
"riccoBoatS": {'t': 'riccoShip'},
"riccoPole": {},
"riccoShipDol": {'t': 'riccoShip'},
"riccoShipLog": {'t': 'riccoShip'},
"riccoShip": {'t': 'riccoShip'},
"riccoSwitchShine": {},
"riccoYachtL": {'t': 'riccoShip'},
"riccoYachtS": {'t': 'riccoShip'},
"rollblockb": {'m': 'AllPurposeBoardB.bmd'},
"rollblockr": {'m': 'AllPurposeBoardR.bmd'},
"rollblocky": {'m': 'AllPurposeBoardY.bmd'},
"rulet00": {'m': 'rulet00.bmd', 'n': 'rulet00', 'u': 0},
"SandBird": {'m': 'SandBird.bmd', 'n': 'sandbird', 'u': 0},
"sand_block": {'m': 'SandBlock.bmd'},
"SandBombBase00": {'t': 'SandBombBase', 'm': 'SandBombBase00.bmd'},
"SandBombBaseFoot": {'t': 'SandBombBase', 'm': 'SandBombBaseFoot.bmd'},
"SandBombBaseHand": {'t': 'SandBombBase', 'm': 'SandBombBaseHand.bmd'},
"SandBombBaseMushroom": {'t': 'SandBombBase', 'm': 'SandBombBaseMushroom.bmd'},
"SandBombBasePyramid": {'t': 'SandBombBase', 'm': 'SandBombBasePyramid.bmd'},
"SandBombBaseShit": {'t': 'SandBombBase', 'm': 'SandBombBaseShit.bmd'},
"SandBombBaseStairs": {'t': 'SandBombBase', 'm': 'SandBombBaseStairs.bmd'},
"SandBombBaseStar": {'t': 'SandBombBase', 'm': 'SandBombBaseStar.bmd'},
"SandBombBaseTurtle": {'t': 'SandBombBase', 'm': 'SandBombBaseTurtle.bmd'},
"SandBomb": {'m': 'SandBomb.bmd', 'n': 'sandbomb_wait', 'u': 0},
"SandCastle": {'t': 'SandBombBase', 'm': 'SandCastle.bmd'},
"SandLeafBase00": {'m': 'SandLeafBase00.bmd'},
"SandLeafBase01": {'m': 'SandLeafBase01.bmd'},
"SandLeafBase02": {'m': 'SandLeafBase02.bmd'},
"SandLeafBase03": {'m': 'SandLeafBase03.bmd'},
"SandLeaf": {'m': 'SandLeaf.bmd', 'n': 'sandleaf_wait', 'u': 0},
"ShellCup": {'m': 'ShellCup.bmd', 'n': 'shellcup', 'u': 0},
"shine": {},
"SignCircle": {'m': 'maru_sign.bmd'},
"SignCross": {'m': 'batu_sign.bmd'},
"SignTriangle": {'m': '3kaku_sign.bmd'},
"SirenabossWall": {'m': 'boss_wall.bmd'},
"SirenaCasinoRoof": {'m': 'casino_lighting.bmd', 'n': 'casino_lighting', 'u': 5},
"skate_block": {'m': 'breakable_block.bmd'},
"SkyIsland": {'m': 'SkyIsland.bmd', 'n': 'skyisland', 'u': 0},
"spread_block": {'m': 'breakable_block.bmd'},
"stand_break": {'m': 'stand_break.bmd', 'n': 'stand_break0', 'u': 0},
"StartDemo": {},
"SuperHipDropBlock": {'m': 'super_rock.bmd'},
"supermario_block": {'m': 'breakable_block.bmd'},
"SurfGesoGreen": {},
"SurfGesoRed": {},
"SurfGesoYellow": {},
"TeethOfJuicer": {'m': 'TeethOfJuicer.bmd', 'n': 'teethofjuicer', 'u': 0},
"uirou": {'m': 'uirou.bmd'},
"umaibou": {'m': 'umaibou.bmd'},
"WaterHitHideObj": {},
"WaterMelonBlock": {'t': 'WaterMelon', 'm': 'WaterMelonBlock.bmd'},
"watermelon": {'m': 'watermelon.bmd'},
"WatermelonStatic": {'m': 'watermelon.bmd'},
"water_power_inertial_lift": {'m': 'breakable_block.bmd'},
"water_power_lift": {'m': 'breakable_block.bmd'},
"water_power_ship": {'m': 'breakable_block.bmd'},
"WaterRecoverObj": {},
"water_roll_block": {'m': 'water_roll_block.bmd'},
"WaterSprayBox": {},
"WaterSprayCylinder": {},
"windmill_far": {'m': 'bigWindmill.bmd'},
"wood_barrel_once": {'t': 'barrel', 'm': 'barrel_normal.bmd'},
"wood_barrel": {'t': 'barrel', 'm': 'barrel_normal.bmd'},
"WoodBox": {'t': 'kibako', 'm': 'kibako.bmd'},
"yoshiblock": {'m': 'yoshiblock.bmd'},
"yTurnLift": {'m': 'yTurnLift.bmd'},
}
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

import csv, os
AudioRes = pathlib.Path(os.getcwd()) / "AudioRes"
soundInfos = {int(row["InternalID"], 16): row for row in csv.DictReader(open(AudioRes / "msound.csv"))}
scenetime = pathlib.Path(__file__).stat().st_mtime
sounds = {}
from xml.dom import minidom
import shutil
def getSound(soundKey):
    if soundKey in sounds:
        return sounds[soundKey]
    soundInfo = soundInfos[soundKey]
    commands = open(AudioRes / "se" / soundInfo["Category"] / (soundInfo["Name"]+".txt"))
    labels = {}
    loop = False
    bank = inst = 0
    volume = 1.0
    note = 0
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
                note += key
            elif command[0] == 'SET_BANK_INST':
                bank, inst = command[1:]
            elif command[0] == 'JMP':
                label = command[2]
                if label in labels and labels[label] < i:
                    loop = True
            elif command[0] == 'TRANSPOSE':
                assert command[1] == 0x3C
                note += command[1]
            elif command[0] == 'SIMPLEADSR':
                attackTime, decayTime, decayTime2, sustainLevel, releaseTime = command[1:]
                volume *= sustainLevel/0xFFFF
    pitch = 2**((note-0x3C)/12.0)
    
    (outpath / "audio").mkdir(parents=True, exist_ok=True)
    metapath = outpath / "audio" / (soundInfo["Name"]+".wav.meta")
    destpath = outpath / "audio" / (soundInfo["Name"]+".wav")
    if metapath.exists() and metapath.stat().st_mtime >= scenetime:
        parsedInfo = (volume, pitch, loop, unityparser.UnityDocument.load_yaml(metapath).entry['guid'])
        sounds[soundKey] = parsedInfo
        return parsedInfo
    
    ibnk = minidom.parse(open(AudioRes / "IBNK" / ("%d.xml"%bank)))
    for instrument in ibnk.firstChild.getElementsByTagName("instrument"):
        if int(instrument.getAttribute("program")) == inst:
            break
    keyRegions = instrument.getElementsByTagName("key-region")
    assert len(keyRegions) == 1, keyRegions
    assert "key" not in keyRegions[0].attributes, keyRegions[0]
    velocityRegions = keyRegions[0].getElementsByTagName("velocity-region")
    assert len(velocityRegions) == 1, velocityRegions
    waveId = int(velocityRegions[0].getAttribute("wave-id"))
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

def addMeshFilter(bmdFilename, objObj):
    if bmdFilename in bmds:
        asset, materialIds = bmds[bmdFilename]
    else:
        warn("Didn't load %r"%bmdFilename)
        asset = materialIds = None
    renderer = objObj.getOrCreateComponent(MeshRenderer)
    if materialIds is not None:
        renderer.m_Materials = [getFileRef(materialId, id=2100000) for materialId in materialIds]

    meshFilter = objObj.getOrCreateComponent(MeshFilter)
    if asset is not None:
        meshFilter.m_Mesh = getFileRef(asset, id=4300000)

for group in strategy.objects:
    assert group.name == 'IdxGroup'
    grpObj, grpXfm = setupObject(group)
    grpXfm.m_Children = []
    for o in group.objects:
        objObj, objXfm = setupObject(o)
        grpXfm.m_Children.append(getObjRef(objXfm))
        objXfm.m_Father = getObjRef(grpXfm)
        if isinstance(o, TActor):
            setup3d(objXfm, o)
        elif isinstance(o, TPlacement):
            setupPosition(objXfm, o)
        if isinstance(o, TMapObjBase):
            lowername = o.model.lower()
            if lowername in cols:
                for physName, uuid in cols[lowername]:
                    # different terrain types ok?
                    addCol(uuid, objObj)
        if isinstance(o, TMapObjBase):
            modelEntry = modelLookup.get(o.model, None)
            if modelEntry is None or ('t' in modelEntry and 'm' not in modelEntry):
                bmdFile = scenedirpath / "mapobj" / (o.model+".bmd")
                if bmdFile.exists():
                    if modelEntry is None:
                        modelEntry = {'m': o.model+".bmd"}
                    else:
                        modelEntry['m'] = o.model+".bmd"
            if modelEntry is not None:
                if 'm' in modelEntry:
                    bmdFilename = "mapobj/"+modelEntry['m'].lower()
                    addMeshFilter(bmdFilename, objObj)
                else:
                    warn("No model for %r"%o.model)
        if isinstance(o, TMapStaticObj):
            #objObj.m_StaticEditorFlags = 0xFFFFFFFF
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
                    bmdFilename = prefix+"/"+modelEntry['modelName'].lower()
                    addMeshFilter(bmdFilename, objObj)
                if 'collisionManagerName' in modelEntry:
                    for physName, uuid in cols[modelEntry['collisionManagerName'].lower()]:
                        # different terrain types ok?
                        addCol(uuid, objObj)
                if 'soundKey' in modelEntry:
                    audioSource = objObj.getOrCreateComponent(AudioSource)
                    volume, pitch, loop, clipGuid = getSound(modelEntry['soundKey'])
                    audioSource.m_Enabled = 1
                    audioSource.m_audioClip = getFileRef(clipGuid, id=8300000, type=3)
                    audioSource.m_PlayOnAwake = 1
                    audioSource.m_Volume = volume
                    audioSource.m_Pitch = pitch
                    audioSource.Loop = int(loop)
                if 'particle' in modelEntry:
                    objObj.getOrCreateComponent(ParticleSystemRenderer)
                    objObj.getOrCreateComponent(ParticleSystem)
        if o.name == "Map":
            pass

tables = readsection(open(scenedirpath / "map" / "tables.bin", 'rb'))
assert tables.name == "NameRefGrp"
for group in tables.objects:
    grpObj, grpXfm = setupObject(group)
    grpXfm.m_Children = []
    if group.name == "PositionHolder":
        for o in group.objects:
            assert o.name == "StagePositionInfo"
            objObj, objXfm = setupObject(o)
            grpXfm.m_Children.append(getObjRef(objXfm))
            objXfm.m_Father = getObjRef(grpXfm)
            setupPosition(objXfm, o)
    elif group.name == "CameraMapToolTable":
        cameraGameObjects = {}
        for o in group.objects:
            assert o.name == "CameraMapInfo"
            objObj, objXfm = setupObject(o)
            grpXfm.m_Children.append(getObjRef(objXfm))
            objXfm.m_Father = getObjRef(grpXfm)
            setup3d(objXfm, o)
            cameraGameObjects[o.description] = objObj.getOrCreateComponent(MonoBehaviour)
    elif group.name in ("CubeGeneralInfoTable", "StreamGeneralInfoTable"):
        for o in group.objects:
            objObj, objXfm = setupObject(o)
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

scene.dump_yaml(outpath / "map" / "scene.unity")

