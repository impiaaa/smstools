from scenebin import calcKeyCode, readString, stylecolor, readsection
from struct import unpack

registeredObjectClasses = {}
def register(*names):
    assert len(names) > 0
    def sub(c):
        c.names = list(names)+c.names
        for name in names:
            assert name not in registeredObjectClasses
            registeredObjectClasses[name] = c
        return c
    return sub

class TNameRef:
    names = []
    def read(self, fin):
        self.deschash, = unpack('>H', fin.read(2))
        self.description = readString(fin)
        assert self.deschash == calcKeyCode(self.description), (hex(self.deschash), self.description)
    def __repr__(self):
        return "%s: %s" % (self.name, self.description)
    def search(self, name, keyCode=None):
        if (keyCode is None or self.deschash == keyCode) and self.description == name:
           return self
        else:
           return None

@register('CameraMapInfo')
class TCameraMapTool(TNameRef):
    def read(self, fin):
        super().read(fin)
        self.pos = unpack('>3f', fin.read(12))
        self.rot = unpack('>3f', fin.read(12))
        self.cameraMode, self.someFlag, self.someFrames = unpack('>iii', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|%.1f,%.1f,%.1f mode=%r %d,%d'%(self.pos+(self.cameraMode, self.someFlag, self.someFrames))

@register('ScenarioArchiveName')
class TScenarioArchiveName(TNameRef):
    def read(self, fin):
        super().read(fin)
        self.name1 = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|'+self.name1

@register('StageEnemyInfo')
class TStageEnemyInfo(TNameRef):
    def read(self, fin):
        super().read(fin)
        self.name1 = readString(fin)
        self.unk1 = unpack('>II', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|'+self.name1+repr(self.unk1)

@register('StageEventInfo')
class TStageEventInfo(TNameRef):
    def read(self, fin):
        super().read(fin)
        self.unk1, = unpack('>I', fin.read(4))
        self.unk2 = readString(fin)
        self.unk3 = readString(fin)
        self.unk4 = readString(fin)
        self.unk5 = readString(fin)
        self.unk6 = readString(fin)
        self.unk7 = readString(fin)
        self.unk8, = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk1)+repr(self.unk2)+repr(self.unk3)+repr(self.unk4)+repr(self.unk5)+repr(self.unk6)+repr(self.unk7)+repr(self.unk8)

@register('StagePositionInfo')
class TStagePositionInfo(TNameRef):
    def read(self, fin):
        super().read(fin)
        self.pos = unpack('>3f', fin.read(12))
        unk1 = unpack('>IIIIII', fin.read(24))
    def __repr__(self):
        return super().__repr__()+'|%.1f,%.1f,%.1f'%(self.pos)


class TCharacter(TNameRef):
    def read(self, fin):
        super().read(fin)
        self.directory = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|dir=%s'%self.directory

@register('ObjChara')
class TObjChara(TCharacter): pass

#@register('SmplChara')
class TSmplChara(TCharacter): pass

@register('SmplChara')
class TSMSSmplChara(TCharacter): pass

@register('CubeGeneralInfo')
class TCubeGeneralInfo(TNameRef):
    def read(self, fin):
        super().read(fin)
        self.pos = unpack('>3f', fin.read(12))
        self.rot = unpack('>3f', fin.read(12))
        self.scale = unpack('>3f', fin.read(12))
        self.unk = unpack('>3I', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|%.1f,%.1f,%.1f %r'%(self.pos+(self.unk,))

@register('CameraCubeInfo')
class TCubeCameraInfo(TCubeGeneralInfo):
    def read(self, fin):
        super().read(fin)
        self.cameraObject = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|cam=%s'%(self.cameraObject)


@register('CubeStreamInfo')
class TCubeStreamInfo(TCubeGeneralInfo):
    def read(self, fin):
        super().read(fin)
        self.unk3 = unpack('>2I', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk3)


class GroupObject(TNameRef):
    def read(self, fin):
        super().read(fin)
        count, = unpack('>L', fin.read(4))
        self.objects = [readsection(fin) for i in range(count)]
    def search(self, name, keyCode=None):
        if keyCode is None:
           keyCode = calcKeyCode(name)
        res = super().search(name, keyCode)
        if res is not None:
           return res
        for o in self.objects:
           res = o.search(name, keyCode)
           if res is not None:
               return res

@register('NameRefGrp')
class TNameRefPtrListT(GroupObject): pass

@register('CameraMapToolTable', 'EventTable', 'PositionHolder', 'ScenarioArchiveNameTable')
class TNameRefAryT(GroupObject): pass

@register('CubeGeneralInfoTable', 'ScenarioArchiveNamesInStage', 'StreamGeneralInfoTable')
class TNameRefPtrAryT(GroupObject): pass

@register('StageEnemyInfoHeader')
class TStageEnemyInfoTable(TNameRefPtrAryT): pass


#class TDirector(TNameRef):

#class TGCLogoDir(TDirector):

#class TMarDirector(TDirector):

#class TMenuDirector(TDirector):

#class TMovieDirector(TDirector):

#class TSelectDir(TDirector):


class TViewObj(TNameRef): pass

@register('AmbColor')
class TAmbColor(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.color = unpack('>BBBB', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%s'%(stylecolor(self.color))

class TLightMap(TViewObj):
    def read(self, fin):
        #super().read(fin)
        infoCount, = unpack('>I', fin.read(4))
        self.lightInfos = []
        for i in range(infoCount):
            unk1, = unpack('>I', fin.read(4))
            objName = readString(fin)
            self.lightInfos.append((unk1, objName))
    def __repr__(self):
        return "TLightMap"+repr(self.lightInfos)

@register('Viewport')
class TViewport(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.rect = unpack('>4I', fin.read(16))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.rect)

@register('AfterEffect')
class TAfterEffect(TViewObj): pass

@register('AlphaCatch')
class TAlphaCatch(TViewObj): pass

@register('AreaCylinder', 'AreaSphere')
class TAreaCylinder(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.bottom = unpack('>fff', fin.read(3*4))
        fin.read(3*4)
        self.radius, self.height = unpack('>ff', fin.read(8))
        fin.read(4)
        readString(fin)
        count, = unpack('>I', fin.read(4))
        for i in range(count):
            unpack('>I', fin.read(4))
            readString(fin)
        self.areaManager = readString(fin)
        self.unk2, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|(%.1f,%.1f,%.1f) r=%f h=%f u=%d'%(self.bottom+(self.radius, self.height, self.unk2))

#class TAreaCylinderManager(TViewObj):

#class TBGTentacle(TViewObj):

#class TBPVomit(TViewObj):

#class TBWLeash(TViewObj):

@register('BeamManager')
class TBeamManager(TViewObj): pass

#class TBoidLeader(TViewObj):

@register('CardLoad')
class TCardLoad(TViewObj): pass

@register('CardSave')
class TCardSave(TViewObj): pass

@register('Conductor')
class TConductor(TViewObj): pass

@register('ConsoleStr')
class TConsoleStr(TViewObj): pass

@register('EffectObjManager')
class TEffectObjManager(TViewObj): pass

#class TFlashPane(TViewObj):

@register('GCConsole')
class TGCConsole2(TViewObj): pass

@register('GXAlphaUpdate')
class TGXAlphaUpdate(TViewObj): pass

@register('GateShadow')
class TGateShadow(TViewObj): pass

@register('Generator')
class TGenerator(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.unk2 = unpack('>III', fin.read(12))
        self.rx, self.ry, self.rz = unpack('>3f', fin.read(12))
        unk3 = unpack('>III', fin.read(12))
        unk4 = readString(fin)
        count, = unpack('>I', fin.read(4))
        for i in range(count):
           unk5 = unpack('>I', fin.read(4))
           unk6 = readString(fin)
        self.name2 = readString(fin)
        self.managerName = readString(fin)
        self.unk7 = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%r %.1f,%.1f,%.1f %s manager=%s %d'%(self.unk2, self.rx, self.ry, self.rz, self.name2, self.managerName, self.unk7)

@register('Guide')
class TGuide(TViewObj): pass

@register('HangingBridge')
class THangingBridge(TViewObj): pass

@register('J3DSysFlag')
class TJ3DSysFlag(TViewObj): pass

@register('J3DSysSetViewMtx')
class TJ3DSysSetViewMtx(TViewObj): pass

#class TLensFlare(TViewObj):

#class TLensGlow(TViewObj):

#class TLightDrawBuffer(TViewObj):

#class TLightWithDBSetManager(TViewObj):

@register('BindShadow')
class TMBindShadowManager(TViewObj): pass

@register('MirrorMapOperator')
class TMammaMirrorMapOperator(TViewObj): pass

class TMapXlu:
    def read(self, fin):
        count1, = unpack('>I', fin.read(4))
        self.things = []
        for i in range(count1):
            jointModelIndexes = []
            count2, = unpack('>I', fin.read(4))
            for j in range(count2):
                thing.append(unpack('>II', fin.read(8)))
            self.things.append(jointModelIndexes)
    def __repr__(self):
        return "TMapXlu"+repr(self.things)

class TMapCollisionData:
    def read(self, fin):
        self.xBlockCount, self.zBlockCount, self.checkDataCount, self.checkListCount, self.checkListWarpCount = unpack('>IIIII', fin.read(20))
    def __repr__(self):
        return "TMapCollisionData(xBlockCount=%s, zBlockCount=%s, checkDataCount=%s, checkListCount=%s, checkListWarpCount=%s)"%(self.xBlockCount, self.zBlockCount, self.checkDataCount, self.checkListCount, self.checkListWarpCount)

class NamedPosition:
    def read(self, fin):
        self.name = readString(fin)
        self.x, self.y, self.z, self.rx, self.ry, self.rz, self.sx, self.sy, self.sz = unpack('>fffffffff', fin.read(36))
    def __repr__(self):
        return "%s(%.1f,%.1f,%.1f)" % (self.name, self.x, self.y, self.z)

class TMapWarp:
    def read(self, fin):
        count, = unpack('>I', fin.read(4))
        self.currentAwakeJointId = 0
        self.jointWakeIds = []
        self.warps = []
        if count != 0:
            self.currentAwakeJointId, = unpack('>I', fin.read(4))
            for i in range(count):
                self.jointWakeIds.append(unpack('>II', fin.read(8)))
            for i in range(count*2):
                w = NamedPosition()
                w.read(fin)
                self.warps.append(w)
    def __repr__(self):
        return "TMapWarp(%r, %r, %r)"%(self.currentAwakeJointId, self.jointWakeIds, self.warps)

@register('Map')
class TMap(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.xlu = TMapXlu()
        self.xlu.read(fin)
        self.collisionData = TMapCollisionData()
        self.collisionData.read(fin)
        self.warp = TMapWarp()
        self.warp.read(fin)
    def __repr__(self):
        return super().__repr__()+'|xlu=%r, collisionData=%r, warp=%r'%(self.xlu, self.collisionData, self.warp)

@register('MapDrawWall')
class TMapDrawWall(TViewObj): pass

@register('MapObjFlagManager')
class TMapObjFlagManager(TViewObj):
    def read(self, fin):
        super().read(fin)
        readString(fin)

@register('MapObjGrassManager')
class TMapObjGrassManager(TViewObj): pass

@register('MapObjPoleManager')
class TMapObjPoleManager(TViewObj):
    def read(self, fin):
        super().read(fin)
        readString(fin)

class TRevivalPolluter:
    def __repr__(self):
        return "TRevivalPolluter"+repr(self.unk1)

@register('MapObjRevivalPollution')
class TMapObjRevivalPollution(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.count, = unpack('>i', fin.read(4))
        self.polluters = []
        for i in range(self.count):
           p = TRevivalPolluter()
           p.unk1 = unpack('>II', fin.read(8))
           self.polluters.append(p)
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.polluters)

@register('MapObjSoundGroup')
class TMapObjSoundGroup(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.graphName = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|graph=%s'%self.graphName

@register('MapObjWave')
class TMapObjWave(TViewObj): pass

@register('MapWireManager')
class TMapWireManager(TViewObj):
    def read(self, fin):
        super().read(fin)
        readString(fin)
        self.wireCount, self.count2, self.drawWidth, self.drawHeight = unpack('>iiff', fin.read(16))
        self.upperSurface = unpack('>3i', fin.read(12))
        self.lowerSurface = unpack('>3i', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|c1=%d,c2=%d,w=%d,h=%d,u=%r,l=%r'%(self.wireCount, self.count2, self.drawWidth, self.drawHeight, self.upperSurface, self.lowerSurface)

#class TMareEventDepressWall(TViewObj):

@register('MareEventWallRock')
class TMareEventWallRock(TViewObj): pass

#class TMarioParticleManager(TViewObj):

@register('MarioPositionObj')
class TMarioPositionObj(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.spawns = []
        while fin.tell() < len(fin.getvalue()):
           m = NamedPosition()
           m.read(fin)
           self.spawns.append(m)
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.spawns)

#class TMenuBase(TViewObj):

#class TMenuPlane(TViewObj):

#class TMirrorActor(TViewObj):

@register('MirrorModelManager')
class TMirrorModelManager(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.counts = unpack('>3I', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.counts)

@register('ModelWaterManager')
class TModelWaterManager(TViewObj): pass

#class TMovieRumble(TViewObj):

#class TMovieSubTitle(TViewObj):

#class TNintendo2D(TViewObj):

@register('PauseMenu')
class TPauseMenu2(TViewObj): pass

@register('PerformList')
class TPerformList(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.things = []
        while fin.tell() < len(fin.getvalue()):
           s = readString(fin)
           x, = unpack('>i', fin.read(4))
           self.things.append((s,x))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.things)

@register('PollutionTest')
class TPollutionTest(TViewObj): pass

#class TProgSelect(TViewObj):

@register('QuestionManager')
class TQuestionManager(TViewObj): pass

@register('ReInitGX')
class TReInitGX(TViewObj): pass

@register('SMSDrawInit')
class TSMSDrawInit(TViewObj): pass

#class TSamboLeaf(TViewObj):

@register('ScreenTexture')
class TScreenTexture(TViewObj): pass

#class TSelectGrad(TViewObj):

#class TSelectMenu(TViewObj):

#class TSelectShineManager(TViewObj):

@register('Silhouette')
class TSilhouette(TViewObj): pass

#class TSnapTimeObj(TViewObj):

@register('SplashManager')
class TSplashManager(TViewObj): pass

@register('StickyStain')
class TStickyStainManager(TViewObj): pass

@register('Strategy')
class TStrategy(TViewObj):
    def read(self, fin):
        super().read(fin)
        count, = unpack('>L', fin.read(4))
        assert count <= 16
        self.objects = [readsection(fin) for i in range(count)]
    def search(self, name, keyCode=None):
        if keyCode is None:
           keyCode = calcKeyCode(name)
        res = super().search(name, keyCode)
        if res is not None:
           return res
        for o in self.objects:
           res = o.search(name, keyCode)
           if res is not None:
               return res

@register('SunMgr')
class TSunMgr(TViewObj):
    def read(self, fin):
        super().read(fin)
        unpack('>IIII', fin.read(16))
        self.unk1, = unpack('>f', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%.1f'%self.unk1

#class TTHPRender(TViewObj):

@register('Talk2D')
class TTalk2D2(TViewObj): pass

@register('TalkCursor')
class TTalkCursor(TViewObj): pass

@register('TargetArrow')
class TTargetArrow(TViewObj): pass

@register('ZBufferCatch')
class TZBufferCatch(TViewObj): pass


@register('GroupObj')
class TViewObjPtrListT(TViewObj):
    def read(self, fin):
        super().read(fin)
        count, = unpack('>L', fin.read(4))
        self.objects = [readsection(fin) for i in range(count)]
    def search(self, name, keyCode=None):
        if keyCode is None:
           keyCode = calcKeyCode(name)
        res = super().search(name, keyCode)
        if res is not None:
           return res
        for o in self.objects:
           res = o.search(name, keyCode)
           if res is not None:
               return res

@register('AmbAry')
class TAmbAry(TViewObjPtrListT): pass

@register('IdxGroup')
class TIdxGroupObj(TViewObjPtrListT):
    def read(self, fin):
        TViewObj.read(self, fin)
        self.groupid, count = unpack('>LL', fin.read(8))
        self.objects = [readsection(fin) for i in range(count)]
    def __repr__(self):
        return super().__repr__()+'|groupId=%d'%self.groupid

@register('LightAry')
class TLightAry(TViewObjPtrListT): pass

@register('SmJ3DScn', 'MarScene')
class TSmJ3DScn(TViewObjPtrListT):
    def read(self, fin):
        TViewObj.read(self, fin)
        self.lightMap = TLightMap()
        self.lightMap.read(fin)
        count, = unpack('>L', fin.read(4))
        self.objects = [readsection(fin) for i in range(count)]
    def __repr__(self):
        return super().__repr__()+'|%r'%self.lightMap


@register('DrawBufObj')
class TDrawBufObj(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.someId, self.matPacketCount = unpack('>LL', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|%d matPacketCount=%d'%(self.someId, self.matPacketCount)

@register('MirrorMapDrawBuf')
class TMirrorMapDrawBuf(TDrawBufObj): pass


#class TFrmGXSet(TViewObj):

#class TDStageGroup(TFrmGXSet): pass


class TBathWaterPreprocessor(TViewObj): pass

@register('BathWater')
class TBathWaterManager(TBathWaterPreprocessor): pass


@register('CubeWire', 'CubeSoundEffect', 'CubeShadow', 'CubeSoundChange', 'CubeStream', 'CubeCamera', 'CubeMirror')
class TCubeManagerBase(TViewObj): pass

class TCubeManagerMarioIn(TCubeManagerBase): pass

@register('CubeArea')
class TCubeManagerArea(TCubeManagerMarioIn): pass

@register('CubeFastC', 'CubeFastA', 'CubeFastB')
class TCubeManagerFast(TCubeManagerMarioIn): pass


#class TEmitterViewObj(TViewObj):

#class TEmitterIndirectViewObj(TEmitterViewObj):


class TEventWatcher(TViewObj): pass

class TMapEvent(TEventWatcher): pass

@register('DolpicEventBiancoGate')
class TDolpicEventBiancoGate(TMapEvent): pass

@register('DolpicEventRiccoGate', 'DolpicEventMammaGate')
class TDolpicEventRiccoMammaGate(TMapEvent):
    def read(self, fin):
        super().read(fin)
        self.warpPoint = unpack('>3f', fin.read(12))
        unk, = unpack('>I', fin.read(4))
        self.warpParm, = unpack('>f', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|warpPoint=%r %1.f'%(self.warpPoint, self.warpParm)

class TMapEventSink(TMapEvent):
    def read(self, fin):
        super().read(fin)
        self.buildingCount, = unpack('>i', fin.read(4))
        self.someArrayOffset, = unpack('>i', fin.read(4))
        self.buildingPollutionIndexes = [self.readBuilding(fin) for i in range(self.buildingCount)]
    def readBuilding(self, fin):
        return unpack('>II', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.buildingPollutionIndexes)

@register('MapEventSinkInPollution')
class TMapEventSinkInPollution(TMapEventSink): pass

@register('MapEventSinkShadowMario')
class TMapEventSinkShadowMario(TMapEventSink):
    def readBuilding(self, fin):
        return unpack('>II', fin.read(8))+readString(fin)

@register('MapEventSirenaSink')
class TMapEventSirenaSink(TMapEventSink):
    def read(self, fin):
        super().read(fin)
        readString(fin)
        self.warpPoint = unpack('>3f', fin.read(12))
        unk, = unpack('>I', fin.read(4))
        self.warpParm, = unpack('>f', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|warpPoint=%r %1.f'%(self.warpPoint, self.warpParm)


@register('MapEventSinkInPollutionReset')
class TMapEventSinkInPollutionReset(TMapEventSinkInPollution): pass

@register('AirportEventSink')
class TAirportEventSink(TMapEventSinkInPollutionReset): pass

@register('MapEventSinkBianco')
class TMapEventSinkBianco(TMapEventSinkInPollutionReset): pass


class TSMSFader(TViewObj): pass
    #def read(self, fin):
    #    super().read(fin)
    #    self.someDuration, = unpack('>I', fin.read(4))
    #    self.color = unpack('>BBBB', fin.read(4))
    #def __repr__(self):
    #    return super().__repr__()+'|%d,%s'%(self.someDuration,stylecolor(self.color))

@register('ScrnFader')
class TSmplFader(TSMSFader): pass

@register('ShineFader')
class TShineFader(TSmplFader): pass


@register('SunGlass')
class TSunGlass(TViewObj): pass

@register('SunShine')
class TSunShine(TSunGlass): pass


class TEfbCtrl(TViewObj): pass

#class TEfbCtrlDisp(TEfbCtrl): pass

@register('EfbCtrlTex')
class TEfbCtrlTex(TEfbCtrl): pass


class TJointModelManager(TViewObj): pass

#class TMapModelManager(TJointModelManager): pass

@register('Pollution')
class TPollutionManager(TJointModelManager): pass


@register('normalLight')
class TLightCommon(TViewObj): pass

@register('MLight')
class TLightMario(TLightCommon): pass

@register('shadowLight')
class TLightShadow(TLightCommon): pass


class TObjManager(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.typeName = readString(fin)
        self.objCount, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%s x%d'%(self.typeName, self.objCount)

@register('MareJellyFish')
class TMareJellyFishManager(TObjManager): pass

@register('LiveManager')
class TLiveManager(TObjManager): pass

@register('BoardNpcManager')
class TBoardNpcManager(TLiveManager): pass


@register('MapObjBaseManager')
class TMapObjBaseManager(TLiveManager):
    def read(self, fin):
        super().read(fin)
        self.far, self.unkClip = unpack('>ff', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|far=%.1f %.1f'%(self.far, self.unkClip)

@register('ItemManager')
class TItemManager(TMapObjBaseManager): pass

@register('MapObjManager')
class TMapObjManager(TMapObjBaseManager): pass

@register('PoolManager')
class TPoolManager(TMapObjBaseManager): pass


@register('EnemyManager')
class TEnemyManager(TLiveManager):
    def read(self, fin):
        super().read(fin)
        self.sharedMActorSetsCount, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|setCount=%d'%(self.sharedMActorSetsCount)

@register('AnimalBirdManager')
class TAnimalBirdManager(TEnemyManager): pass

@register('BEelTearsManager')
class TBEelTearsManager(TEnemyManager): pass

@register('BathtubPeachManager')
class TBathtubPeachManager(TEnemyManager): pass

@register('BeeHiveManager')
class TBeeHiveManager(TEnemyManager): pass

@register('GateKeeperManager')
class TBiancoGateKeeperManager(TEnemyManager): pass

@register('BossEelManager')
class TBossEelManager(TEnemyManager): pass

@register('BossGessoManager')
class TBossGessoManager(TEnemyManager): pass

@register('BossHanachanManager')
class TBossHanachanManager(TEnemyManager): pass

@register('BossMantaManager')
class TBossMantaManager(TEnemyManager): pass

@register('KBossPakkunManager', 'BossPakkunManager')
class TBossPakkunManager(TEnemyManager): pass

@register('BossTelesaManager')
class TBossTelesaManager(TEnemyManager): pass

@register('BossWanwanManager')
class TBossWanwanManager(TEnemyManager): pass

@register('ButterflyManager')
class TButterfloidManager(TEnemyManager): pass

@register('EMarioManager')
class TEMarioManager(TEnemyManager): pass

@register('EggGenManager')
class TEggGenManager(TEnemyManager): pass

@register('FishoidManager')
class TFishoidManager(TEnemyManager): pass

@register('FruitsBoatManager', 'FruitsBoatManagerB', 'FruitsBoatManagerC', 'FruitsBoatManagerD')
class TFruitsBoatManager(TEnemyManager): pass

@register('HinoKuri2Manager')
class THinokuri2Manager(TEnemyManager): pass

@register('KoopaJrManager')
class TKoopaJrManager(TEnemyManager): pass

@register('KoopaJrSubmarineManager')
class TKoopaJrSubmarineManager(TEnemyManager): pass

@register('KoopaManager')
class TKoopaManager(TEnemyManager): pass

@register('LimitKoopaJrManager')
class TLimitKoopaJrManager(TEnemyManager): pass

@register('LimitKoopaManager')
class TLimitKoopaManager(TEnemyManager): pass

@register('RiccoHookManager')
class TRiccoHookManager(TEnemyManager): pass

@register('SamboFlowerManager')
class TSamboFlowerManager(TEnemyManager): pass

@register('SealManager')
class TSealManager(TEnemyManager): pass

@register('TinKoopaManager')
class TTinKoopaManager(TEnemyManager): pass

@register('TypicalManager')
class TTypicalManager(TEnemyManager): pass

@register('WireTrapManager')
class TWireTrapManager(TEnemyManager): pass


class TAnimalManagerBase(TEnemyManager): pass

@register('MewManager')
class TMewManager(TAnimalManagerBase): pass


@register('SleepBossHanachanManager')
class TDemoBossHanachanManager(TEnemyManager): pass

#class TSleepBossHanachanManager(TDemoBossHanachanManager): pass


class TLauncherManager(TEnemyManager): pass

@register('CommonLauncherManager')
class TCommonLauncherManager(TLauncherManager): pass

@register('HamukuriLauncherManager')
class THamuKuriLauncherManager(TLauncherManager): pass

@register('NamekuriLauncherManager')
class TNameKuriLauncherManager(TLauncherManager): pass


class TEffectModelManager(TEnemyManager): pass

@register('EffectBombColumWaterManager')
class TEffectBombColumWaterManager(TEffectModelManager): pass

@register('EffectColumSandManager')
class TEffectColumSandManager(TEffectModelManager): pass

@register('EffectColumWaterManager')
class TEffectColumWaterManager(TEffectModelManager): pass

@register('EffectExplosionManager')
class TEffectExplosionManager(TEffectModelManager): pass


class TNPCManager(TEnemyManager): pass

@register('KinojiiManager')
class TKinojiiManager(TNPCManager): pass

@register('KinopioManager')
class TKinopioManager(TNPCManager): pass

@register('PeachManager')
class TPeachManager(TNPCManager): pass

@register('RaccoonDogManager')
class TRaccoonDogManager(TNPCManager): pass

@register('SunflowerLManager')
class TSunflowerLManager(TNPCManager): pass

@register('SunflowerSManager')
class TSunflowerSManager(TNPCManager): pass


class TMareBaseManager(TNPCManager): pass

class TMareWBaseManager(TMareBaseManager): pass

@register('MareWAManager')
class TMareWAManager(TMareWBaseManager): pass

@register('MareWBManager')
class TMareWBManager(TMareWBaseManager): pass

@register('MareWManager')
class TMareWManager(TMareWBaseManager): pass


class TMareMBaseManager(TMareBaseManager): pass

@register('MareMAManager')
class TMareMAManager(TMareMBaseManager): pass

@register('MareMBManager')
class TMareMBManager(TMareMBaseManager): pass

@register('MareMCManager')
class TMareMCManager(TMareMBaseManager): pass

@register('MareMDManager')
class TMareMDManager(TMareMBaseManager): pass

@register('MareMManager')
class TMareMManager(TMareMBaseManager): pass


class TMonteWBaseManager(TNPCManager): pass

@register('MonteWAManager')
class TMonteWAManager(TMonteWBaseManager): pass

@register('MonteWBManager')
class TMonteWBManager(TMonteWBaseManager): pass

@register('MonteWManager')
class TMonteWManager(TMonteWBaseManager): pass


class TMonteWSpecialManager(TMonteWBaseManager): pass

@register('MonteWCManager')
class TMonteWCManager(TMonteWSpecialManager): pass


class TMonteMBaseManager(TNPCManager): pass

@register('MonteMAManager')
class TMonteMAManager(TMonteMBaseManager): pass

@register('MonteMBManager')
class TMonteMBManager(TMonteMBaseManager): pass

@register('MonteMCManager')
class TMonteMCManager(TMonteMBaseManager): pass

@register('MonteMDManager')
class TMonteMDManager(TMonteMBaseManager): pass

@register('MonteMManager')
class TMonteMManager(TMonteMBaseManager): pass


class TMonteMSpecialManager(TMonteMBaseManager): pass

@register('MonteMEManager')
class TMonteMEManager(TMonteMSpecialManager): pass

@register('MonteMFManager')
class TMonteMFManager(TMonteMSpecialManager): pass

@register('MonteMGManager')
class TMonteMGManager(TMonteMSpecialManager): pass

@register('MonteMHManager')
class TMonteMHManager(TMonteMSpecialManager): pass


class TSmallEnemyManager(TEnemyManager): pass

@register('AmenboManager')
class TAmenboManager(TSmallEnemyManager): pass

@register('AmiNokoManager')
class TAmiNokoManager(TSmallEnemyManager): pass

@register('BathtubKillerManager')
class TBathtubKillerManager(TSmallEnemyManager): pass

@register('BombHeiManager')
class TBombHeiManager(TSmallEnemyManager): pass

@register('BubbleManager')
class TBubbleManager(TSmallEnemyManager): pass

@register('CannonManager')
class TCannonManager(TSmallEnemyManager): pass

@register('ChuuHanaManager')
class TChuuHanaManager(TSmallEnemyManager): pass

@register('CoasterKillerManager')
class TCoasterKillerManager(TSmallEnemyManager): pass

@register('DebuTelesaManager')
class TDebuTelesaManager(TSmallEnemyManager): pass

@register('EffectEnemyManager')
class TEffectEnemyManager(TSmallEnemyManager): pass

@register('ElecNokonokoManager')
class TElecNokonokoManager(TSmallEnemyManager): pass

@register('FireWanwanManager')
class TFireWanwanManager(TSmallEnemyManager): pass

@register('GessoManager')
class TGessoManager(TSmallEnemyManager): pass

@register('GorogoroManager')
class TGorogoroManager(TSmallEnemyManager): pass

@register('HanaSamboManager')
class THanaSamboManager(TSmallEnemyManager): pass

@register('HauntLegManager')
class THauntLegManager(TSmallEnemyManager): pass

@register('IgaigaManager')
class TIgaigaManager(TSmallEnemyManager): pass

@register('KageMarioModokiManager')
class TKageMarioModokiManager(TSmallEnemyManager): pass

@register('KazekunManager')
class TKazekunManager(TSmallEnemyManager): pass

@register('KillerManager')
class TKillerManager(TSmallEnemyManager): pass

@register('KukkuManager')
class TKukkuManager(TSmallEnemyManager): pass

@register('KumokunManager')
class TKumokunManager(TSmallEnemyManager): pass

@register('MameGessoManager')
class TMameGessoManager(TSmallEnemyManager): pass

@register('PakkunManager')
class TPakkunManager(TSmallEnemyManager): pass

@register('PoiHanaManager')
class TPoiHanaManager(TSmallEnemyManager): pass

@register('PopoManager')
class TPopoManager(TSmallEnemyManager): pass

@register('RocketManager')
class TRocketManager(TSmallEnemyManager): pass

@register('SamboHeadManager')
class TSamboHeadManager(TSmallEnemyManager): pass

@register('TabePukuManager')
class TTabePukuManager(TSmallEnemyManager): pass

@register('TamaNokoManager')
class TTamaNokoManager(TSmallEnemyManager): pass

@register('TelesaManager')
class TTelesaManager(TSmallEnemyManager): pass

@register('YumboManager')
class TYumboManager(TSmallEnemyManager): pass


@register('NameKuriManager')
class TNameKuriManager(TSmallEnemyManager): pass

@register('DiffusionNameKuriManager')
class TDiffusionNameKuriManager(TNameKuriManager): pass


@register('TobiPukuLaunchPadManager')
class TTobiPukuLaunchPadManager(TSmallEnemyManager): pass

@register('MoePukuLaunchPadManager')
class TMoePukuLaunchPadManager(TTobiPukuLaunchPadManager): pass


@register('TobiPukuManager')
class TTobiPukuManager(TSmallEnemyManager): pass

@register('MoePukuManager')
class TMoePukuManager(TTobiPukuManager): pass


@register('HamuKuriManager')
class THamuKuriManager(TSmallEnemyManager): pass

@register('DoroHamuKuriManager')
class TDoroHamuKuriManager(THamuKuriManager): pass

@register('FireHamuKuriManager')
class TFireHamuKuriManager(THamuKuriManager): pass


@register('DangoHamuKuriManager')
class TDangoHamuKuriManager(THamuKuriManager): pass

@register('BossDangoHamuKuriManager')
class TBossDangoHamuKuriManager(TDangoHamuKuriManager): pass


@register('HaneHamuKuriManager')
class THaneHamuKuriManager(THamuKuriManager): pass

@register('DoroHaneKuriManager')
class TDoroHaneKuriManager(THaneHamuKuriManager): pass


class TPlacement(TViewObj):
    def read(self, fin):
        super().read(fin)
        self.pos = unpack('>fff', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|%.1f,%.1f,%.1f'%(self.pos)

@register('Light')
class TLight(TPlacement):
    def read(self, fin):
        super().read(fin)
        self.color = unpack('>BBBB', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%s'%(stylecolor(self.color))

@register('IdxLight')
class TIdxLight(TLight): pass


class TCamera(TPlacement): pass

#class TOrthoProj(TCamera):

@register('PolarCamera')
class TPolarCamera(TCamera): pass

@register('MirrorCamera')
class TMirrorCamera(TCamera): pass

class TLookAtCamera(TCamera): pass

@register('PolarSubCamera')
class CPolarSubCamera(TLookAtCamera):
    def __init__(self):
        super().__init__()
        self.pos = (0,0,0)
    def read(self, fin):
        pass


class TActor(TPlacement):
    def read(self, fin):
        super().read(fin)
        self.rot = unpack('>fff', fin.read(12))
        self.scale = unpack('>fff', fin.read(12))
        self.character = readString(fin)
        self.lightMap = TLightMap()
        self.lightMap.read(fin)
    def __repr__(self):
        return super().__repr__()+'|character=%s'%(self.character)

@register('SmJ3DAct')
class TSmJ3DAct(TActor): pass

#class TBGPolDrop(TActor):

def readHideObjInfo(o, fin):
    eventId, throwSpeed, throwVerticalSpeed, unk = unpack('>iffi', fin.read(16))
    o.eventId = eventId # TODO actorType
    o.throwSpeed = throwSpeed * 0.06
    o.throwVerticalSpeed = 20.0 if throwVerticalSpeed < 0.0 else throwVerticalSpeed
    return unk

@register('HideObjInfo')
class THideObjInfo(TActor):
    def read(self, fin):
        super().read(fin)
        readHideObjInfo(self, fin)
    def __repr__(self):
        return super().__repr__()+'|event=0x%x throw=%.1f,%.1f'%(self.eventId, self.throwSpeed, self.throwVerticalSpeed)

#class TMapObjSeaIndirect(TActor):

#class TMapObjWaterFilter(TActor):

@register('MarineSnow')
class TMarineSnow(TActor): pass

@register('Shimmer')
class TShimmer(TActor):
    def read(self, fin):
        super().read(fin)
        self.modelBaseName = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|model=%s'%(self.modelBaseName)

@register('Sky')
class TSky(TActor): pass

@register('SunsetModel', 'SunModel')
class TSunModel(TActor): pass

class TSimpleEffect(TActor): pass

@register('EffectBiancoFunsui')
class TEffectBiancoFunsui(TSimpleEffect): pass

@register('EffectPinnaFunsui')
class TEffectPinnaFunsui(TSimpleEffect): pass


@register('HitActor')
class THitActor(TActor): pass

#class TAmiHit(THitActor):

#class TBEelTearsDrop(THitActor):

#class TBGAttackHit(THitActor):

#class TBGBodyHit(THitActor):

#class TBGEyeHit(THitActor):

#class TBGKObstacle(THitActor): pass

#class TBPHeadHit(THitActor):

#class TBPNavel(THitActor):

#class TBPPolDrop(THitActor):

#class TBPTornado(THitActor):

#class TBWHit(THitActor):

#class TBWLeashNode(THitActor):

#class TBathWater(THitActor):

#class TBossEelTooth(THitActor):

#class TBossEelVortex(THitActor):

#class TBossMantaAdditionalCollision(THitActor):

#class TBossTelesaBody(THitActor):

#class TBossTelesaKillSmallEnemy(THitActor):

#class TBossTelesaTongue(THitActor):

#class TCallbackHitActor(THitActor):

#class TChorobei(THitActor):

@register('DamageObj')
class TDamageObj(THitActor):
    def read(self, fin):
        super().read(fin)
        self.groupName = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|group=%s'%(self.groupName)

@register('EffectFire')
class TEffectObjBase(THitActor): pass

#class TGKHitObj(THitActor):

#class THanaSamboHead(THitActor):

#class THauntedObject(THitActor):

#class THino2Hit(THitActor):

#class TKukkuBall(THitActor):

#class TLampTrapIronHit(THitActor):

#class TLampTrapSpikeHit(THitActor):

#class TMapModelActor(THitActor):

@register('MapObjFlag')
class TMapObjFlag(THitActor):
    def read(self, fin):
        super().read(fin)
        self.baseBtiName = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|bti=%s'%(self.baseBtiName)

@register('MapObjGrassGroup')
class TMapObjGrassGroup(THitActor):
    def read(self, fin):
        super().read(fin)
        self.bladeCount, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%(self.bladeCount)

#class TMapObjMessenger(THitActor):

#class TMapObjOptionWall(THitActor):

@register('MapStaticObj')
class TMapStaticObj(THitActor):
    def read(self, fin):
        super().read(fin)
        self.baseName = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|%s'%(self.baseName)

@register('MareEventPoint')
class TMareEventPoint(THitActor): pass

#class TMarioEffect(THitActor):

@register('OneShotGenerator')
class TOneShotGenerator(THitActor):
    def read(self, fin):
        super().read(fin)
        self.managerName = readString(fin)
        self.graphName = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|manager=%s,graph=%s'%(self.managerName,self.graphName)

#class TPoiHanaCollision(THitActor):

#class TPopoCollision(THitActor):

#class TRouletteSw(THitActor):

@register('ShiningStone')
class TShiningStone(THitActor): pass

#class TTPHitActor(THitActor):

#class TTinKoopaFlame(THitActor):

@register('WarpArea')
class TWarpAreaActor(THitActor):
    def read(self, fin):
        super().read(fin)
        self.upModel, self.downModel = unpack('>2xh2xh', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|%d,%d'%(self.upModel, self.downModel)

#class TYumboSeed(THitActor):

#class TPinnaShell(THitActor):


@register('BalloonHelp')
class THelpActor(THitActor):
    def read(self, fin):
        super().read(fin)
        self.someObjectName = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|%s'%(self.someObjectName)

@register('SwitchHelp')
class TSwitchHelpActor(THelpActor): pass


#class TWaterHitActor(THitActor):

#class TFootHitActor(TWaterHitActor):


#class TBossEelCollision(THitActor):

#class TBossEelAwaCollision(TBossEelCollision):

#class TBossEelBarrierCollision(TBossEelCollision):

#class TBossEelBodyCollision(TBossEelCollision):

#class TBossEelTearsRecoverCollision(TBossEelCollision):


#class TKoopaParts(THitActor):

#class TKoopaBody(TKoopaParts): pass

#class TKoopaFlame(TKoopaParts):

#class TKoopaHand(TKoopaParts): pass

#class TKoopaHead(TKoopaParts):


class TTakeActor(THitActor): pass

#class TBGBeakHit(TTakeActor):

#class TBGTakeHit(TTakeActor):

#class TBWPicket(TTakeActor):

#class TFireWanwanTailHit(TTakeActor):

#class THookTake(TTakeActor):

#class TMapWireActor(TTakeActor): pass

#class TYoshiTongue(TTakeActor):

@register('JellyGate')
class TModelGate(TTakeActor): pass


@register('Mario')
class TMario(TTakeActor):
    def read(self, fin):
        super().read(fin)
        self.someWaterGunParam, self.flagThing = unpack('>II', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|%d,%d'%(self.someWaterGunParam, self.flagThing)

#class TEnemyMario(TMario):


#class TRealoidActor(TTakeActor):

#class TBee(TRealoidActor): pass

#class TButterfly(TRealoidActor): pass

#class TFish(TRealoidActor):


@register('LiveActor')
class TLiveActor(TTakeActor):
    def read(self, fin):
        super().read(fin)
        self.someObjectName = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|%s'%(self.someObjectName)

#class TMareWallRock(TLiveActor):

#class TTinKoopaPartsBase(TLiveActor):


#class TBathtubGripParts(TLiveActor):

#class TBathtubGripPartsFragile(TBathtubGripParts): pass

#class TBathtubGripPartsHard(TBathtubGripParts): pass


#class TBossHanachanPartsBase(TLiveActor):

#class TBossHanachanPartsBody(TBossHanachanPartsBase):

#class TBossHanachanPartsHead(TBossHanachanPartsBase):


class TMapObjPlane(TLiveActor): pass

@register('RockPlane')
class TRockPlane(TMapObjPlane): pass

@register('SandPlane')
class TSandPlane(TMapObjPlane): pass


#class TLimitKoopaParts(TLiveActor):

#class TLimitKoopaBody(TLimitKoopaParts):

#class TLimitKoopaFlame(TLimitKoopaParts):

#class TLimitKoopaHand(TLimitKoopaParts):

#class TLimitKoopaHead(TLimitKoopaParts):


class TSpineEnemy(TLiveActor):
    def read(self, fin):
        TActor.read(self, fin)
        self.someObjectName = None
        self.managerName = readString(fin)
        self.graphName = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|manager=%s,graph=%s'%(self.managerName,self.graphName)

@register('AnimalMew')
class TAnimalBase(TSpineEnemy):
    def read(self, fin):
        super().read(fin)
        self.childCount, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|n=%d'%(self.childCount)

@register('AnimalBird')
class TAnimalBird(TSpineEnemy):
    def read(self, fin):
        super().read(fin)
        self.eventId, = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|event=%d'%(self.eventId)

@register('NPCKinopio', 'NPCMonteMH', 'NPCMonteMG', 'NPCPeach', 'NPCMonteMF', 'NPCMonteME', 'NPCMonteMD', 'NPCMonteMC', 'NPCMonteMB', 'NPCMonteMA', 'NPCSunflowerS', 'NPCMareMC', 'NPCMareMD', 'NPCMareMA', 'NPCMareMB', 'NPCMareWA', 'NPCMareWB', 'NPCSunflowerL', 'NPCBoard', 'NPCKinojii', 'NPCMareW', 'NPCMonteWA', 'NPCMonteWB', 'NPCMonteWC', 'NPCMareM', 'NPCRaccoonDog', 'NPCDummy', 'NPCMonteW', 'NPCMonteM')
class TBaseNPC(TSpineEnemy):
    def read(self, fin):
        super().read(fin)
        if self.name in ('NPCDummy', 'NPCBoard'):
            self.unk = None
            self.hasThingFlag = 0
            self.thingAttr1 = 0
            self.thingAttr2 = 0
            self.coinId = -1
        else:
            # body color selection, clothes color selection, some other color thing
            self.unk = [unpack('>III', fin.read(12)) for i in range(2)]
            self.partsFlag, self.actionFlagIndex, self.hasThingFlag, self.thingAttr1, self.thingAttr2, self.coinId = unpack('>iIIiii', fin.read(24))
    def __repr__(self):
        return super().__repr__()+'|%r,%d,%d,%d,%d'%(self.unk, self.hasThingFlag, self.thingAttr1, self.thingAttr2, self.coinId)

@register('BathtubPeach')
class TBathtubPeach(TSpineEnemy): pass

@register('BossEel')
class TBossEel(TSpineEnemy): pass

@register('BossGesso')
class TBossGesso(TSpineEnemy): pass

@register('BossHanachan')
class TBossHanachan(TSpineEnemy): pass

@register('BossManta')
class TBossManta(TSpineEnemy): pass

@register('BossPakkun', 'KBossPakkun')
class TBossPakkun(TSpineEnemy): pass

@register('BossTelesa')
class TBossTelesa(TSpineEnemy): pass

@register('BossWanwan')
class TBossWanwan(TSpineEnemy): pass

@register('EMario')
class TEMario(TSpineEnemy):
    def read(self, fin):
        super().read(fin)
        self.someModeSetting, self.replayIndex1, self.replayIndex2, self.replayIndex3, unk1, unk2 = unpack('>IIIIII', fin.read(24))
    def __repr__(self):
        return super().__repr__()+'|%d,%d,%d,%d'%(self.someModeSetting, self.replayIndex1, self.replayIndex2, self.replayIndex3)

@register('WickedEggGenerator', 'EggGenerator')
class TEggGenerator(TSpineEnemy): pass

@register('FruitsBoatD', 'FruitsBoatC', 'FruitsBoatB', 'FruitsBoat')
class TFruitsBoat(TSpineEnemy): pass

@register('HinoKuri2')
class THinokuri2(TSpineEnemy): pass

@register('Koopa')
class TKoopa(TSpineEnemy): pass

@register('KoopaJr')
class TKoopaJr(TSpineEnemy): pass

@register('KoopaJrSubmarine')
class TKoopaJrSubmarine(TSpineEnemy): pass

@register('LimitKoopa')
class TLimitKoopa(TSpineEnemy): pass

@register('LimitKoopaJr')
class TLimitKoopaJr(TSpineEnemy): pass

@register('RiccoHook')
class TRiccoHook(TSpineEnemy): pass

@register('SamboFlower')
class TSamboFlower(TSpineEnemy):
    def read(self, fin):
        super().read(fin)
        self.someHasExtra, self.unk4 = unpack('>iI', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|%d,%d'%(self.someHasExtra, self.unk4)

@register('OrangeSeal')
class TSeal(TSpineEnemy): pass

@register('TinKoopa')
class TTinKoopa(TSpineEnemy): pass

@register('TypicalEnemy')
class TTypicalEnemy(TSpineEnemy): pass

@register('WireTrap')
class TWireTrap(TSpineEnemy):
    def read(self, fin):
        super().read(fin)
        self.scale1, self.someFlag1, self.unk4, self.colorFlag = unpack('>IiIi', fin.read())
    def __repr__(self):
        return super().__repr__()+'|%d,%d,%d,%d'%(self.scale1, self.someFlag1, self.unk4, self.colorFlag)


class TBEelTears(TSpineEnemy): pass

@register('OilBall')
class TOilBall(TBEelTears): pass


@register('SleepBossHanachan')
class TDemoBossHanachan(TSpineEnemy): pass

#class TSleepBossHanachan(TDemoBossHanachan):


class TGateKeeperBase(TSpineEnemy): pass

@register('GateKeeper')
class TBiancoGateKeeper(TGateKeeperBase): pass


#class TEnemyAttachment(TSpineEnemy):

#class TElecCarapace(TEnemyAttachment):

#class TGessoPolluteObj(TEnemyAttachment): pass

#class TPakkunSeed(TEnemyAttachment):


class TLauncher(TSpineEnemy): pass

@register('CommonLauncher')
class TCommonLauncher(TLauncher):
    def read(self, fin):
        super().read(fin)
        self.enemyManagerName = readString(fin)
        self.launchTimerReset, = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|manager=%s,timer=%d'%(self.enemyManagerName, self.launchTimerReset)

@register('HamukuriLauncher')
class THamuKuriLauncher(TLauncher): pass

@register('NamekuriLauncher')
class TNameKuriLauncher(TLauncher): pass


class TRealoid(TSpineEnemy):
    def read(self, fin):
        super().read(fin)
        self.boidCount, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|count=%d'%(self.boidCount)

@register('BeeHive')
class TBeeHive(TRealoid):
    def read(self, fin):
        super().read(fin)
        self.eventId1, self.eventId2 = unpack('>ii', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|ev1=%d,ev2=%d'%(self.eventId1, self.eventId2)

@register('Butterfly', 'ButterflyB', 'ButterflyC')
class TButterfloid(TRealoid):
    def read(self, fin):
        super().read(fin)
        self.eventId = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|event=%d'%(self.eventId)

@register('FishoidA', 'FishoidD', 'FishoidC', 'FishoidB')
class TFishoid(TRealoid):
    def read(self, fin):
        super().read(fin)
        self.eventId = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|event=%d'%(self.eventId)


#class TEffectModel(TSpineEnemy):

#class TEffectBombColumWater(TEffectModel): pass

#class TEffectColumSand(TEffectModel): pass

#class TEffectColumWater(TEffectModel): pass

#class TEffectExplosion(TEffectModel): pass


class TSmallEnemy(TSpineEnemy):
    def read(self, fin):
        super().read(fin)
        self.coinId, = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|coin=%d'%self.coinId

@register('Amenbo')
class TAmenbo(TSmallEnemy): pass

@register('BathtubKiller')
class TBathtubKiller(TSmallEnemy): pass

@register('Cannon')
class TCannon(TSmallEnemy):
    def read(self, fin):
        TSpineEnemy.read(self, fin)
        self.coinId = -1

@register('DebuTelesa')
class TDebuTelesa(TSmallEnemy): pass

@register('FireWanwan')
class TFireWanwan(TSmallEnemy): pass

@register('HanaSambo')
class THanaSambo(TSmallEnemy): pass

@register('Kazekun')
class TKazekun(TSmallEnemy): pass

@register('Kukku')
class TKukku(TSmallEnemy): pass

@register('Kumokun')
class TKumokun(TSmallEnemy): pass

@register('Rocket')
class TRocket(TSmallEnemy): pass

@register('TabePuku')
class TTabePuku(TSmallEnemy): pass

@register('Yumbo')
class TYumbo(TSmallEnemy): pass


@register('Pakkun')
class TPakkun(TSmallEnemy): pass

@register('StayPakkun')
class TStayPakkun(TPakkun): pass


@register('TobiPukuLaunchPad')
class TTobiPukuLaunchPad(TSmallEnemy):
    def read(self, fin):
        super().read(fin)
        self.someLaunchParm, = unpack('>f', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%.1f'%self.someLaunchParm

@register('MoePukuLaunchPad')
class TMoePukuLaunchPad(TTobiPukuLaunchPad): pass


class TWalkerEnemy(TSmallEnemy): pass

@register('AmiNoko')
class TAmiNoko(TWalkerEnemy): pass

@register('BombHei')
class TBombHei(TWalkerEnemy): pass

#class TBubble(TWalkerEnemy):

#class TChuuHana(TWalkerEnemy):

@register('EffectEnemy')
class TEffectEnemy(TWalkerEnemy): pass

@register('ElecNokonoko')
class TElecNokonoko(TWalkerEnemy): pass

#class THauntLeg(TWalkerEnemy):

@register('KageMarioModoki')
class TKageMarioModoki(TWalkerEnemy): pass

@register('MameGesso')
class TMameGesso(TWalkerEnemy): pass

@register('Popo')
class TPopo(TWalkerEnemy): pass

@register('SamboHead')
class TSamboHead(TWalkerEnemy): pass

@register('TamaNoko')
class TTamaNoko(TWalkerEnemy): pass


class TCoasterEnemy(TWalkerEnemy): pass

@register('CoasterKiller')
class TCoasterKiller(TCoasterEnemy): pass


class TFlyEnemy(TWalkerEnemy): pass

@register('Killer')
class TKiller(TFlyEnemy): pass


@register('NameKuri')
class TNameKuri(TWalkerEnemy): pass

#class TDiffusionNameKuri(TNameKuri):


@register('Gesso')
class TGesso(TWalkerEnemy): pass

@register('LandGesso')
class TLandGesso(TGesso): pass

@register('SurfGesso')
class TSurfGesso(TGesso): pass


@register('PoiHana')
class TPoiHana(TWalkerEnemy): pass

@register('PoiHanaRed')
class TPoiHanaRed(TPoiHana): pass

@register('SleepPoiHana')
class TSleepPoiHana(TPoiHana): pass


#class TRollEnemy(TWalkerEnemy):

#class TGorogoro(TRollEnemy): pass

#class TIgaiga(TRollEnemy): pass


class TTobiPuku(TWalkerEnemy): pass

@register('MoePuku')
class TMoePuku(TTobiPuku): pass

@register('PukuPuku')
class TPukuPuku(TTobiPuku): pass


@register('HamuKuri')
class THamuKuri(TWalkerEnemy): pass

@register('DoroHamuKuri')
class TDoroHamuKuri(THamuKuri): pass

@register('FireHamuKuri')
class TFireHamuKuri(THamuKuri): pass


class TDangoHamuKuri(THamuKuri): pass

@register('BossDangoHamuKuri')
class TBossDangoHamuKuri(TDangoHamuKuri): pass


@register('HaneHamuKuri')
class THaneHamuKuri(THamuKuri): pass

@register('DoroHaneKuri')
class TDoroHaneKuri(THaneHamuKuri): pass

@register('HaneHamuKuri2')
class THaneHamuKuri2(THaneHamuKuri): pass


@register('Telesa')
class TTelesa(TWalkerEnemy): pass

@register('BoxTelesa')
class TBoxTelesa(TTelesa): pass

@register('LoopTelesa')
class TLoopTelesa(TTelesa): pass

@register('MarioModokiTelesa')
class TMarioModokiTelesa(TTelesa):
    def read(self, fin):
        super().read(fin)
        self.mimics, = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|mimic=%d'%(self.mimics)

@register('SeeTelesa')
class TSeeTelesa(TTelesa): pass


@register('bigWindmillBlock', 'craneCargoUpDown', 'FerrisGondola', 'WindmillRoof', 'BiaTurnBridge', 'no_data', 'SandBirdBlock', 'merry_egg', 'MapObjBase', 'submarine', 'IceCar', 'FruitTree', 'maregate', 'MammaSurfboard', 'NormalBlock', 'GateManta', 'WatermelonStatic')
class TMapObjBase(TLiveActor):
    def read(self, fin):
        TActor.read(self, fin)
        self.someObjectName = None
        self.model = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|model='+self.model

@register('AmiKing')
class TAmiKing(TMapObjBase): pass

@register('BasketReverse')
class TBasketReverse(TMapObjBase): pass

@register('Bathtub')
class TBathtub(TMapObjBase): pass

#class TBathtubGrip(TMapObjBase):

@register('BellDolpicTV', 'BellDolpicPolice')
class TBellDolpic(TMapObjBase): pass

@register('BiaBell')
class TBiancoBell(TMapObjBase): pass

@register('BiaWatermill')
class TBiancoWatermill(TMapObjBase): pass

@register('BiaWatermillVertical')
class TBiancoWatermillVertical(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.restRotSpeed1000, = unpack('>f', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|speed=%.1f'%(self.restRotSpeed1000)

@register('BigWindmill')
class TBigWindmill(TMapObjBase): pass

@register('ChestRevolve')
class TChestRevolve(TMapObjBase): pass

@register('Cogwheel')
class TCogwheel(TMapObjBase): pass

@register('cogwheel_plate', 'cogwheel_pot')
class TCogwheelScale(TMapObjBase): pass

@register('CoverFruit')
class TCoverFruit(TMapObjBase): pass

@register('CraneRotY')
class TCraneRotY(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.maxRotChange, = unpack('>f', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|max=%.1f'%(self.maxRotChange)

@register('craneUpDown')
class TCraneUpDown(TMapObjBase): pass

@register('DemoCannon')
class TDemoCannon(TMapObjBase): pass

@register('Donchou')
class TDonchou(TMapObjBase): pass

@register('Door')
class TDoor(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.someFlag, = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%(self.someFlag)

@register('DptMonteFence')
class TDptMonteFence(TMapObjBase): pass

@register('FerrisWheel')
class TFerrisWheel(TMapObjBase): pass

@register('FileLoadBlockC', 'FileLoadBlockB', 'FileLoadBlockA')
class TFileLoadBlock(TMapObjBase): pass

#class TFluff(TMapObjBase):

@register('FluffManager')
class TFluffManager(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.minFluffY, self.areaSize, self.fluffSound = unpack('>ffi', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|minY=%.1f,size=%.1f,sound=%d'%(self.minFluffY, self.areaSize, self.fluffSound)

@register('RiccoSwitchShine')
class TFruitLauncher(TMapObjBase): pass

@register('RiccoSwitch')
class TFruitSwitch(TMapObjBase): pass

@register('GoalFlag')
class TGoalFlag(TMapObjBase): pass

@register('GoalWatermelon')
class TGoalWatermelon(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.shinePos = unpack('>fff', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|shine=%.1f,%.1f,%.1f'%(self.shinePos)

@register('IceBlock')
class TIceBlock(TMapObjBase): pass

@register('JumpBase')
class TJumpBase(TMapObjBase): pass

@register('JumpMushroom')
class TJumpMushroom(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        unk = unpack('>I', fin.read(4))

@register('LampTrapIron')
class TLampTrapIron(TMapObjBase): pass

@register('LampTrapSpike')
class TLampTrapSpike(TMapObjBase): pass

@register('LeanMirror')
class TLeanMirror(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.unk4, = unpack('>f', fin.read(4))
        if fin.tell() < len(fin.getvalue()):
            unk = readString(fin)
            self.marioDestination = unpack('>fff', fin.read(12))
        else:
            self.marioDestination = (0,0,0)
    def __repr__(self):
        return super().__repr__()+'|%.1f,goto=%.1f,%.1f,%.1f'%((self.unk4,)+self.marioDestination)

@register('MammaBlockRotate')
class TMammaBlockRotate(TMapObjBase): pass

@register('MammaYacht')
class TMammaYacht(TMapObjBase): pass

@register('MapObjElasticCode')
class TMapObjElasticCode(TMapObjBase): pass

@register('MapObjGrowTree')
class TMapObjGrowTree(TMapObjBase): pass

@register('MonteRoot')
class TMapObjMonteRoot(TMapObjBase): pass

@register('Puncher')
class TMapObjPuncher(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.throwPower, = unpack('>f', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|power=%.1f'%(self.throwPower)

@register('MapObjRootPakkun')
class TMapObjRootPakkun(TMapObjBase): pass

@register('MapObjStartDemo')
class TMapObjStartDemo(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.movieIndex, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|movie=%d'%(self.movieIndex)

@register('MapObjSwitch')
class TMapObjSwitch(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.unk4 = unpack('>III', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|%r'%(self.unk4)

@register('MapObjWaterSpray')
class TMapObjWaterSpray(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.unk4 = unpack('>2f4i', fin.read(24))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk4)

@register('MareCork')
class TMareCork(TMapObjBase): pass

@register('MareEventBumpyWall')
class TMareEventBumpyWall(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.buildingId, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|building=%d'%(self.buildingId)

@register('MareFall')
class TMareFall(TMapObjBase): pass

@register('MareGate', 'GateShell')
class TMareGate(TMapObjBase): pass

@register('merry_pole')
class TMerryPole(TMapObjBase): pass

@register('Merrygoround')
class TMerrygoround(TMapObjBase): pass

@register('MonumentShine')
class TMonumentShine(TMapObjBase): pass

@register('MuddyBoat')
class TMuddyBoat(TMapObjBase): pass

@register('Mushroom1upR', 'Mushroom1up', 'mushroom1upX', 'mushroom1upR', 'mushroom1up', 'Mushroom1upX')
class TMushroom1up(TMapObjBase): pass

@register('PanelRevolve')
class TPanelRevolve(TMapObjBase): pass

@register('PinnaCoaster')
class TPinnaCoaster(TMapObjBase): pass

@register('PinnaDoorOpen', 'PinnaDoor')
class TPinnaEntrance(TMapObjBase): pass

@register('PolluterBase')
class TPolluterBase(TMapObjBase): pass

@register('AirportPool', 'Pool')
class TPool(TMapObjBase): pass

@register('RedCoinSwitch')
class TRedCoinSwitch(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.unk4, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%(self.unk4)

@register('riccoWatermill')
class TRiccoWatermill(TMapObjBase): pass

@register('RollBlockB', 'GetaGreen', 'RollBlockY', 'Umaibou', 'RollBlockR', 'GetaOrange', 'RollBlock')
class TRollBlock(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.rollSpeed, = unpack('>f', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|speed=%.1f'%(self.rollSpeed)

@register('SakuCasino')
class TSakuCasino(TMapObjBase): pass

@register('SandBlock')
class TSandBlock(TMapObjBase): pass

@register('SandEgg')
class TSandEgg(TMapObjBase): pass

@register('SirenaCasinoRoof')
class TSirenaCasinoRoof(TMapObjBase): pass

@register('SirenaGate')
class TSirenaGate(TMapObjBase): pass

@register('ShellCup')
class TShellCup(TMapObjBase): pass

@register('SirenabossWall')
class TSirenabossWall(TMapObjBase): pass

@register('SwingBoard')
class TSwingBoard(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.texPosTime, self.someRate = unpack('>ff', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|%.1f,%.1f'%(self.texPosTime, self.someRate)

@register('TurboNozzleDoor')
class TTurboNozzleDoor(TMapObjBase): pass

@register('WaterRecoverObj')
class TWaterRecoverObj(TMapObjBase): pass

@register('WireBell')
class TWireBell(TMapObjBase): pass


class THorizontalViking(TMapObjBase): pass

@register('Viking')
class TViking(THorizontalViking): pass


@register('CoinFish')
class TJointCoin(TMapObjBase): pass

@register('SandBird')
class TSandBird(TJointCoin): pass


@register('JuiceBlock')
class TJuiceBlock(TMapObjBase): pass

@register('TelesaBlock')
class TTelesaBlock(TJuiceBlock): pass


@register('LampSeesaw')
class TLampSeesaw(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.minDown, self.pushDownScale = unpack('>ff', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|min=%.1f,scale=%.1f'%(self.minDown, self.pushDownScale)

@register('LampSeesawMain')
class TLampSeesawMain(TLampSeesaw): pass


@register('LeafBoat')
class TLeafBoat(TMapObjBase): pass

@register('LeafBoatRotten')
class TLeafBoatRotten(TLeafBoat):
    def read(self, fin):
        super().read(fin)
        self.someSound, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%(self.someSound)


@register('Roulette')
class TRoulette(TMapObjBase): pass

@register('CasinoRoulette')
class TCasinoRoulette(TRoulette): pass


@register('SandLeaf')
class TSandLeaf(TMapObjBase): pass

@register('SandBomb')
class TSandBomb(TSandLeaf): pass


@register('ChangeStage', 'MapObjChangeStage')
class TMapObjChangeStage(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.destination, = unpack('>2xH', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|dest=%d'%(self.destination)

@register('ChangeStageMerrygoround')
class TChangeStageMerrygoround(TMapObjChangeStage): pass

@register('MapObjChangeStageHipDrop')
class TMapObjChangeStageHipDrop(TMapObjChangeStage): pass


class TSandBase(TMapObjBase): pass

@register('SandLeafBase')
class TSandLeafBase(TSandBase): pass


@register('SandBombBase')
class TSandBombBase(TSandBase): pass

@register('SandCastle')
class TSandCastle(TSandBombBase): pass


@register('lean_block')
class TLeanBlock(TMapObjBase): pass

@register('crane_cargo')
class TCraneCargo(TLeanBlock): pass

@register('PinnaHangingBridgeBoard', 'HangingBridgeBoard')
class THangingBridgeBoard(TLeanBlock): pass


@register('MapObjFloatOnSea')
class TMapObjFloatOnSea(TLeanBlock): pass

@register('RiccoLog')
class TWoodLog(TMapObjFloatOnSea): pass


class TRailMapObj(TMapObjBase):
    def read(self, fin):
        super().read(fin)
        self.graphName = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|graph=%s'%(self.graphName)

@register('RailBlockR', 'EXRollCube', 'RailBlockY', 'RailBlockB', 'RailBlock')
class TRailBlock(TRailMapObj): pass

@register('RideCloud')
class TRideCloud(TRailMapObj):
    def read(self, fin):
        super().read(fin)
        self.color1 = unpack('>HHHH', fin.read(8))
        self.color2 = unpack('>HHHH', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|%s,%s'%(stylecolor(self.color1), stylecolor(self.color2))


@register('Castella', 'Kamaboko', 'NormalLift', 'Hikidashi', 'EXKickBoard', 'Uirou')
class TNormalLift(TRailMapObj):
    def read(self, fin):
        super().read(fin)
        self.collisionData, = unpack('>f', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|colinfo=%.1f'%(self.collisionData)

@register('YoshiBlock', 'WoodBlock')
class TWoodBlock(TNormalLift):
    def read(self, fin):
        TRailMapObj.read(self, fin)
        self.unk1, = unpack('>I', fin.read(4))
        self.color = unpack('>III', fin.read(12))
        self.collisionData = 0
    def __repr__(self):
        return super().__repr__()+'|%s'%(stylecolor(self.color))


class TSirenaRollMapObj(TMapObjBase): pass

@register('CasinoPanelGate')
class TCasinoPanelGate(TSirenaRollMapObj): pass

@register('Closet')
class TCloset(TSirenaRollMapObj): pass


@register('SlotDrum')
class TSlotDrum(TSirenaRollMapObj): pass

@register('ItemSlotDrum')
class TItemSlotDrum(TSlotDrum): pass

@register('TelesaSlot')
class TTelesaSlot(TSlotDrum): pass


@register('Fence')
class TFence(TMapObjBase): pass

@register('RailFence')
class TRailFence(TFence):
    def read(self, fin):
        super().read(fin)
        self.graphName = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|graph=%s'%(self.graphName)

@register('FenceInner', 'fence_revolve_inner', 'bambooFence_revolve_inner')
class TRevolvingFenceInner(TFence): pass

@register('FenceRevolve')
class TRevolvingFenceOuter(TFence): pass

@register('FenceWaterV')
class TFenceWater(TFence): pass

@register('FenceWaterH')
class TFenceWaterH(TFenceWater): pass


@register('PanelBreak', 'GlassBreak', 'MapObjGeneral')
class TMapObjGeneral(TMapObjBase): pass

@register('AirportSwitch')
class TAirportSwitch(TMapObjGeneral): pass

@register('BalloonKoopaJr')
class TBalloonKoopaJr(TMapObjGeneral): pass

@register('breakable_block', 'BreakableBlock')
class TBreakableBlock(TMapObjGeneral): pass

@register('EggYoshi')
class TEggYoshi(TMapObjGeneral):
    def read(self, fin):
        super().read(fin)
        self.unk2 = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%(self.unk2)

@register('Manhole')
class TManhole(TMapObjGeneral): pass

@register('NozzleBox')
class TNozzleBox(TMapObjGeneral):
    def read(self, fin):
        super().read(fin)
        self.itemName = readString(fin)
        self.validStr = readString(fin)
        self.throwSpeedScale, self.throwSpeedY = unpack('>2f', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|item=%s,valid=%s,speed=%.1f,y=%.1f'%(self.itemName, self.validStr, self.throwSpeedScale, self.throwSpeedY)

@register('WoodBarrel')
class TWoodBarrel(TMapObjGeneral): pass


@register('PalmSago', 'BananaTree', 'PalmNatume', 'PalmOugi', 'Palm')
class TMapObjTree(TMapObjGeneral): pass

@register('MapObjTreeScale')
class TMapObjTreeScale(TMapObjTree): pass


@register('Football')
class TMapObjBall(TMapObjGeneral): pass

@register('WaterMelon')
class TBigWatermelon(TMapObjBall): pass


@register('ResetFruit', 'Fruit', 'FruitBanana', 'FruitDurian', 'FruitPine', 'FruitPapaya')
class TResetFruit(TMapObjBall): pass

@register('RandomFruit')
class TRandomFruit(TResetFruit): pass


@register('sand_bird_test', 'Item')
class TItem(TMapObjGeneral): pass

@register('normal_nozzle_item', 'yoshi_whistle_item', 'ItemNozzle', 'rocket_nozzle_item', 'back_nozzle_item')
class TItemNozzle(TItem): pass

@register('Shine')
class TShine(TItem):
    def read(self, fin):
        super().read(fin)
        self.normalOrQuickly = readString(fin)
        self.shineId, self.shineVisible = unpack('>ii', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|mode=%s,id=%d,visible=%d'%(self.normalOrQuickly, self.shineId, self.shineVisible)

@register('SurfGesoRed', 'SurfGesoYellow', 'SurfGesoGreen', 'GesoSurfBoard')
class TSurfGesoObj(TItem): pass


@register('Coin', 'joint_coin')
class TCoin(TItem): pass

@register('coin_blue', 'CoinBlue')
class TCoinBlue(TCoin):
    def read(self, fin):
        super().read(fin)
        self.blueCoinId, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|blueCoin=%d'%self.blueCoinId

#class TCoinEmpty(TCoin): pass

@register('CoinRed', 'coin_red')
class TCoinRed(TCoin): pass

@register('FlowerCoin')
class TFlowerCoin(TCoin):
    def read(self, fin):
        super().read(fin)
        self.flowerCoin, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|flowerCoin=%d'%self.flowerCoin


class THideObjBase(TMapObjBase):
    def __init__(self):
        self.uniqueId = self.throwSpeed = self.throwVerticalSpeed = self.unk5 = 0
    def read(self, fin):
        super().read(fin)
        self.unk5 = readHideObjInfo(self, fin)
        self.uniqueId = self.eventId
    def __repr__(self):
        return super().__repr__()+'|id=0x%x throw=%.1f,%.1f %d'%(self.uniqueId, self.throwSpeed, self.throwVerticalSpeed, self.unk5)

@register('MiniWindmill')
class TBiancoMiniWindmill(THideObjBase): pass

@register('BrickBlock')
class TBrickBlock(THideObjBase): pass

@register('HideObj')
class THideObj(THideObjBase): pass

@register('HipDropHideObj')
class THipDropHideObj(THideObjBase): pass

@register('Billboard')
class TMapObjBillboard(THideObjBase): pass

@register('MapObjNail')
class TMapObjNail(THideObjBase): pass

@register('MapObjSmoke')
class TMapObjSmoke(THideObjBase): pass

@register('MapObjSteam')
class TMapObjSteam(THideObjBase): pass

@register('WaterHitHideObj')
class TWaterHitHideObj(THideObjBase): pass


@register('FruitHitHideObj')
class TFruitHitHideObj(THideObjBase): pass

@register('FruitBasket')
class TFruitBasket(TFruitHitHideObj): pass

@register('FruitBasketEvent')
class TFruitBasketEvent(TFruitBasket): pass


@register('DolWeathercock')
class TMapObjTurn(THideObjBase): pass

@register('BellWatermill')
class TBellWatermill(TMapObjTurn): pass


@register('WaterHitPictureHideObj', 'PosterTeresa')
class TWaterHitPictureHideObj(THideObjBase):
    def read(self, fin):
        super().read(fin)
        self.hitColor = unpack('>III', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|%s'%(stylecolor(self.hitColor))

@register('PictureTeresa')
class TPictureTelesa(TWaterHitPictureHideObj): pass

@register('HideObjPictureTwin')
class THideObjPictureTwin(TWaterHitPictureHideObj): pass

@register('WatermelonBlock')
class TBreakHideObj(THideObjBase): pass

@register('SuperHipDropBlock')
class TSuperHipDropBlock(TBreakHideObj): pass

@register('WoodBox')
class TWoodBox(TBreakHideObj): pass


#class TViewConnecter(TViewObj):

#class TDStageDisp(TViewConnecter): pass

#class TScreen(TViewConnecter): pass

#class TCamConnecter(TViewConnecter):


#class TEnemyPolluteModel(TViewObj):

#class TGessoPolluteModel(TEnemyPolluteModel): pass

#class TGorogoroPolluteModel(TEnemyPolluteModel): pass

#class TIgaigaPolluteModel(TEnemyPolluteModel): pass


#class TEnemyPolluteModelManager(TViewObj):

#class TGessoPolluteModelManager(TEnemyPolluteModelManager): pass

#class TGorogoroPolluteModelManager(TEnemyPolluteModelManager): pass

#class TIgaigaPolluteModelManager(TEnemyPolluteModelManager): pass


#class TLightWithDBSet(TViewObj):

#class TIndirectLightWithDBSet(TLightWithDBSet): pass

#class TMapObjectLightWithDBSet(TLightWithDBSet): pass

#class TObjectLightWithDBSet(TLightWithDBSet): pass

#class TPlayerLightWithDBSet(TLightWithDBSet): pass


#class TSharedParts(TViewObj):

#class TBossEelEye(TSharedParts):

#class TBossEelHeartCoin(TSharedParts):

#class TCannonDom(TSharedParts):

#class TDoroHige(TSharedParts):

#class TTamaNokoFlower(TSharedParts):

#
# linkdata.bin
# (read by hand in the game, no classes)
#

@register('ReplayLink')
class ReplayLink(GroupObject): pass

@register('Link')
class Link(TNameRef):
    def read(self, fin):
        super().read(fin)
        self.s1 = readString(fin)
        self.s2 = readString(fin)
        self.s3 = readString(fin)
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.s1)+repr(self.s2)+repr(self.s3)

#
# only in test11/scene.bin, unimplemented
#

@register('WaterMoveBlock')
class TWaterMoveBlock(TMapObjBase): pass

