from struct import unpack
import sys, io, pathlib
from warnings import warn

def calcKeyCode(name):
    x = 0
    for c in name.encode('shift-jis'):
        x = (c + x*3)&0xFFFF
    return x

def readstring(fin):
    length, = unpack('>H', fin.read(2))
    return fin.read(length).decode('shift-jis')

def readsection(fin):
    sectionlength, namehash = unpack('>IH', fin.read(6))
    name = readstring(fin)
    assert namehash == calcKeyCode(name), (hex(namehash), name)
    if name in registeredObjectClasses:
        o = registeredObjectClasses[name]()
    else:
        o = SceneObject()
    
    o.namehash = namehash
    o.name = name
    
    assert name.isidentifier()
    x = io.BytesIO(fin.read(sectionlength-8-len(name)))
    o.read(x)
    o.extra = x.read()
    return o

registeredObjectClasses = {}
def register(c):
    assert c.__name__ not in registeredObjectClasses
    registeredObjectClasses[c.__name__] = c
    return c

def stylecolor(r,g,b):
    if r == g == b and r != 0 and r != 0xff:
        colorcode = int((r+2312)/10)
    else:
        colorcode = 16 + (36 * r/51) + (6 * g/51) + b/51
    if (r*r + g*g + b*b) < 48768:
        stylecode = 48
    else:
        stylecode = 38
    return "\x1b[%d;5;%dm#%02X%02X%02X\x1b[0m"%(stylecode, colorcode, r, g, b)

class NamedPosition:
    def read(self, fin):
        self.name = readstring(fin)
        self.x, self.y, self.z, self.rx, self.ry, self.rz, self.sx, self.sy, self.sz = unpack('>fffffffff', fin.read(36))
    def __repr__(self):
        return "%s(%.1f,%.1f,%.1f)" % (self.name, self.x, self.y, self.z)

#
# abstract classes
#

class SceneObject:
    def read(self, fin):
        self.deschash, = unpack('>H', fin.read(2))
        self.description = readstring(fin)
        assert self.deschash == calcKeyCode(self.description), (hex(self.deschash), self.description)
    def __repr__(self):
        return "%s: %s" % (self.name, self.description)

class GroupObject(SceneObject):
    def read(self, fin):
        super().read(fin)
        count, = unpack('>L', fin.read(4))
        self.objects = [readsection(fin) for i in range(count)]

class MultiGroupObject(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.groupid, count = unpack('>LL', fin.read(8))
        self.objects = [readsection(fin) for i in range(count)]
    def __repr__(self):
        return super().__repr__()+'|%d'%self.groupid

class OneStringObject(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.name1 = readstring(fin)
    def __repr__(self):
        return super().__repr__()+'|'+self.name1

class ManagerObjectBase(OneStringObject):
    def read(self, fin):
        super().read(fin)
        self.unk1, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%(self.unk1)

class ManagerObject2Float(ManagerObjectBase):
    def read(self, fin):
        super().read(fin)
        self.unk2 = unpack('>ff', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk2)

class ManagerObject1Int(ManagerObjectBase):
    def read(self, fin):
        super().read(fin)
        self.unk2, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%(self.unk2)

class PositionObject(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.x, self.y, self.z = unpack('>fff', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|%.1f,%.1f,%.1f'%(self.x, self.y, self.z)

class LightGeneral(PositionObject):
    def read(self, fin):
        super().read(fin)
        self.r, self.g, self.b, self.a, self.intensity = unpack('>BBBBf', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|%s,%x,%f'%(stylecolor(self.r, self.g, self.b), self.a, self.intensity)

class ThreeDObject(PositionObject):
    def read(self, fin):
        super().read(fin)
        self.rx, self.ry, self.rz, \
          self.sx, self.sy, self.sz = unpack('>ffffff', fin.read(24))

class OneStringThreeDObject(ThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.manager = readstring(fin)
        self.flags, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|manager=%s,flags=%x'%(self.manager, self.flags)

class TwoStringThreeDObject(OneStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.model = readstring(fin)
    def __repr__(self):
        return super().__repr__()+'|model='+self.model

class ThreeStringThreeDObject(TwoStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.name3 = readstring(fin)
    def __repr__(self):
        return super().__repr__()+'|'+self.name3

class NPC(ThreeStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk1 = unpack('>12i', fin.read(48))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk1)

class Animal(ThreeStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk2, = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%self.unk2

class Fishoid(Animal):
    def read(self, fin):
        super().read(fin)
        self.unk3, = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%self.unk3

class HideObjBase(TwoStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk = unpack('>i2fi3i', fin.read(28))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk)

class TwoString4ParmThreeDObject1(TwoStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk = unpack('>iifi', fin.read(16))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk)

class TwoString4ParmThreeDObject2(TwoStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk = unpack('>iffi', fin.read(16))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk)

#
# scene.bin
#

@register
class AmbAry(GroupObject): pass
@register
class GroupObj(GroupObject): pass
@register
class LightAry(GroupObject): pass
@register
class Strategy(GroupObject): pass

@register
class IdxGroup(MultiGroupObject): pass
@register
class MarScene(MultiGroupObject): pass

@register
class MapObjSoundGroup(OneStringObject): pass
@register
class MapObjWave(OneStringObject): pass

@register
class MapObjFlagManager(ManagerObjectBase): pass
@register
class MapObjPoleManager(ManagerObjectBase): pass

@register
class ItemManager(ManagerObject2Float): pass
@register
class MapObjBaseManager(ManagerObject2Float): pass
@register
class MapObjManager(ManagerObject2Float): pass
@register
class PoolManager(ManagerObject2Float): pass

@register
class AmiNokoManager(ManagerObject1Int): pass
@register
class AnimalBirdManager(ManagerObject1Int): pass
@register
class BEelTearsManager(ManagerObject1Int): pass
@register
class BathtubKillerManager(ManagerObject1Int): pass
@register
class BathtubPeachManager(ManagerObject1Int): pass
@register
class BeeHiveManager(ManagerObject1Int): pass
@register
class BoardNpcManager(ManagerObject1Int): pass
@register
class BombHeiManager(ManagerObject1Int): pass
@register
class BossDangoHamuKuriManager(ManagerObject1Int): pass
@register
class BossEelManager(ManagerObject1Int): pass
@register
class BossGessoManager(ManagerObject1Int): pass
@register
class BossHanachanManager(ManagerObject1Int): pass
@register
class BossMantaManager(ManagerObject1Int): pass
@register
class BossPakkunManager(ManagerObject1Int): pass
@register
class BossTelesaManager(ManagerObject1Int): pass
@register
class BossWanwanManager(ManagerObject1Int): pass
@register
class BubbleManager(ManagerObject1Int): pass
@register
class ButterflyManager(ManagerObject1Int): pass
@register
class CannonManager(ManagerObject1Int): pass
@register
class ChuuHanaManager(ManagerObject1Int): pass
@register
class CoasterKillerManager(ManagerObject1Int): pass
@register
class CommonLauncherManager(ManagerObject1Int): pass
@register
class DangoHamuKuriManager(ManagerObject1Int): pass
@register
class DebuTelesaManager(ManagerObject1Int): pass
@register
class DiffusionNameKuriManager(ManagerObject1Int): pass
@register
class DoroHamuKuriManager(ManagerObject1Int): pass
@register
class DoroHaneKuriManager(ManagerObject1Int): pass
@register
class EffectBombColumWaterManager(ManagerObject1Int): pass
@register
class EffectColumSandManager(ManagerObject1Int): pass
@register
class EffectColumWaterManager(ManagerObject1Int): pass
@register
class EffectExplosionManager(ManagerObject1Int): pass
@register
class EggGenManager(ManagerObject1Int): pass
@register
class ElecNokonokoManager(ManagerObject1Int): pass
@register
class FireHamuKuriManager(ManagerObject1Int): pass
@register
class FireWanwanManager(ManagerObject1Int): pass
@register
class FishoidManager(ManagerObject1Int): pass
@register
class FruitsBoatManager(ManagerObject1Int): pass
@register
class FruitsBoatManagerB(ManagerObject1Int): pass
@register
class GateKeeperManager(ManagerObject1Int): pass
@register
class GessoManager(ManagerObject1Int): pass
@register
class GorogoroManager(ManagerObject1Int): pass
@register
class HamuKuriManager(ManagerObject1Int): pass
@register
class HamukuriLauncherManager(ManagerObject1Int): pass
@register
class HanaSamboManager(ManagerObject1Int): pass
@register
class HaneHamuKuriManager(ManagerObject1Int): pass
@register
class HinoKuri2Manager(ManagerObject1Int): pass
@register
class IgaigaManager(ManagerObject1Int): pass
@register
class KBossPakkunManager(ManagerObject1Int): pass
@register
class KazekunManager(ManagerObject1Int): pass
@register
class KillerManager(ManagerObject1Int): pass
@register
class KinojiiManager(ManagerObject1Int): pass
@register
class KinopioManager(ManagerObject1Int): pass
@register
class KoopaJrManager(ManagerObject1Int): pass
@register
class KoopaJrSubmarineManager(ManagerObject1Int): pass
@register
class KoopaManager(ManagerObject1Int): pass
@register
class KukkuManager(ManagerObject1Int): pass
@register
class KumokunManager(ManagerObject1Int): pass
@register
class LimitKoopaJrManager(ManagerObject1Int): pass
@register
class MameGessoManager(ManagerObject1Int): pass
@register
class MapWireManager(ManagerObject1Int):
    def read(self, fin):
        super().read(fin)
        self.unk3 = unpack('>2f3I3I', fin.read(32))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk3)
@register
class MareJellyFish(ManagerObject1Int): pass
@register
class MareMAManager(ManagerObject1Int): pass
@register
class MareMBManager(ManagerObject1Int): pass
@register
class MareMCManager(ManagerObject1Int): pass
@register
class MareMDManager(ManagerObject1Int): pass
@register
class MareMManager(ManagerObject1Int): pass
@register
class MareWAManager(ManagerObject1Int): pass
@register
class MareWBManager(ManagerObject1Int): pass
@register
class MareWManager(ManagerObject1Int): pass
@register
class MewManager(ManagerObject1Int): pass
@register
class MoePukuLaunchPadManager(ManagerObject1Int): pass
@register
class MoePukuManager(ManagerObject1Int): pass
@register
class MonteMAManager(ManagerObject1Int): pass
@register
class MonteMBManager(ManagerObject1Int): pass
@register
class MonteMCManager(ManagerObject1Int): pass
@register
class MonteMDManager(ManagerObject1Int): pass
@register
class MonteMEManager(ManagerObject1Int): pass
@register
class MonteMFManager(ManagerObject1Int): pass
@register
class MonteMGManager(ManagerObject1Int): pass
@register
class MonteMHManager(ManagerObject1Int): pass
@register
class MonteMManager(ManagerObject1Int): pass
@register
class MonteWAManager(ManagerObject1Int): pass
@register
class MonteWBManager(ManagerObject1Int): pass
@register
class MonteWCManager(ManagerObject1Int): pass
@register
class MonteWManager(ManagerObject1Int): pass
@register
class NameKuriManager(ManagerObject1Int): pass
@register
class PakkunManager(ManagerObject1Int): pass
@register
class PeachManager(ManagerObject1Int): pass
@register
class PoiHanaManager(ManagerObject1Int): pass
@register
class PopoManager(ManagerObject1Int): pass
@register
class RaccoonDogManager(ManagerObject1Int): pass
@register
class RiccoHookManager(ManagerObject1Int): pass
@register
class RocketManager(ManagerObject1Int): pass
@register
class SamboFlowerManager(ManagerObject1Int): pass
@register
class SamboHeadManager(ManagerObject1Int): pass
@register
class SealManager(ManagerObject1Int): pass
@register
class SleepBossHanachanManager(ManagerObject1Int): pass
@register
class SunflowerLManager(ManagerObject1Int): pass
@register
class SunflowerSManager(ManagerObject1Int): pass
@register
class TabePukuManager(ManagerObject1Int): pass
@register
class TamaNokoManager(ManagerObject1Int): pass
@register
class TelesaManager(ManagerObject1Int): pass
@register
class TinKoopaManager(ManagerObject1Int): pass
@register
class TobiPukuLaunchPadManager(ManagerObject1Int): pass
@register
class TobiPukuManager(ManagerObject1Int): pass
@register
class TypicalManager(ManagerObject1Int): pass
@register
class WireTrapManager(ManagerObject1Int): pass
@register
class YumboManager(ManagerObject1Int): pass

@register
class Light(LightGeneral): pass
@register
class SunMgr(LightGeneral): pass

@register
class BathWater(OneStringThreeDObject): pass
@register
class EffectBiancoFunsui(OneStringThreeDObject): pass
@register
class EffectFire(OneStringThreeDObject): pass
@register
class EffectPinnaFunsui(OneStringThreeDObject): pass
@register
class JellyGate(OneStringThreeDObject): pass
@register
class MapObjGrassManager(OneStringThreeDObject): pass
@register
class MareEventPoint(OneStringThreeDObject): pass
@register
class MarineSnow(OneStringThreeDObject): pass
@register
class Mario(OneStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk2 = unpack('>II', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk2)
@register
class MirrorCamera(OneStringThreeDObject): pass
@register
class MirrorMapOperator(OneStringThreeDObject): pass
@register
class Pollution(OneStringThreeDObject): pass
@register
class Sky(OneStringThreeDObject): pass
@register
class SunModel(OneStringThreeDObject): pass
@register
class SunsetModel(OneStringThreeDObject): pass

@register
class Amenbo(TwoStringThreeDObject): pass
@register
class AmiKing(TwoStringThreeDObject): pass
@register
class AmiNoko(TwoStringThreeDObject): pass
@register
class AreaCylinder(TwoStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk2 = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%(self.unk2)
@register
class BalloonHelp(TwoStringThreeDObject): pass
@register
class BalloonKoopaJr(TwoStringThreeDObject): pass
@register
class BananaTree(TwoStringThreeDObject): pass
@register
class BasketReverse(TwoStringThreeDObject): pass
@register
class Bathtub(TwoStringThreeDObject): pass
@register
class BathtubPeach(TwoStringThreeDObject): pass
@register
class BeeHive(TwoStringThreeDObject): pass
@register
class BellDolpicPolice(TwoStringThreeDObject): pass
@register
class BellDolpicTV(TwoStringThreeDObject): pass
@register
class BellWatermill(TwoStringThreeDObject): pass
@register
class BiaBell(TwoStringThreeDObject): pass
@register
class BiaTurnBridge(TwoStringThreeDObject): pass
@register
class BiaWatermill(TwoStringThreeDObject): pass
@register
class BiaWatermillVertical(TwoStringThreeDObject): pass
@register
class BigWindmill(TwoStringThreeDObject): pass
@register
class BossDangoHamuKuri(TwoStringThreeDObject): pass
@register
class BossEel(TwoStringThreeDObject): pass
@register
class BossGesso(TwoStringThreeDObject): pass
@register
class BossHanachan(TwoStringThreeDObject): pass
@register
class BossManta(TwoStringThreeDObject): pass
@register
class BossPakkun(TwoStringThreeDObject): pass
@register
class BossTelesa(TwoStringThreeDObject): pass
@register
class BossWanwan(TwoStringThreeDObject): pass
@register
class BoxTelesa(TwoStringThreeDObject): pass
@register
class BreakableBlock(TwoStringThreeDObject): pass
@register
class BrickBlock(TwoStringThreeDObject): pass
@register
class Butterfly(TwoStringThreeDObject): pass
@register
class ButterflyB(TwoStringThreeDObject): pass
@register
class ButterflyC(TwoStringThreeDObject): pass
@register
class Cannon(TwoStringThreeDObject): pass
@register
class CasinoPanelGate(TwoStringThreeDObject): pass
@register
class CasinoRoulette(TwoStringThreeDObject): pass
@register
class ChestRevolve(TwoStringThreeDObject): pass
@register
class Closet(TwoStringThreeDObject): pass
@register
class Cogwheel(TwoStringThreeDObject): pass
@register
class Coin(TwoStringThreeDObject): pass
@register
class CoinBlue(TwoStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.blueCoinId, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|blueCoin=%d'%self.blueCoinId
@register
class CoinFish(TwoStringThreeDObject): pass
@register
class CoinRed(TwoStringThreeDObject): pass
@register
class CommonLauncher(TwoStringThreeDObject): pass
@register
class CoverFruit(TwoStringThreeDObject): pass
@register
class CraneRotY(TwoStringThreeDObject): pass
@register
class DebuTelesa(TwoStringThreeDObject): pass
@register
class DemoCannon(TwoStringThreeDObject): pass
@register
class Donchou(TwoStringThreeDObject): pass
@register
class Door(TwoStringThreeDObject): pass
@register
class DoroHaneKuri(TwoStringThreeDObject): pass
@register
class DptMonteFence(TwoStringThreeDObject): pass
@register
class EMario(TwoStringThreeDObject): pass
@register
class EXRollCube(TwoStringThreeDObject): pass
@register
class EggYoshi(TwoStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk2 = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%(self.unk2)
@register
class ElecNokonoko(TwoStringThreeDObject): pass
@register
class Fence(TwoStringThreeDObject): pass
@register
class FenceInner(TwoStringThreeDObject): pass
@register
class FenceRevolve(TwoStringThreeDObject): pass
@register
class FenceWaterH(TwoStringThreeDObject): pass
@register
class FenceWaterV(TwoStringThreeDObject): pass
@register
class FerrisWheel(TwoStringThreeDObject): pass
@register
class FileLoadBlockA(TwoStringThreeDObject): pass
@register
class FileLoadBlockB(TwoStringThreeDObject): pass
@register
class FileLoadBlockC(TwoStringThreeDObject): pass
@register
class FireHamuKuri(TwoStringThreeDObject): pass
@register
class FireWanwan(TwoStringThreeDObject): pass
@register
class FlowerCoin(TwoStringThreeDObject): pass
@register
class FluffManager(TwoStringThreeDObject): pass
@register
class Football(TwoStringThreeDObject): pass
@register
class Fruit(TwoStringThreeDObject): pass
@register
class FruitHitHideObj(TwoStringThreeDObject): pass
@register
class FruitTree(TwoStringThreeDObject): pass
@register
class FruitsBoatB(TwoStringThreeDObject): pass
@register
class GateKeeper(TwoStringThreeDObject): pass
@register
class GateShell(TwoStringThreeDObject): pass
@register
class Generator(TwoStringThreeDObject): pass
@register
class Gesso(TwoStringThreeDObject): pass
@register
class GetaGreen(TwoStringThreeDObject): pass
@register
class GetaOrange(TwoStringThreeDObject): pass
@register
class GlassBreak(TwoStringThreeDObject): pass
@register
class GoalFlag(TwoStringThreeDObject): pass
@register
class HamuKuri(TwoStringThreeDObject): pass
@register
class HamukuriLauncher(TwoStringThreeDObject): pass
@register
class HanaSambo(TwoStringThreeDObject): pass
@register
class HaneHamuKuri(TwoStringThreeDObject): pass
@register
class HaneHamuKuri2(TwoStringThreeDObject): pass
@register
class HangingBridge(TwoStringThreeDObject): pass
@register
class HideObj(TwoStringThreeDObject): pass
@register
class HinoKuri2(TwoStringThreeDObject): pass
@register
class HipDropHideObj(TwoStringThreeDObject): pass
@register
class IceBlock(TwoStringThreeDObject): pass
@register
class IceCar(TwoStringThreeDObject): pass
@register
class Item(TwoStringThreeDObject): pass
@register
class ItemNozzle(TwoStringThreeDObject): pass
@register
class ItemSlotDrum(TwoStringThreeDObject): pass
@register
class JumpBase(TwoStringThreeDObject): pass
@register
class JumpMushroom(TwoStringThreeDObject): pass
@register
class KBossPakkun(TwoStringThreeDObject): pass
@register
class Kamaboko(TwoStringThreeDObject): pass
@register
class Kazekun(TwoStringThreeDObject): pass
@register
class Koopa(TwoStringThreeDObject): pass
@register
class KoopaJr(TwoStringThreeDObject): pass
@register
class Kukku(TwoStringThreeDObject): pass
@register
class Kumokun(TwoStringThreeDObject): pass
@register
class LampTrapIron(TwoStringThreeDObject): pass
@register
class LampTrapSpike(TwoStringThreeDObject): pass
@register
class LandGesso(TwoStringThreeDObject): pass
@register
class LeafBoat(TwoStringThreeDObject): pass
@register
class LeafBoatRotten(TwoStringThreeDObject): pass
@register
class LeanMirror(TwoStringThreeDObject): pass
@register
class LimitKoopaJr(TwoStringThreeDObject): pass
@register
class LoopTelesa(TwoStringThreeDObject): pass
@register
class MameGesso(TwoStringThreeDObject): pass
@register
class MammaYacht(TwoStringThreeDObject): pass
@register
class Manhole(TwoStringThreeDObject): pass
@register
class MapObjBase(TwoStringThreeDObject): pass
@register
class MapObjChangeStage(TwoStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.destination, = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|dest=%d'%(self.destination)
@register
class MapObjFlag(TwoStringThreeDObject): pass
@register
class MapObjFloatOnSea(TwoStringThreeDObject): pass
@register
class MapObjGeneral(TwoStringThreeDObject): pass
@register
class MapObjNail(TwoStringThreeDObject): pass
@register
class MapObjRootPakkun(TwoStringThreeDObject): pass
@register
class MapObjSmoke(TwoStringThreeDObject): pass
@register
class MapObjStartDemo(TwoStringThreeDObject): pass
@register
class MapObjSteam(TwoStringThreeDObject): pass
@register
class MapObjSwitch(TwoStringThreeDObject): pass
@register
class MapObjTreeScale(TwoStringThreeDObject): pass
@register
class MapObjWaterSpray(TwoStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk = unpack('>2f4i', fin.read(24))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk)
@register
class MapStaticObj(TwoStringThreeDObject): pass
@register
class MareCork(TwoStringThreeDObject): pass
@register
class MareEventBumpyWall(TwoStringThreeDObject): pass
@register
class MareFall(TwoStringThreeDObject): pass
@register
class MareGate(TwoStringThreeDObject): pass
@register
class MarioModokiTelesa(TwoStringThreeDObject): pass
@register
class Merrygoround(TwoStringThreeDObject): pass
@register
class MiniWindmill(TwoStringThreeDObject): pass
@register
class MoePukuLaunchPad(TwoStringThreeDObject): pass
@register
class MonumentShine(TwoStringThreeDObject): pass
@register
class MuddyBoat(TwoStringThreeDObject): pass
@register
class Mushroom1upX(TwoStringThreeDObject): pass
@register
class NormalBlock(TwoStringThreeDObject): pass
@register
class NormalLift(TwoStringThreeDObject): pass
@register
class Palm(TwoStringThreeDObject): pass
@register
class PalmNatume(TwoStringThreeDObject): pass
@register
class PalmOugi(TwoStringThreeDObject): pass
@register
class PalmSago(TwoStringThreeDObject): pass
@register
class PanelBreak(TwoStringThreeDObject): pass
@register
class PanelRevolve(TwoStringThreeDObject): pass
@register
class PictureTeresa(TwoStringThreeDObject): pass
@register
class PinnaCoaster(TwoStringThreeDObject): pass
@register
class PinnaDoor(TwoStringThreeDObject): pass
@register
class PoiHana(TwoStringThreeDObject): pass
@register
class PoiHanaRed(TwoStringThreeDObject): pass
@register
class PosterTeresa(TwoStringThreeDObject): pass
@register
class Puncher(TwoStringThreeDObject): pass
@register
class RailBlock(TwoStringThreeDObject): pass
@register
class RailBlockB(TwoStringThreeDObject): pass
@register
class RailBlockR(TwoStringThreeDObject): pass
@register
class RailFence(TwoStringThreeDObject): pass
@register
class RandomFruit(TwoStringThreeDObject): pass
@register
class RedCoinSwitch(TwoStringThreeDObject): pass
@register
class ResetFruit(TwoStringThreeDObject): pass
@register
class RiccoHook(TwoStringThreeDObject): pass
@register
class RiccoLog(TwoStringThreeDObject): pass
@register
class RiccoSwitch(TwoStringThreeDObject): pass
@register
class RiccoSwitchShine(TwoStringThreeDObject): pass
@register
class RideCloud(TwoStringThreeDObject): pass
@register
class Rocket(TwoStringThreeDObject): pass
@register
class RollBlock(TwoStringThreeDObject): pass
@register
class RollBlockB(TwoStringThreeDObject): pass
@register
class RollBlockY(TwoStringThreeDObject): pass
@register
class Roulette(TwoStringThreeDObject): pass
@register
class SakuCasino(TwoStringThreeDObject): pass
@register
class SamboFlower(TwoStringThreeDObject): pass
@register
class SamboHead(TwoStringThreeDObject): pass
@register
class SandBird(TwoStringThreeDObject): pass
@register
class SandBlock(TwoStringThreeDObject): pass
@register
class SandBomb(TwoStringThreeDObject): pass
@register
class SandBombBase(TwoStringThreeDObject): pass
@register
class SandCastle(TwoStringThreeDObject): pass
@register
class SandEgg(TwoStringThreeDObject): pass
@register
class SandLeafBase(TwoStringThreeDObject): pass
@register
class SeeTelesa(TwoStringThreeDObject): pass
@register
class ShellCup(TwoStringThreeDObject): pass
@register
class Shimmer(TwoStringThreeDObject): pass
@register
class Shine(TwoStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unkName = readstring(fin)
        self.shineId, self.shineVisible = unpack('>Ii', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|name=%s,id=%d,visible=%d'%(self.unkName, self.shineId, self.shineVisible)
@register
class ShiningStone(TwoStringThreeDObject): pass
@register
class SirenaCasinoRoof(TwoStringThreeDObject): pass
@register
class SirenabossWall(TwoStringThreeDObject): pass
@register
class SleepBossHanachan(TwoStringThreeDObject): pass
@register
class SleepPoiHana(TwoStringThreeDObject): pass
@register
class SlotDrum(TwoStringThreeDObject): pass
@register
class StayPakkun(TwoStringThreeDObject): pass
@register
class SurfGesoGreen(TwoStringThreeDObject): pass
@register
class SurfGesoRed(TwoStringThreeDObject): pass
@register
class SurfGesoYellow(TwoStringThreeDObject): pass
@register
class SwingBoard(TwoStringThreeDObject): pass
@register
class SwitchHelp(TwoStringThreeDObject): pass
@register
class TabePuku(TwoStringThreeDObject): pass
@register
class TamaNoko(TwoStringThreeDObject): pass
@register
class TelesaSlot(TwoStringThreeDObject): pass
@register
class TinKoopa(TwoStringThreeDObject): pass
@register
class TobiPukuLaunchPad(TwoStringThreeDObject): pass
@register
class TurboNozzleDoor(TwoStringThreeDObject): pass
@register
class Uirou(TwoStringThreeDObject): pass
@register
class Umaibou(TwoStringThreeDObject): pass
@register
class Viking(TwoStringThreeDObject): pass
@register
class WaterMelon(TwoStringThreeDObject): pass
@register
class WaterMoveBlock(TwoStringThreeDObject): pass
@register
class WaterRecoverObj(TwoStringThreeDObject): pass
@register
class WatermelonBlock(TwoStringThreeDObject): pass
@register
class WindmillRoof(TwoStringThreeDObject): pass
@register
class WireTrap(TwoStringThreeDObject): pass
@register
class WoodBarrel(TwoStringThreeDObject): pass
@register
class WoodBlock(TwoStringThreeDObject): pass
@register
class YoshiBlock(TwoStringThreeDObject): pass
@register
class Yumbo(TwoStringThreeDObject): pass
@register
class craneUpDown(TwoStringThreeDObject): pass
@register
class riccoWatermill(TwoStringThreeDObject): pass

@register
class FruitsBoat(ThreeStringThreeDObject): pass
@register
class NozzleBox(ThreeStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.name4 = readstring(fin)
        self.unk = unpack('>2f', fin.read())
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.name4)+repr(self.unk)
@register
class NPCDummy(ThreeStringThreeDObject): pass
@register
class OrangeSeal(ThreeStringThreeDObject): pass

@register
class AnimalBird(Animal): pass
@register
class AnimalMew(Animal): pass
@register
class FishoidA(Fishoid): pass
@register
class FishoidB(Fishoid): pass
@register
class FishoidC(Fishoid): pass
@register
class FishoidD(Fishoid): pass

@register
class NPCBoard(NPC): pass
@register
class NPCKinojii(NPC): pass
@register
class NPCKinopio(NPC): pass
@register
class NPCMareM(NPC): pass
@register
class NPCMareMA(NPC): pass
@register
class NPCMareMB(NPC): pass
@register
class NPCMareMC(NPC): pass
@register
class NPCMareMD(NPC): pass
@register
class NPCMareW(NPC): pass
@register
class NPCMareWA(NPC): pass
@register
class NPCMareWB(NPC): pass
@register
class NPCMonteM(NPC): pass
@register
class NPCMonteMA(NPC): pass
@register
class NPCMonteMB(NPC): pass
@register
class NPCMonteMC(NPC): pass
@register
class NPCMonteMD(NPC): pass
@register
class NPCMonteME(NPC): pass
@register
class NPCMonteMF(NPC): pass
@register
class NPCMonteMG(NPC): pass
@register
class NPCMonteMH(NPC): pass
@register
class NPCMonteW(NPC): pass
@register
class NPCMonteWA(NPC): pass
@register
class NPCMonteWB(NPC): pass
@register
class NPCMonteWC(NPC): pass
@register
class NPCPeach(NPC): pass
@register
class NPCRaccoonDog(NPC): pass
@register
class NPCSunflowerL(NPC): pass
@register
class NPCSunflowerS(NPC): pass

@register
class HideObjPictureTwin(HideObjBase): pass
@register
class WaterHitPictureHideObj(HideObjBase): pass

@register
class FruitBasketEvent(TwoString4ParmThreeDObject1): pass
@register
class WoodBox(TwoString4ParmThreeDObject1): pass

@register
class Billboard(TwoString4ParmThreeDObject2): pass
@register
class DolWeathercock(TwoString4ParmThreeDObject2): pass
@register
class SuperHipDropBlock(TwoString4ParmThreeDObject2): pass
@register
class WaterHitHideObj(TwoString4ParmThreeDObject2): pass

@register
class AirportEventSink(SceneObject): pass
@register
class AmbColor(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.r, self.g, self.b, self.a = unpack('>BBBB', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%s,%x'%(stylecolor(self.r, self.g, self.b), self.a)
@register
class AmenboManager(SceneObject): pass
@register
class CubeArea(SceneObject): pass
@register
class CubeCamera(SceneObject): pass
@register
class CubeFastA(SceneObject): pass
@register
class CubeFastB(SceneObject): pass
@register
class CubeFastC(SceneObject): pass
@register
class CubeMirror(SceneObject): pass
@register
class CubeShadow(SceneObject): pass
@register
class CubeSoundChange(SceneObject): pass
@register
class CubeSoundEffect(SceneObject): pass
@register
class CubeStream(SceneObject): pass
@register
class CubeWire(SceneObject): pass
@register
class DolpicEventMammaGate(SceneObject): pass
@register
class DolpicEventRiccoGate(SceneObject): pass
@register
class EffectObjManager(SceneObject): pass
@register
class HideObjInfo(SceneObject): pass
@register
class Map(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.unknown = unpack('>7I', fin.read(28))
        self.warps = []
        if self.unknown[6] == 2:
            self.unknown += unpack('>5I', fin.read(20))
            while fin.tell() < len(fin.getvalue()):
                w = NamedPosition()
                w.read(fin)
                self.warps.append(w)
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unknown)+repr(self.warps)
@register
class MapEventSinkBianco(SceneObject): pass
@register
class MapEventSirenaSink(SceneObject): pass
@register
class MapObjGrassGroup(SceneObject): pass
@register
class MareEventWallRock(SceneObject): pass
@register
class MarioPositionObj(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.spawns = []
        while fin.tell() < len(fin.getvalue()):
            m = NamedPosition()
            m.read(fin)
            self.spawns.append(m)
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.spawns)
@register
class MirrorModelManager(SceneObject): pass
@register
class PolarSubCamera(SceneObject): pass
@register
class WarpArea(SceneObject): pass
@register
class WatermelonStatic(SceneObject): pass

#
# tables.bin
#

@register
class CameraMapToolTable(GroupObject): pass
@register
class CubeGeneralInfoTable(GroupObject): pass
@register
class EventTable(GroupObject): pass
@register
class NameRefGrp(GroupObject): pass
@register
class PositionHolder(GroupObject): pass
@register
class StageEnemyInfoHeader(GroupObject): pass
@register
class StreamGeneralInfoTable(GroupObject): pass

@register
class StageEnemyInfo(ManagerObject1Int): pass

@register
class CubeStreamInfo(ThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk1 = unpack('>5I', fin.read(20))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk1)
@register
class StagePositionInfo(ThreeDObject): pass
@register
class CubeGeneralInfo(ThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk1 = unpack('>3I', fin.read(12))
        if fin.tell() < len(fin.getvalue()):
            self.unk2 = readstring(fin)
        else:
            self.unk2 = None
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk1)+repr(self.unk2)

@register
class CameraCubeInfo(CubeGeneralInfo): pass

@register
class CameraMapInfo(PositionObject):
    def read(self, fin):
        super().read(fin)
        self.pos2 = unpack('>3f', fin.read(12))
        self.unk = unpack('>3i', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.pos2)+repr(self.unk)
@register
class StageEventInfo(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.unk1, = unpack('>I', fin.read(4))
        self.unk2 = readstring(fin)
        self.unk3 = readstring(fin)
        self.unk4 = readstring(fin)
        self.unk5 = readstring(fin)
        self.unk6 = readstring(fin)
        self.unk7 = readstring(fin)
        self.unk8, = unpack('>i', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk1)+repr(self.unk2)+repr(self.unk3)+repr(self.unk4)+repr(self.unk5)+repr(self.unk6)+repr(self.unk7)+repr(self.unk8)

#
# PerformLists.bin
#

@register
class PerformList(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.things = []
        while fin.tell() < len(fin.getvalue()):
            s = readstring(fin)
            x, = unpack('>i', fin.read(4))
            self.things.append((s,x))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.things)

#
# linkdata.bin
#

@register
class ReplayLink(GroupObject): pass
@register
class Link(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.s1 = readstring(fin)
        self.s2 = readstring(fin)
        self.s3 = readstring(fin)
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.s1)+repr(self.s2)+repr(self.s3)

#
# scenecmn.bin
#

class DrawBufBase(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.n1, self.n2 = unpack('>II', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|%d,%d'%(self.n1, self.n2)

@register
class SmplChara(OneStringObject): pass
@register
class ObjChara(OneStringObject): pass
@register
class DrawBufObj(DrawBufBase): pass
@register
class MirrorMapDrawBuf(DrawBufBase): pass
@register
class Viewport(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.unk = unpack('>4I', fin.read(16))
    def __repr__(self):
        return super().__repr__()+'|'+repr(self.unk)

#
# stageArc.bin
#

@register
class ScenarioArchiveNamesInStage(GroupObject): pass
@register
class ScenarioArchiveNameTable(GroupObject): pass
@register
class ScenarioArchiveName(OneStringObject): pass

if __name__ == "__main__":
    def printobj(o, i=0):
        print('  '*i, o)
        if o.extra:
            print('  '*(i+1), o.extra.hex())
        if hasattr(o, "objects"):
            for o2 in o.objects:
                printobj(o2, i+1)
    o = readsection(open(sys.argv[1], 'rb'))
    printobj(o)

