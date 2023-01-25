# copied from https://github.com/magcius/noclip.website/tree/master/src/Common/JSYSTEM/JPA.ts

from common import *
from bti import Image
from struct import Struct
from math import pi, log2
from enum import Enum, IntEnum

class VolumeType(Enum):
    Cube     = 0x00
    Sphere   = 0x01
    Cylinder = 0x02
    Torus    = 0x03
    Point    = 0x04
    Circle   = 0x05
    Line     = 0x06

class JPADynamicsBlock(Section):
    header = Struct('>4xffffffhhhBB2xHfhhHHhhHhhhhhhhfffffhhhhII')
    fields = [
        'emitterSclX', 'emitterSclY', 'emitterSclZ',
        'emitterTrsX', 'emitterTrsY', 'emitterTrsZ',
        'emitterRotX', 'emitterRotY', 'emitterRotZ',
        ('volumeType', VolumeType),
        'rateStep', 'divNumber', 'rate', '_rateRndm',
        'maxFrame', 'startFrame',
        'volumeSize', '_volumeSweep', '_volumeMinRad',
        'lifeTime', '_lifeTimeRndm',
        '_moment', '_momentRndm',
        '_initialVelRatio', '_accelRndm',
        '_airResist', '_airResistRndm',
        'initialVelOmni', 'initialVelAxis',
        'initialVelRndm', 'initialVelDir',
        'accel',
        'emitterDirX', 'emitterDirY', 'emitterDirZ',
        '_spread', 'emitFlags', 'kfa1KeyTypeMask'
    ]
    def read(self, fin, start, length):
        super().read(fin, start, length)
        self.emitterScl = (self.emitterSclX, self.emitterSclY, self.emitterSclZ)
        self.emitterTrs = (self.emitterTrsX, self.emitterTrsY, self.emitterTrsZ)
        self.emitterDir = (self.emitterDirX, self.emitterDirY, self.emitterDirZ)
        self.emitterRot = ((self.emitterRotX/0x7FFF)*pi, (self.emitterRotY/0x7FFF)*pi, (self.emitterRotZ/0x7FFF)*pi)
        self.volumeSweep = self._volumeSweep / 0x8000
        self.volumeMinRad = self._volumeMinRad / 0x8000
        self.spread = self._spread / 0x8000
        self.rateRndm = self._rateRndm / 0x8000
        self.initialVelRatio = self._initialVelRatio / 0x8000
        self.lifeTimeRndm = self._lifeTimeRndm / 0x8000
        self.airResist = self._airResist / 0x8000
        self.airResistRndm = self._airResistRndm / 0x8000
        self.moment = self._moment / 0x8000
        self.momentRndm = self._momentRndm / 0x8000
        self.accelRndm = self._accelRndm / 0x8000
    
    def write(self, fout):
        self.emitterSclX, self.emitterSclY, self.emitterSclZ = self.emitterScl
        self.emitterTrsX, self.emitterTrsY, self.emitterTrsZ = self.emitterTrs
        self.emitterDirX, self.emitterDirY, self.emitterDirZ = self.emitterDir
        self.emitterRotX = int(self.emitterRot[0]*0x7FFF/pi)
        self.emitterRotY = int(self.emitterRot[1]*0x7FFF/pi)
        self.emitterRotZ = int(self.emitterRot[2]*0x7FFF/pi)
        self._volumeSweep = int(self.volumeSweep*0x8000)
        self._volumeMinRad = int(self.volumeMinRad*0x8000)
        self._spread = int(self.spread*0x8000)
        self._rateRndm = int(self.rateRndm*0x8000)
        self._initialVelRatio = int(self.initialVelRatio*0x8000)
        self._lifeTimeRndm = int(self.lifeTimeRndm*0x8000)
        self._airResist = int(self.airResist*0x8000)
        self._airResistRndm = int(self.airResistRndm*0x8000)
        self._moment = int(self.moment*0x8000)
        self._momentRndm = int(self.momentRndm*0x8000)
        self._accelRndm = int(self.accelRndm*0x8000)
        super().write(fout)

class ShapeType(Enum):
    Point            = 0x00
    Line             = 0x01
    Billboard        = 0x02
    Direction        = 0x03
    DirectionCross   = 0x04
    Stripe           = 0x05
    StripeCross      = 0x06
    Rotation         = 0x07
    RotationCross    = 0x08
    DirBillboard     = 0x09
    YBillboard       = 0x0A

class DirType(Enum):
    Vel      = 0
    Pos      = 1
    PosInv   = 2
    EmtrDir  = 3
    PrevPctl = 4

class RotType(Enum):
    Y       = 0x00
    X       = 0x01
    Z       = 0x02
    XYZ     = 0x03
    YJiggle = 0x04

class CalcIdxType(Enum):
    Normal  = 0x00
    Repeat  = 0x01
    Reverse = 0x02
    Merge   = 0x03
    Random  = 0x04

class JPABaseShape(Section):
    header = Struct('>4xHHHHHHffHBBBBB9xB4xBBBBBBBBBBBBBBBB7xBBBB12xHBxBBBBII20xhhhhhhhhhhhBx')
    fields = [
        'unk1', 'unk2', 'unk3',
        'texIdxAnimDataOffs', 'colorPrmAnimDataOffs', 'colorEnvAnimDataOffs',
        'baseSizeX', 'baseSizeY',
        'anmRndm', 'texAnmCalcFlags', 'colorAnmCalcFlags',
        ('shapeType', ShapeType), ('dirType', DirType), ('rotType', RotType),
        'colorInSelect', 'blendMode', 'blendSrcFactor', 'blendDstFactor', 'logicOp',
        'alphaCmp0', 'alphaRef0', 'alphaOp', 'alphaCmp1', 'alphaRef1',
        ('zCompLoc', bool), ('zTest', bool), 'zCompare', ('zWrite', bool), ('zPrepass', bool),
        ('isEnableProjection', bool), 'flags',
        'texAnimFlags', ('texCalcIdxType', CalcIdxType), 'texIdxAnimDataCount', 'texIdx',
        'colorAnimMaxFrm', ('colorCalcIdxType', CalcIdxType),
        'colorPrmAnimFlags', 'colorEnvAnimFlags',
        'colorPrmAnimDataCount', 'colorEnvAnimDataCount',
        'colorPrm', 'colorEnv',
        'texInitTransX', 'texInitTransY',
        'texInitScaleX', 'texInitScaleY',
        'tilingS', 'tilingT',
        'texIncTransX', 'texIncTransY',
        'texIncScaleX', 'texIncScaleY',
        '_texIncRot', ('isEnableTexScrollAnm', bool)
    ]
    def read(self, fin, start, length):
        super().read(fin, start, length)
        
        self.texIdxAnimData = array('B')
        if self.texIdxAnimDataOffs != 0:
            fin.seek(start+self.texIdxAnimDataOffs)
            self.texIdxAnimData.fromfile(fin, self.texIdxAnimDataCount)
        
        self.colorPrmAnimData = []
        if self.colorPrmAnimDataOffs != 0:
            fin.seek(start+self.colorPrmAnimDataOffs)
            self.colorPrmAnimData = self.readColorTable(fin, self.colorPrmAnimDataCount)
        
        self.colorEnvAnimData = []
        if self.colorEnvAnimDataOffs != 0:
            fin.seek(start+self.colorEnvAnimDataOffs)
            self.colorEnvAnimData = self.readColorTable(fin, self.colorEnvAnimDataCount)
        
        self.baseSize = self.baseSizeX, self.baseSizeY
        self.texInitTrans = (self.texInitTransX/0x8000, self.texInitTransY/0x8000)
        self.texInitScale = (self.texInitScaleX/0x8000, self.texInitScaleY/0x8000)
        self.tiling = (self.tilingS/0x8000, self.tilingT/0x8000)
        self.texIncTrans = (self.texIncTransX/0x8000, self.texIncTransY/0x8000)
        self.texIncScale = (self.texIncScaleX/0x8000, self.texIncScaleY/0x8000)
        self.texIncRot = self._texIncRot/0x8000
    
    def readColorTable(self, fin, count):
        h = Struct('>HI')
        return [h.unpack(fin.read(h.size)) for i in range(count)]
    
    def writeColorTable(self, fout, table):
        h = Struct('>HI')
        for e in table: fout.write(h.pack(*e))
    
    def write(self, fout):
        self.texIdxAnimDataOffs = self.header.size+8+alignAmt(self.header.size+8, 16)
        self.texIdxAnimDataCount = len(self.texIdxAnimData)
        self.colorPrmAnimDataOffs = self.texIdxAnimDataOffs+self.texIdxAnimDataCount
        self.colorPrmAnimDataCount = len(self.colorPrmAnimData)
        self.colorEnvAnimDataOffs = self.colorPrmAnimDataOffs+6*self.colorPrmAnimDataCount
        self.colorEnvAnimDataCount = len(self.colorEnvAnimData)
        self.baseSizeX, self.baseSizeY = self.baseSize
        self.texInitTransX = int(self.texInitTrans[0]*0x8000)
        self.texInitTransY = int(self.texInitTrans[1]*0x8000)
        self.texInitScaleX = int(self.texInitScale[0]*0x8000)
        self.texInitScaleY = int(self.texInitScale[1]*0x8000)
        self.tilingS = int(self.tiling[0]*0x8000)
        self.tilingT = int(self.tiling[1]*0x8000)
        self.texIncTransX = int(self.texIncTrans[0]*0x8000)
        self.texIncTransY = int(self.texIncTrans[1]*0x8000)
        self.texIncScaleX = int(self.texIncScale[0]*0x8000)
        self.texIncScaleY = int(self.texIncScale[1]*0x8000)
        self._texIncRot = int(self.texIncRot*0x8000)
        super().write(fout)
        alignFile(fout, 16, 8)
        self.texIdxAnimData.tofile(fout)
        self.writeColorTable(fout, self.colorPrmAnimData)
        self.writeColorTable(fout, self.colorEnvAnimData)

class JPAExtraShape(Section):
    header = Struct('>4xI4xhhhhhBBhhhh12xhhhhhhBBHhhhBBHB3xh6xhhhh2xB')
    fields = [
        'unk1', '_alphaInTiming', '_alphaOutTiming',
        '_alphaInValue', '_alphaBaseValue', '_alphaOutValue',
        'alphaAnmFlags', 'alphaWaveTypeFlag',
        '_alphaWaveParam1', '_alphaWaveParam2', '_alphaWaveParam3', '_alphaWaveRandom',
        '_scaleOutRandom', '_scaleInTiming', '_scaleOutTiming',
        '_scaleInValueY', 'unk2', '_scaleOutValueY', 'pivotY', 'anmTypeY', 'scaleAnmMaxFrameY',
        '_scaleInValueX', 'unk3', '_scaleOutValueX', 'pivotX', 'anmTypeX', 'scaleAnmMaxFrameX',
        'scaleAnmFlags',
        '_rotateDirection', '_rotateAngle', '_rotateSpeed',
        '_rotateAngleRandom', '_rotateSpeedRandom', ('isEnableRotate', bool)
    ]
    def read(self, fin, start, length):
        super().read(fin, start, length)
        self.alphaInTiming = self._alphaInTiming/0x8000
        self.alphaOutTiming = self._alphaOutTiming/0x8000
        self.alphaInValue = self._alphaInValue/0x8000
        self.alphaBaseValue = self._alphaBaseValue/0x8000
        self.alphaOutValue = self._alphaOutValue/0x8000
        self.alphaWaveParam1 = self._alphaWaveParam1/0x8000
        self.alphaWaveParam2 = self._alphaWaveParam2/0x8000
        self.alphaWaveParam3 = self._alphaWaveParam3/0x8000
        self.alphaWaveRandom = self._alphaWaveRandom/0x8000
        self.scaleOutRandom = self._scaleOutRandom/0x8000
        self.scaleInTiming = self._scaleInTiming/0x8000
        self.scaleOutTiming = self._scaleOutTiming/0x8000
        self.scaleInValueY = self._scaleInValueY/0x8000
        self.scaleOutValueY = self._scaleOutValueY/0x8000
        self.scaleInValueX = self._scaleInValueX/0x8000
        self.scaleOutValueX = self._scaleOutValueX/0x8000
        self.rotateDirection = self._rotateDirection/0x8000
        self.rotateAngle = self._rotateAngle/0x8000
        self.rotateSpeed = self._rotateSpeed/0x8000
        self.rotateAngleRandom = self._rotateAngleRandom/0x8000
        self.rotateSpeedRandom = self._rotateSpeedRandom/0x8000
    def write(self, fout):
        self._alphaInTiming = int(self.alphaInTiming*0x8000)
        self._alphaOutTiming = int(self.alphaOutTiming*0x8000)
        self._alphaInValue = int(self.alphaInValue*0x8000)
        self._alphaBaseValue = int(self.alphaBaseValue*0x8000)
        self._alphaOutValue = int(self.alphaOutValue*0x8000)
        self._alphaWaveParam1 = int(self.alphaWaveParam1*0x8000)
        self._alphaWaveParam2 = int(self.alphaWaveParam2*0x8000)
        self._alphaWaveParam3 = int(self.alphaWaveParam3*0x8000)
        self._alphaWaveRandom = int(self.alphaWaveRandom*0x8000)
        self._scaleOutRandom = int(self.scaleOutRandom*0x8000)
        self._scaleInTiming = int(self.scaleInTiming*0x8000)
        self._scaleOutTiming = int(self.scaleOutTiming*0x8000)
        self._scaleInValueY = int(self.scaleInValueY*0x8000)
        self._scaleOutValueY = int(self.scaleOutValueY*0x8000)
        self._scaleInValueX = int(self.scaleInValueX*0x8000)
        self._scaleOutValueX = int(self.scaleOutValueX*0x8000)
        self._rotateDirection = int(self.rotateDirection*0x8000)
        self._rotateAngle = int(self.rotateAngle*0x8000)
        self._rotateSpeed = int(self.rotateSpeed*0x8000)
        self._rotateAngleRandom = int(self.rotateAngleRandom*0x8000)
        self._rotateSpeedRandom = int(self.rotateSpeedRandom*0x8000)
        super().write(fout)

class JPASweepShape(Section):
    header = Struct('>8xBBBxHHHB13xffHH11xBBBB4xff2xBBII')
    fields = [
        ('shapeType', ShapeType), ('dirType', DirType), ('rotType', RotType),
        'life', 'rate', '_timing', 'step',
        'posRndm', 'baseVel', '_velInfRate', '_rotateSpeed',
        '_inheritRGB', '_inheritAlpha', '_inheritScale',
        '_baseVelRndm', '_gravity',
        ('isEnableField', bool), ('isEnableDrawParent', bool), ('isEnableScaleOut', bool), ('isEnableAlphaOut', bool),
        'texIdx', 'globalScale2DX', 'globalScale2DY',
        ('isEnableRotate', bool), 'flags', 'colorPrm', 'colorEnv'
    ]
    def read(self, fin, start, length):
        super().read(fin, start, length)
        self.timing = self._timing/0x8000
        self.velInfRate = self._velInfRate/0x8000
        self.rotateSpeed = self._rotateSpeed/0x8000
        self.inheritRGB = self._inheritRGB/0x8000
        self.inheritAlpha = self._inheritAlpha/0x8000
        self.inheritScale = self._inheritScale/0x8000
        self.baseVelRndm = self._baseVelRndm/0x8000
        self.gravity = self._gravity/0x8000
        self.globalScale2D = (self.globalScale2DX, self.globalScale2DY)
    def write(self, fout):
        self._timing = int(self.timing*0x8000)
        self._velInfRate = int(self.velInfRate*0x8000)
        self._rotateSpeed = int(self.rotateSpeed*0x8000)
        self._inheritRGB = int(self.inheritRGB*0x8000)
        self._inheritAlpha = int(self.inheritAlpha*0x8000)
        self._inheritScale = int(self.inheritScale*0x8000)
        self._baseVelRndm = int(self.baseVelRndm*0x8000)
        self._gravity = int(self.gravity*0x8000)
        super().write(fout)

class IndTextureMode(Enum):
    Off    = 0x00
    Normal = 0x01
    Sub    = 0x02

class JPAExTexShape(Section):
    header = Struct('>8xBBhhhhhhbBB15xB2xB')
    fields = [
        (IndTextureMode, 'indTextureMode'), 'indTextureMtxID',
        'p00', 'p01', 'p02', 'p10', 'p11', 'p12',
        'power', 'indTextureID', 'subTextureID',
        'secondTextureFlags', 'secondTextureIndex'
    ]
    def read(self, fin, start, length):
        super().read(fin, start, length)
        scale = 2**self.power
        self.indTextureMtx = [
            self.p00*scale, self.p01*scale, self.p02*scale, scale,
            self.p10*scale, self.p11*scale, self.p12*scale, 0.0
        ]
    def write(self, fout):
        self.p00, self.p01, self.p02, scale, self.p10, self.p11, self.p12, z = self.indTextureMtx
        self.power = int(log2(scale))
        scale = 2**self.power
        self.p00 /= scale
        self.p01 /= scale
        self.p02 /= scale
        self.p10 /= scale
        self.p11 /= scale
        self.p12 /= scale
        super().write(fout)

class JPAKeyBlock(Section):
    header = Struct('>8xBxBx12x')
    fields = ['keyCount', ('isLoopEnable', bool)]
    def read(self, fin, start, length):
        super().read(fin, start, length)
        self.keyValues = array('f')
        self.keyValues.fromfile(self.keyCount*4)
        if sys.byteorder == 'little': self.keyValues.byteswap()
    def write(self, fout):
        self.keyCount = len(self.keyValues)//4
        super().write(fout)
        swapArray(self.keyValues).tofile(fout)

class FieldType(Enum):
    Gravity    = 0x00
    Air        = 0x01
    Magnet     = 0x02
    Newton     = 0x03
    Vortex     = 0x04
    Random     = 0x05
    Drag       = 0x06
    Convection = 0x07
    Spin       = 0x08

class FieldAddType(Enum):
    FieldAccel    = 0x00
    BaseVelocity  = 0x01
    FieldVelocity = 0x02

class JPAFieldBlock(Section):
    header = Struct('>4xBxBBBB2xffffffffffffhhhh')
    fields = [
        ('type', FieldType), ('velType', FieldAddType), 'cycle', 'sttFlag', 'unk1',
        'mag', 'magRndm', 'maxDist',
        'posX', 'posY', 'posZ',
        'dirX', 'dirY', 'dirZ',
        'param1', 'param2', 'param3',
        '_fadeIn', '_fadeOut',
        '_enTime', '_disTime'
    ]
    def read(self, fin, start, length):
        super().read(fin, start, length)
        self.pos = (self.posX, self.posY, self.posZ)
        self.dir = (self.dirX, self.dirY, self.dirZ)
        self.fadeIn = self._fadeIn/0x8000
        self.fadeOut = self._fadeOut/0x8000
        self.enTime = self._enTime/0x8000
        self.disTime = self._disTime/0x8000
    def write(self, fout):
        self.posX, self.posY, self.posZ = self.pos
        self.dirX, self.dirY, self.dirZ = self.dir
        self._fadeIn = int(self.fadeIn*0x8000)
        self._fadeOut = int(self.fadeOut*0x8000)
        self._enTime = int(self.enTime*0x8000)
        self._disTime = int(self.disTime*0x8000)
        super().write(fout)

class JPATexture(Section):
    header = Struct('4x')
    fields = []
    def read(self, fin, start, length):
        super().read(fin, start, length)
        self.texture = Image()
        name = fin.read(20)
        if name[0] == 0:
            self.texture.name = None
            textureHeaderOffset = 0
        else:
            self.texture.name = name.decode('shift-jis').rstrip("\0")
            textureHeaderOffset = 32
        fin.seek(start+textureHeaderOffset)
        self.texture.read(fin, start, textureHeaderOffset, 0)
    
    def write(self, fout):
        super().write(fout)
        if self.texture.name:
            fout.write(self.texture.name.encode('shift-jis').ljust(20, b'\0'))
        else:
            fout.write(b'\0'*20)
        self.texture.write(fout, 0)

class JPA(BFile):
    sectionHandlers = {
        b'BEM1': JPADynamicsBlock,
        b'BSP1': JPABaseShape,
        b'ESP1': JPAExtraShape,
        b'SSP1': JPASweepShape,
        b'ETX1': JPAExTexShape,
        b'KFA1': JPAKeyBlock,
        b'FLD1': JPAFieldBlock,
        b'TEX1': JPATexture
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: %s <jpa>\n"%sys.argv[0])
        exit(1)
    
    jpa = JPA()
    jpa.read(open(sys.argv[1], 'rb'))
    jpa.write(open(sys.argv[1][:sys.argv[1].rfind('.')]+"-out.jpa", 'wb'))

