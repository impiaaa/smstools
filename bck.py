from warnings import warn
import sys
from common import *
from struct import unpack, pack, Struct, error as StructError
from warnings import warn
from array import array
from enum import Enum
import math
from bisect import bisect

def convRotation(rots, scale):
    for r in rots:
        r.value *= scale
        r.tangentIn *= scale
        r.tangentOut *= scale

class LoopMode(Enum):
    ONCE = 0
    ONCE_AND_RESET = 1
    REPEAT = 2
    MIRRORED_ONCE = 3
    MIRRORED_REPEAT = 4

class J3DAnmTransformKeyData(Section):
    header = Struct('>BBHHHHHIIII')
    fields = [
        ('loopMode', LoopMode), 'angleMultiplier', 'animationLength',
        'numJoints', 'scaleCount', 'rotCount', 'transCount',
        'offsetToJoints', 'offsetToScales', 'offsetToRots', 'offsetToTrans'
    ]
    def read(self, fin, start, size):
        super().read(fin, start, size)
        scales = array('f')
        fin.seek(start+self.offsetToScales)
        scales.fromfile(fin, self.scaleCount)
        if sys.byteorder == 'little': scales.byteswap()
        
        rotations = array('h')
        fin.seek(start+self.offsetToRots)
        rotations.fromfile(fin, self.rotCount)
        if sys.byteorder == 'little': rotations.byteswap()

        translations = array('f')
        fin.seek(start+self.offsetToTrans)
        translations.fromfile(fin, self.transCount)
        if sys.byteorder == 'little': translations.byteswap()
        
        rotationScale = (1<<self.angleMultiplier)*math.pi/0x7FFF
        fin.seek(start+self.offsetToJoints)
        self.anims = [None]*self.numJoints
        for i in range(self.numJoints):
            joint = AnimatedJoint()
            joint.read(fin)
            
            anim = Animation()
            
            anim.scalesX = readComp(scales, joint.x.s)
            anim.scalesY = readComp(scales, joint.y.s)
            anim.scalesZ = readComp(scales, joint.z.s)

            anim.rotationsX = readComp(rotations, joint.x.r)
            convRotation(anim.rotationsX, rotationScale)
            anim.rotationsY = readComp(rotations, joint.y.r)
            convRotation(anim.rotationsY, rotationScale)
            anim.rotationsZ = readComp(rotations, joint.z.r)
            convRotation(anim.rotationsZ, rotationScale)

            anim.translationsX = readComp(translations, joint.x.t)
            anim.translationsY = readComp(translations, joint.y.t)
            anim.translationsZ = readComp(translations, joint.z.t)
            
            self.anims[i] = anim
    
    def write(self, fout):
        maxRotation = max(
         abs(v) for anim in self.anims
                for key in anim.rotationsX+anim.rotationsY+anim.rotationsZ
                for v in (key.value, key.tangentIn, key.tangentOut)
        )
        if maxRotation == 0:
            self.angleMultiplier = 0
        else:
            self.angleMultiplier = max(0, math.ceil(math.log2(maxRotation/math.pi)))
        rotationScale = (1<<self.angleMultiplier)*math.pi/0x7FFF
        
        scales = array('f')
        rotations = array('h')
        translations = array('f')
        joints = []
        for anim in self.anims:
            joint = AnimatedJoint()
            
            addComp(joint.x.s, anim.scalesX, scales)
            addComp(joint.y.s, anim.scalesY, scales)
            addComp(joint.z.s, anim.scalesZ, scales)
            
            addComp(joint.x.r, anim.rotationsX, rotations, rotationScale, int)
            addComp(joint.y.r, anim.rotationsY, rotations, rotationScale, int)
            addComp(joint.z.r, anim.rotationsZ, rotations, rotationScale, int)

            addComp(joint.x.t, anim.translationsX, translations)
            addComp(joint.y.t, anim.translationsY, translations)
            addComp(joint.z.t, anim.translationsZ, translations)
            
            joints.append(joint)
        
        if sys.byteorder == 'little':
            scales.byteswap()
            rotations.byteswap()
            translations.byteswap()
        
        self.offsetToJoints = self.header.size+8
        self.numJoints = len(self.anims)
        
        self.offsetToScales = self.offsetToJoints+(9*AnimIndex.header.size*len(joints))
        self.scaleCount = len(scales)
        
        self.offsetToRots = self.offsetToScales+(scales.itemsize*len(scales))
        self.rotCount = len(rotations)
        
        self.offsetToTrans = self.offsetToRots+(rotations.itemsize*len(rotations))
        self.transCount = len(translations)
        
        super().write(fout)
        
        for joint in joints:
            joint.write(fout)
        
        scales.tofile(fout)
        rotations.tofile(fout)
        translations.tofile(fout)

class Bck(BFile):
    sectionHandlers = {b'ANK1': J3DAnmTransformKeyData}

class AnimatedJoint(Readable):
    def __init__(self, f=None):
        self.x = AnimComponent()
        self.y = AnimComponent()
        self.z = AnimComponent()
        super().__init__(f)
    def read(self, f):
        self.x.read(f)
        self.y.read(f)
        self.z.read(f)
    def write(self, f):
        self.x.write(f)
        self.y.write(f)
        self.z.write(f)

class AnimComponent(Readable):
    def __init__(self, f=None):
        self.s = AnimIndex()
        self.r = AnimIndex()
        self.t = AnimIndex()
        super().__init__(f)
    def read(self, f):
        self.s.read(f)
        self.r.read(f)
        self.t.read(f)
    def write(self, f):
        self.s.write(f)
        self.r.write(f)
        self.t.write(f)

class TangentType(Enum):
    In = 0
    InOut = 1

class AnimIndex(ReadableStruct):
    header = Struct('>HHH')
    fields = ["count", "index", ("tangent", TangentType)]

class Key(object):
    time: float
    value: float
    tangentIn: float
    tangentOut: float

class Animation(object):
    scalesX: list[Key]
    scalesY: list[Key]
    scalesZ: list[Key]
    rotationsX: list[Key]
    rotationsY: list[Key]
    rotationsZ: list[Key]
    translationsX: list[Key]
    translationsY: list[Key]
    translationsZ: list[Key]

def readComp(src, index):
    dst = [None]*index.count

    if index.count <= 0:
        warn("bck1: readComp(): count is <= 0")
        return
    elif index.count == 1:
        k = Key()
        k.time = 0
        k.value = src[index.index]
        k.tangentIn = 0
        k.tangentOut = 0
        dst[0] = k
    else:
        sz = {TangentType.In: 3, TangentType.InOut: 4}[index.tangent]
        for j in range(index.count):
            k = Key()
            k.time = src[index.index + sz*j]
            k.value = src[index.index + sz*j + 1]
            k.tangentIn = src[index.index + sz*j + 2]
            if index.tangent == TangentType.InOut:
                k.tangentOut = src[index.index + sz*j + 3]
            else:
                k.tangentOut = k.tangentIn
            dst[j] = k
        dst.sort(key=lambda a: a.time)
    
    return dst

def addComp(idx: AnimIndex, keys: list[Key], out, scale=1.0, cnv=float):
    idx.count = len(keys)
    tangentSimple = all([key.tangentIn == key.tangentOut for key in keys])
    idx.tangent = TangentType.In if tangentSimple else TangentType.InOut
    if idx.count == 1:
        values = [cnv(key.value/scale) for key in keys]
    elif tangentSimple:
        values = [cnv(v) for key in keys for v in (key.time, key.value/scale, key.tangentIn/scale)]
    else:
        values = [cnv(v) for key in keys for v in (key.time, key.value/scale, key.tangentIn/scale, key.tangentOut/scale)]
    idx.index = arrayStringSearch(out, values)
    if idx.index is None:
        idx.index = len(out)
        out.extend(values)

def getPointCubic(cf, t):
    return ((cf[0] * t + cf[1]) * t + cf[2]) * t + cf[3]

def getDerivativeCubic(cf, t):
    return (3 * cf[0] * t + 2 * cf[1]) * t + cf[2]

def getCoeffHermite(p0, p1, s0, s1):
    return (
        (p0 *  2) + (p1 * -2) + (s0 *  1) +  (s1 *  1),
        (p0 * -3) + (p1 *  3) + (s0 * -2) +  (s1 * -1),
        (p0 *  0) + (p1 *  0) + (s0 *  1) +  (s1 *  0),
        (p0 *  1) + (p1 *  0) + (s0 *  0) +  (s1 *  0)
    )

def getPointHermite(p0, p1, s0, s1, t):
    coeff = getCoeffHermite(p0, p1, s0, s1)
    return getPointCubic(coeff, t)

def getDerivativeHermite(p0, p1, s0, s1, t):
    coeff = getCoeffHermite(p0, p1, s0, s1)
    return getDerivativeCubic(coeff, t)

def hermiteInterpolate(k0, k1, frame, tangents=False):
    length = k1.time - k0.time
    t = (frame - k0.time) / length
    p0 = k0.value
    p1 = k1.value
    s0 = k0.tangentOut * length
    s1 = k1.tangentIn * length
    if tangents:
        return getPointHermite(p0, p1, s0, s1, t), getDerivativeHermite(p0, p1, s0, s1, t)
    else:
        return getPointHermite(p0, p1, s0, s1, t)

def animateSingle(time, keyList, tangents=False):
    timeList = [key.time for key in keyList]
    i = bisect(timeList, time)
    if i <= 0:
        # the time is before any keys
        if tangents:
            return keyList[0].value, keyList[0].tangentIn
        else:
            return keyList[0].value
    elif i >= len(keyList):
        # the time is after all keys
        if tangents:
            return keyList[-1].value, keyList[0].tangentOut
        else:
            return keyList[-1].value
    else:
        keyBefore = keyList[i-1]
        keyAfter = keyList[i]
        return hermiteInterpolate(keyBefore, keyAfter, time, tangents)

def animate(time, keyListSet, tangents=False):
    return (animateSingle(time, keyList, tangents) for keyList in keyListSet)

