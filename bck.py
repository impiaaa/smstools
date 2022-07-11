from warnings import warn
import sys
from common import *
from struct import unpack, pack, Struct, error as StructError
from warnings import warn
from array import array
import math
assert sys.version_info[0] >= 3

def convRotation(rots, scale):
    for r in rots:
        r.value *= scale
        r.tangent *= scale

class Ank1(Section):
    header = Struct('>BBHHHHHIIII')
    def read(self, fin, start, size):
        self.loopFlags, angleMultiplier, self.animationLength, \
        numJoints, scaleCount, rotCount, transCount, \
        offsetToJoints, offsetToScales, offsetToRots, offsetToTrans = self.header.unpack(fin.read(28))
        
        scales = array('f')
        fin.seek(start+offsetToScales)
        scales.fromfile(fin, scaleCount)
        if sys.byteorder == 'little': scales.byteswap()
        
        rotations = array('h')
        fin.seek(start+offsetToRots)
        rotations.fromfile(fin, rotCount)
        if sys.byteorder == 'little': rotations.byteswap()

        translations = array('f')
        fin.seek(start+offsetToTrans)
        translations.fromfile(fin, transCount)
        if sys.byteorder == 'little': translations.byteswap()
        
        rotScale = float(1<<angleMultiplier)*math.pi/32768.0
        fin.seek(start+offsetToJoints)
        self.anims = [None]*numJoints
        for i in range(numJoints):
            joint = AnimatedJoint()
            joint.read(fin)
            
            anim = Animation()
            
            anim.scalesX = readComp(scales, joint.x.s)
            anim.scalesY = readComp(scales, joint.y.s)
            anim.scalesZ = readComp(scales, joint.z.s)

            anim.rotationsX = readComp(rotations, joint.x.r)
            convRotation(anim.rotationsX, rotScale)
            anim.rotationsY = readComp(rotations, joint.y.r)
            convRotation(anim.rotationsY, rotScale)
            anim.rotationsZ = readComp(rotations, joint.z.r)
            convRotation(anim.rotationsZ, rotScale)

            anim.translationsX = readComp(translations, joint.x.t)
            anim.translationsY = readComp(translations, joint.y.t)
            anim.translationsZ = readComp(translations, joint.z.t)
            
            self.anims[i] = anim

class Bck(BFile):
    sectionHandlers = {b'ANK1': Ank1}

class AnimatedJoint(Readable):
    def read(self, f):
        self.x = AnimComponent(f)
        self.y = AnimComponent(f)
        self.z = AnimComponent(f)

class AnimComponent(Readable):
    def read(self, f):
        self.s = AnimIndex(f)
        self.r = AnimIndex(f)
        self.t = AnimIndex(f)

class AnimIndex(ReadableStruct):
    header = Struct('>HHH')
    fields = ["count", "index", "zero"]

class Key(object): pass
class Animation(object): pass

def readComp(src, index):
    dst = [None]*index.count
    #violated by biawatermill01.bck
    if index.zero != 0:
        warn("bck: zero field %d instead of zero" % index.zero)
    #TODO: biawatermill01.bck doesn't work, so the "zero"
    #value is obviously something important

    if index.count <= 0:
        warn("bck1: readComp(): count is <= 0")
        return
    elif index.count == 1:
        k = Key()
        k.time = 0
        k.value = src[index.index]
        k.tangent = 0
        dst[0] = k
    else:
        for j in range(index.count):
            k = Key()
            k.time = src[index.index + 3*j]
            k.value = src[index.index + 3*j + 1]
            k.tangent = src[index.index + 3*j + 2]
            dst[j] = k
        dst.sort(key=lambda a: a.time)
    
    return dst

