from struct import unpack, pack, Struct, error as StructError
from warnings import warn
from array import array
import sys
import math

def getString(pos, f):
    t = f.tell()
    f.seek(pos)
    if sys.version_info[0] >= 3: ret = bytes()
    else: ret = str()

    c = f.read(1)
    while ord(c) != 0 and len(c) != 0:
        ret += c
        c = f.read(1)

    f.seek(t)

    return ret.decode('shift-jis')

class Readable(object):
    def __init__(self, fin=None):
        super()
        if fin is not None: self.read(fin)

class Section(object): pass

class Bck(object):
    def read(self, fin):
        signature, fileLength, chunkCount, svr = unpack('>8sLL4s12x', fin.read(0x20))
        for chunkno in range(chunkCount):
            start = fin.tell()
            try: chunk, size = unpack('>4sL', fin.read(8))
            except StructError:
                warn("File too small for chunk count of "+str(chunkCount))
                continue
            if chunk == b"ANK1":
                self.ank1 = Ank1()
                self.ank1.read(fin, start, size)
            else:
                warn("Unsupported section %r" % chunk)
            fin.seek(start+size)

def convRotation(rots, scale):
    for r in rots:
        r.value *= scale
        r.tangent *= scale

class Ank1(object):
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

class AnimIndex(Readable):
    header = Struct('>HHH')
    def read(self, f):
        self.count, self.index, self.zero = self.header.unpack(f.read(6))

class Key(object): pass
class Animation(object): pass
