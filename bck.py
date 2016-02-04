from struct import unpack
from array import array
from warnings import warn
import sys, os.path

fin = open(sys.argv[1], 'rb')
signature, fileLength, chunkCount, svr = unpack('>8sLL4s12x', fin.read(0x20))

class f(object):
    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, ", ".join(["%s=%r" % x for x in vars(self).iteritems()]))
class Joint(f): pass
class Component(f): pass
class Index(f): pass
class Key(f): pass
class Animation(f):
    def __init__(self):
        self.scalesX = []
        self.scalesY = []
        self.scalesZ = []
        
        self.rotationsX = []
        self.rotationsY = []
        self.rotationsZ = []

        self.translationsX = []
        self.translationsY = []
        self.translationsZ = []

def readAnimIndex(f, h):
    h.count, h.index, h.zero = unpack('>HHH', f.read(6))

def readAnimComponent(f, h):
    h.s = Index()
    h.r = Index()
    h.t = Index()
    readAnimIndex(f, h.s)
    readAnimIndex(f, h.r)
    readAnimIndex(f, h.t)

def readAnimatedJoint(f, h):
    h.x = Component()
    h.y = Component()
    h.z = Component()
    readAnimComponent(f, h.x)
    readAnimComponent(f, h.y)
    readAnimComponent(f, h.z)

def readComp(dst, src, index):
    #violated by biawatermill01.bck
    if index.zero != 0:
        warn("bck: zero field %d instead of zero" % index.zero)
    #TODO: biawatermill01.bck doesn't work, so the "zero"
    #value is obviously something important

    if index.count <= 0:
        warn("bck1: readComp(): count is <= 0")
        return
    elif index.count == 1:
        dst.append(Key())
        dst[0].time = 0
        dst[0].value = src[index.index]
        dst[0].tangent = 0
    else:
        for j in xrange(index.count):
            dst.append(Key())
            dst[j].time = src[index.index + 3*j]
            dst[j].value = src[index.index + 3*j + 1]
            dst[j].tangent = src[index.index + 3*j + 2]

def convRotation(rots, scale):
    for r in rots:
        r.value *= scale
        r.tangent *= scale

for chunkno in xrange(chunkCount):
    start = fin.tell()
    try: chunk, size = unpack('>4sL', fin.read(8))
    except struct.error:
        warn("File too small for chunk count of "+str(chunkCount))
        continue
    if chunk == "ANK1":
        loopFlags, angleMultiplier, animationLength, numJoints, scaleCount, rotCount, transCount, offsetToJoints, offsetToScales, offsetToRots, offsetToTrans = unpack('>BBHHHHHIIII', fin.read(28))
        
        fin.seek(start+offsetToScales)
        scales = array('f')
        scales.fromfile(fin, scaleCount)
        scales.byteswap()
        
        fin.seek(start+offsetToRots)
        rotations = array('h')
        rotations.fromfile(fin, rotCount)
        rotations.byteswap()
        rotations = list(rotations)
        rotScale = (2.0**angleMultiplier)*180/32768.0
        for i in xrange(len(rotations)):
            #rotations[i] *= rotScale
            rotations[i] = 0

        fin.seek(start+offsetToTrans)
        translations = array('f')
        translations.fromfile(fin, transCount)
        translations.byteswap()
        
        fin.seek(start+offsetToJoints)
        anims = []
        joints = []
        for i in xrange(numJoints):
            joint = Joint()
            joints.append(joint)
            readAnimatedJoint(fin, joint)
            anim = Animation()

            readComp(anim.scalesX, scales, joint.x.s)
            readComp(anim.scalesY, scales, joint.y.s)
            readComp(anim.scalesZ, scales, joint.z.s)

            readComp(anim.rotationsX, rotations, joint.x.r)
            readComp(anim.rotationsY, rotations, joint.y.r)
            readComp(anim.rotationsZ, rotations, joint.z.r)

            readComp(anim.translationsX, translations, joint.x.t)
            readComp(anim.translationsY, translations, joint.y.t)
            readComp(anim.translationsZ, translations, joint.z.t)
            
            anims.append(anim)
    else:
        warn("Unsupported section \'%s\'" % chunk)
    fin.seek(start+size)

fin.close()

def dopart(part, array, frameno, fout):
    for j in xrange(part.count):
        if translations[part.index + 3*j] == frameno:
            fout.write("%f "%array[part.index + 3*j + 1])
            return
        elif translations[part.index + 3*j] > frameno:
            # Too far! Rewind to last frame.
            # TODO: Interpolate missing frame components
            #fout.write("%f "%array[part.index + 3*j - 2])
            fout.write("X ")
            return
    fout.write("%f "%array[part.index + 1])

fout = open(os.path.splitext(sys.argv[1])[0]+"_anim.smd", 'w')
for frameno in xrange(animationLength):
    fout.write("time %d\n"%frameno)
    for i, joint in enumerate(joints):
        if joint.x.t.count < 1:
            print joint.x.t
        fout.write("%d "%i)
        dopart(joint.x.t, translations, frameno, fout)
        dopart(joint.y.t, translations, frameno, fout)
        dopart(joint.z.t, translations, frameno, fout)
        dopart(joint.x.r, rotations, frameno, fout)
        dopart(joint.y.r, rotations, frameno, fout)
        dopart(joint.z.r, rotations, frameno, fout)
        fout.write("\n")
fout.close()

