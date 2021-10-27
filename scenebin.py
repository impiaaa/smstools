from struct import unpack
import sys, io, pathlib
from warnings import warn

def readstring(fin):
    length, = unpack('>H', fin.read(2))
    return fin.read(length).decode("shift-jis")

class SceneObject:
    def __init__(self, namehash):
        self.namehash = namehash
    def read(self, fin):
        self.name = readstring(fin)
        self.deschash, = unpack('>H', fin.read(2))
        self.description = readstring(fin)
    def __repr__(self):
        return "%s(%04x): %s" % (self.name, self.namehash, self.description)

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

class AmbColor(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.r, self.g, self.b, self.a = unpack('>BBBB', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%s,%x'%(stylecolor(self.r, self.g, self.b), self.a)

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

class PositionObject(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.x, self.y, self.z = unpack('>fff', fin.read(12))

class Light(PositionObject):
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

class AreaCylinder(TwoStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk2 = unpack('>I', fin.read(4))
    def __repr__(self):
        return super().__repr__()+'|%d'%(self.unk2)

class OneStringObject(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.name1 = readstring(fin)
    def __repr__(self):
        return super().__repr__()+'|'+self.name1

class ManagerObject1(OneStringObject):
    def read(self, fin):
        super().read(fin)
        self.unk, self.u, self.v = unpack('>Iff', fin.read(12))
    def __repr__(self):
        return super().__repr__()+'|%d,%f,%f'%(self.unk, self.u, self.v)

class ManagerObject2(OneStringObject):
    def read(self, fin):
        super().read(fin)
        self.n1, self.n2 = unpack('>II', fin.read(8))
    def __repr__(self):
        return super().__repr__()+'|%d,%d'%(self.n1, self.n2)

class MarioPosition:
    def __repr__(self):
        return "%s" % (self.name)

class MarioPositionObj(SceneObject):
    def read(self, fin):
        super().read(fin)
        self.spawns = []
        while fin.tell() < len(fin.getvalue()):
            m = MarioPosition()
            m.name = readstring(fin)
            m.x, m.y, m.z, m.rx, m.ry, m.rz, m.sx, m.sy, m.sz = unpack('>fffffffff', fin.read(36))
            self.spawns.append(m)
    def __repr__(self):
        return super().__repr__()+repr(self.spawns)

class Mario(OneStringThreeDObject):
    def read(self, fin):
        super().read(fin)
        self.unk2 = unpack('>II', fin.read(8))
    def __repr__(self):
        return super().__repr__()+repr(self.unk2)

def readsection(fin):
    sectionlength, namehash = unpack('>IH', fin.read(6))
    if namehash in {0x41b8, 0x6e9e, 0x4746, 0xabc3, 0x220f, 0x586d, 0x3d5d}:
        o = GroupObject(namehash)
    elif namehash in {0x3c2e, 0x2682}:
        o = MultiGroupObject(namehash)
    elif namehash == 0xe529:
        o = AmbColor(namehash)
    elif namehash in {0x286a, 0x83c4}:
        o = Light(namehash)
    elif namehash in {0x0710, 0x0736, 0x08ba, 0x08f2, 0x0b42, 0x0b43, 0x0b44, \
                      0x0bc5, 0x0c5d, 0x0ca1, 0x0d63, 0x0d8a, 0x0f2e, 0x1004, \
                      0x14cf, 0x1c39, 0x1c73, 0x1ddd, 0x1e5f, 0x21e4, 0x259b, \
                      0x2639, 0x27f8, 0x2925, 0x2ce9, 0x2cfd, 0x2e81, 0x2f99, \
                      0x31ae, 0x372c, 0x377a, 0x3799, 0x3a33, 0x3eae, 0x3eda, \
                      0x3eec, 0x43e5, 0x495d, 0x4a81, 0x4b61, 0x4d86, 0x4f14, \
                      0x507e, 0x5678, 0x56ba, 0x5970, 0x5afe, 0x5b0c, 0x5c5f, \
                      0x5daa, 0x632e, 0x6380, 0x66d5, 0x67a4, 0x6877, 0x6aae, \
                      0x6cca, 0x6db9, 0x6dde, 0x6fca, 0x704a, 0x704d, 0x72ce, \
                      0x7328, 0x7335, 0x74e8, 0x79d1, 0x7bd3, 0x7df7, 0x7ed2, \
                      0x8141, 0x8386, 0x93a8, 0x97e5, 0x9a54, 0x9d1b, 0x9ee5, \
                      0xa1a8, 0xa9eb, 0xaa5f, 0xab6a, 0xb3ea, 0xb8be, 0xbc49, \
                      0xbf2f, 0xc1ea, 0xcc08, 0xcf5b, 0xd73c, 0xd794, 0xd940, \
                      0xdc40, 0xde07, 0xe015, 0xe0d1, 0xe36d, 0xe52b, 0xf2b5, \
                      0xf3d9, 0xf591, 0xfba0, 0xfd8b, 0xfe2f, 0xfebc}:
        o = TwoStringThreeDObject(namehash)
    elif namehash in {0x00fc, 0x9913}:
        o = OneStringObject(namehash)
    elif namehash in {0x0066, 0x8c51, 0x99b5, 0xc662}:
        o = ManagerObject1(namehash)
    elif namehash in {0x0070, 0x018e, 0x01d8, 0x030d, 0x03a6, 0x0891, 0x0a19, \
                      0x0a63, 0x0b8a, 0x13ff, 0x14aa, 0x167c, 0x1a70, 0x1e5c, \
                      0x23b7, 0x2c7c, 0x3301, 0x35e0, 0x391e, 0x3af2, 0x3af7, \
                      0x3e2f, 0x3e37, 0x44c6, 0x44df, 0x46ed, 0x49a2, 0x4cc4, \
                      0x4f77, 0x501a, 0x550d, 0x5574, 0x5c06, 0x5d77, 0x5ec6, \
                      0x60d1, 0x6229, 0x6834, 0x68da, 0x6c1c, 0x6ed6, 0x6f8e, \
                      0x723f, 0x725a, 0x7aa3, 0x7c85, 0x7cc1, 0x7f2a, 0x8217, \
                      0x8555, 0x8957, 0x8d58, 0x9044, 0x90cc, 0x936b, 0x9581, \
                      0x95ff, 0x9c8b, 0xa068, 0xa176, 0xa20a, 0xa5d3, \
                      0xa7af, 0xa94c, 0xae4b, 0xaf4b, 0xafe7, 0xb1ae, \
                      0xb2cb, 0xb412, 0xb865, 0xbc50, 0xbf93, 0xc601, 0xc740, \
                      0xc9d5, 0xcbaa, 0xcc67, 0xce4c, 0xce96, 0xd07b, 0xd22f, \
                      0xd293, 0xd495, 0xd6d7, 0xd721, 0xd7c6, 0xd8a0, 0xda3e, \
                      0xda80, 0xdd93, 0xdf62, 0xdfac, 0xe7ed, 0xe9e7, 0xf078, \
                      0xf0c2, 0xf0f9, 0xf10c, 0xf836, 0xf903, 0xf94d, 0xf97d, \
                      0xf997, 0xfb95, 0xfdee}:
        o = ManagerObject2(namehash)
    elif namehash == 0x574e:
        o = MarioPositionObj(namehash)
    elif namehash == 0xa2fb:
        o = AreaCylinder(namehash)
    elif namehash == 0x2844:
        o = Mario(namehash)
    elif namehash in {0x04a5, 0x05cf, 0x157b, 0x65f1, 0x7d13, 0x8752, 0x9461, \
                      0xa3d9, 0xa446, 0xad45, 0xb0b0, 0xcc8c, 0xdc95, 0xeea9}:
        o = OneStringThreeDObject(namehash)
    elif namehash in {0x0175, 0x0215, 0x032c, 0x0379, 0x0710, 0x0736, 0x08ba, 0x08f2, 0x0b42, 0x0b43, 0x0b44, 0x0b77, 0x0bc5, 0x0c5d, 0x0ca1, 0x0cbf, 0x0cd2, 0x0d63, 0x0d8a, 0x0f2e, 0x1004, 0x14cf, 0x1592, 0x168d, 0x16be, 0x18fa, 0x1930, 0x1936, 0x19de, 0x1b02, 0x1c39, 0x1c3e, 0x1c73, 0x1ddd, 0x1e5f, 0x1fe7, 0x1fe8, 0x1fe9, 0x1fea, 0x213f, 0x21e4, 0x243c, 0x243d, 0x243e, 0x243f, 0x2440, 0x2441, 0x2442, 0x2443, 0x245a, 0x245b, 0x245c, 0x259b, 0x25db, 0x2639, 0x26f1, 0x27f8, 0x2908, 0x2925, 0x293f, 0x2983, 0x298b, 0x29fb, 0x2a9b, 0x2ac0, 0x2b07, 0x2b5c, 0x2bbc, 0x2c9e, 0x2cae, 0x2ce9, 0x2cfd, 0x2dd6, 0x2ddd, 0x2de3, 0x2dea, 0x2e81, 0x2f99, 0x312c, 0x31ae, 0x358d, 0x372c, 0x377a, 0x3799, 0x3887, 0x3a33, 0x3d4d, 0x3eae, 0x3eda, 0x3eec, 0x4042, 0x4120, 0x43e5, 0x4697, 0x4698, 0x47bb, 0x488c, 0x48d6, 0x495d, 0x49c9, 0x4a81, 0x4b4a, 0x4b61, 0x4bfe, 0x4d0c, 0x4d86, 0x4e03, 0x4f14, 0x4f9a, 0x507e, 0x53a3, 0x546d, 0x5678, 0x56ba, 0x596f, 0x5970, 0x5979, 0x59db, 0x5afe, 0x5b0c, 0x5c5f, 0x5daa, 0x5ecf, 0x5f55, 0x5fbf, 0x6133, 0x6278, 0x632e, 0x6380, 0x6386, 0x63c4, 0x63ff, 0x66d5, 0x67a4, 0x6877, 0x69c3, 0x6a80, 0x6aae, 0x6cc7, 0x6cca, 0x6d13, 0x6db4, 0x6db9, 0x6dde, 0x6f7d, 0x6fca, 0x704a, 0x704d, 0x7298, 0x72ce, 0x7328, 0x7335, 0x74e8, 0x75ce, 0x7864, 0x79d1, 0x7aaa, 0x7b12, 0x7bd3, 0x7ccb, 0x7cdb, 0x7df7, 0x7e3b, 0x7ed2, 0x7eed, 0x80cc, 0x8117, 0x8141, 0x81ef, 0x8267, 0x82f6, 0x8375, 0x8386, 0x8567, 0x887c, 0x88bb, 0x895f, 0x8a0f, 0x8ade, 0x8d1b, 0x8d9d, 0x8fe1, 0x9146, 0x92de, 0x93a8, 0x93ea, 0x9792, 0x97e5, 0x9a54, 0x9b19, 0x9b43, 0x9b90, 0x9cbb, 0x9d1b, 0x9ee5, 0xa1a8, 0xa2fb, 0xa9a8, 0xa9af, 0xa9eb, 0xaa5f, 0xab6a, 0xacda, 0xaf4d, 0xb0d6, 0xb1cc, 0xb1cd, 0xb1ce, 0xb1ea, 0xb1eb, 0xb3ea, 0xb6a9, 0xb6b3, 0xb8be, 0xbc49, 0xbc6e, 0xbc90, 0xbf23, 0xbf2f, 0xc0f8, 0xc1ea, 0xc6c0, 0xcad9, 0xcbcb, 0xcc08, 0xcf5b, 0xd73c, 0xd794, 0xd940, 0xd9a1, 0xdc40, 0xde07, 0xe015, 0xe0d1, 0xe171, 0xe1e9, 0xe36d, 0xe37d, 0xe396, 0xe52b, 0xe533, 0xe5d9, 0xe5e3, 0xe66f, 0xe6b4, 0xebaf, 0xee83, 0xf2b5, 0xf3d9, 0xf58f, 0xf591, 0xf93e, 0xfb60, 0xfba0, 0xfc74, 0xfcc1, 0xfd3a, 0xfd51, 0xfd8b, 0xfe2f, 0xfebc, 0xff57, 0xff5b, 0xffe9}:
        # TODO
        o = TwoStringThreeDObject(namehash)
    else:
        o = SceneObject(namehash)
    
    if 0:
        x = io.BytesIO(fin.read(sectionlength-6))
        o = TwoStringThreeDObject(namehash)
        try:
            o.read(x)
            #assert len(x.read()) == 0
            assert len(o.manager) > 0
            assert len(o.model) > 0
            assert o.rx >= -360 and o.rx <= 360
            assert o.ry >= -360 and o.ry <= 360
            assert o.rz >= -360 and o.rz <= 360
            assert o.sx > 0 and o.sy > 0 and o.sz > 0
            print('%04x'%o.namehash)
        except:
            pass
        return

    x = io.BytesIO(fin.read(sectionlength-6))
    try: o.read(x)
    except:
        print('%04x'%namehash)
        raise
    o.extra = x.read()
    return o


if __name__ == "__main__":
    argpath = pathlib.Path(sys.argv[1])
    if argpath.is_dir():
        if argpath.name == "map":
            scenedirpath = argpath.parent
            scenebinpath = argpath / "scene.bin"
        else:
            scenedirpath = argpath
            scenebinpath = scenedirpath / "map" / "scene.bin"
    else:
        scenedirpath = argpath.parents[1]
        scenebinpath = argpath

    scenename = scenedirpath.name

    def printobj(o, i=0):
        print('  '*i, o)
        if o.extra: print('  '*(i+1), o.extra.hex())
        if hasattr(o, "objects"):
            for o2 in o.objects:
                printobj(o2, i+1)
    o = readsection(open(scenebinpath, 'rb'))
    printobj(o)

