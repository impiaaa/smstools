import struct
from struct import unpack
import sys, io, pathlib
from warnings import warn

def calcKeyCode(name):
    x = 0
    for c in name.encode('shift-jis'):
        x = (c + x*3)&0xFFFF
    return x

def readString(fin):
    length, = unpack('>H', fin.read(2))
    return fin.read(length).decode('shift-jis')

def stylecolor(r,g,b):
    if (r*r + g*g + b*b) < 48768:
        stylecode = 48
    else:
        stylecode = 38
    return "\x1b[%d;2;%d;%d;%dm#%02X%02X%02X\x1b[0m"%(stylecode, r, g, b, r, g, b)

class NamedPosition:
    def read(self, fin):
        self.name = readString(fin)
        self.x, self.y, self.z, self.rx, self.ry, self.rz, self.sx, self.sy, self.sz = unpack('>fffffffff', fin.read(36))
    def __repr__(self):
        return "%s(%.1f,%.1f,%.1f)" % (self.name, self.x, self.y, self.z)

def readsection(fin):
    sectionlength, namehash = unpack('>IH', fin.read(6))
    #print("len", sectionlength, "hash", namehash)
    #print("at", fin.tell())
    name = readString(fin)
    assert namehash == calcKeyCode(name), (hex(namehash), name)
    #print("Found a", name)
    if name in classes.registeredObjectClasses:
        #print("Constructing a", classes.registeredObjectClasses[name])
        o = classes.registeredObjectClasses[name]()
    else:
        warn("Unknown class {}".format(name))
        o = classes.TNameRef()
    
    o.namehash = namehash
    o.name = name
    
    assert name.isidentifier()
    x = io.BytesIO(fin.read(sectionlength-8-len(name)))
    #print("Reading")
    try:
        o.read(x)
    except struct.error as e:
        warn("Couldn't load a {}: {}".format(name, e))
    o.extra = x.read()
    #print("Got", o)
    return o

import classes

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s scene.bin\n"%sys.argv[0])
    exit(1)

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

