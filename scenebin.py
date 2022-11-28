import struct
from struct import unpack
import sys, io, pathlib
from warnings import warn
from common import calcKeyCode

def readString(fin):
    length, = unpack('>H', fin.read(2))
    return fin.read(length).decode('shift-jis')

def stylecolor(c):
    r, g, b = c[:3]
    if (r*r + g*g + b*b) < 48768:
        stylecode = 48
    else:
        stylecode = 38
    mr = min(r, 255)
    mg = min(g, 255)
    mb = min(b, 255)
    s = "\x1b[%d;2;%d;%d;%dm#%02X%02X%02X\x1b[0m"%(stylecode, mr, mg, mb, r, g, b)
    for x in c[3:]:
        s += " %02X"%x
    return s

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

if __name__ == "__main__":
    def printobj(o, i=0):
        try: print('  '*i, o)
        except Exception as e: print('  '*i, e)
        if o.extra:
            print('  '*(i+1), o.extra.hex())
        if hasattr(o, "objects"):
            for o2 in o.objects:
                printobj(o2, i+1)
    o = readsection(open(sys.argv[1], 'rb'))
    printobj(o)

