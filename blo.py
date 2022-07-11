#!/usr/bin/env python

import sys, os
from struct import unpack, Struct
from common import Section, BFile

class Bgn1(Section): pass

class End1(Section): pass

class Inf1(Section):
    header = Struct('>HHI')
    def read(self, fin, start, size):
        self.width, self.height, unknown = self.header.unpack(fin.read(size-8))

class Pan1(Section):
    header = Struct('>H?x4shhhh')
    def read(self, fin, start, size):
        self.rel, self.unknown1, self.id, self.x, self.y, self.width, self.height = self.header.unpack(fin.read(16))

def getResource(fin):
    unk, namelen = unpack('>BB', fin.read(2))
    return fin.read(namelen).decode('shift-jis')

class Pic1(Pan1):
    def read(self, fin, start, size):
        super().read(fin, start, size)
        self.imageName = getResource(fin)
        self.lutName = getResource(fin)

class BLayout(BFile):
    sectionHandlers = {
        b'BGN1': Bgn1,
        b'END1': End1,
        b'PIC1': Pic1,
        b'PAN1': Pan1
    }

grayimages = ["coin_back", "error_window", "juice_liquid", "juice_mask", "juice_surface", "sc_mask", "standard_window", "telop_window_1", "telop_window_2", "telop_window_3", "telop_window_4", "water_back", "water_icon_1", "water_icon_2", "water_icon_3"]

def parsechunks(chunklist, i=0, indent=0, parentx=0, parenty=0):
    toWrite = "<div>\n"
    lastX = lastY = 0
    newx = newy = 0
    while i < len(chunklist):
        chunk = chunklist[i]
        print(' '*indent+chunk.__class__.__name__)
        if isinstance(chunk, Bgn1):
            htmlout.write(toWrite)
            i = parsechunks(chunklist, i+1, indent+1, newx+parentx, newy+parenty)
            htmlout.write("</div>\n")
        elif isinstance(chunk, End1):
            return i
        elif isinstance(chunk, Pan1):
            if chunk.rel == 0x06:
                # relative to parent
                pass
            elif chunk.rel == 0x07:
                # relative to last
                chunk.x += lastX
                chunk.y += lastY
            elif chunk.rel == 0x08:
                # relative to parent, but different order, and set last
                lastX = chunk.x
                lastY = chunk.y
            elif chunk.rel == 0x09:
                # ???
                pass
            if isinstance(chunk, Pic1):
                htmlout.write('<img style="position:absolute; left:%dpx; top:%dpx; width:%dpx; height: %dpx; border: black 0px solid" src="../timg/%s.png" id="%s">\n'%(chunk.x,chunk.y,chunk.width,chunk.height,chunk.imageName,chunk.id))
            else:
                toWrite = '<div style="position:absolute; left:%dpx; top:%dpx; width:%dpx; height: %dpx; border: black 0px solid">\n'%(chunk.x, chunk.y, chunk.width, chunk.height)
        i += 1
    return i

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <blo>\n"%sys.argv[0])
    exit(1)

fin = open(sys.argv[1], 'rb')
blo = BLayout()
blo.read(fin)
fin.close()

htmlout = open(os.path.splitext(sys.argv[1])[0]+".html", 'w')
htmlout.write("<html><head><title></title></head><body>\n")
parsechunks(blo.chunks)
htmlout.write("</body></html>")
htmlout.close()
