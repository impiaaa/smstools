#!/usr/bin/env python

import sys, struct
from common import BFile, Section
from texture import readTextureData, decodeTexturePIL, calcTextureSize

class Gly1(Section):
    header = struct.Struct('>H4xHH')
    
    def read(self, fin, start, size):
        fin.seek(0xC, 1)
        self.format, self.w, self.h = self.header.unpack(fin.read(0xa))
        self.arrayCount = (size-0x18)/calcTextureSize(self.format, self.w, self.h)
        #self.h = (size-0x18)/w
        #if format == 0: self.h *= 2
        fin.seek(2, 1)
        self.data = readTextureData(fin, self.format, self.w, self.h, arrayCount=self.arrayCount)
    
    def export(self, name):
        images = decodeTexturePIL(self.data, self.format, self.w, self.h, arrayCount=self.arrayCount)
        for arrayIdx, mips in enumerate(images):
            for mipIdx, im in enumerate(mips):
                print arrayIdx, mipIdx
                im.save(name+str(arrayIdx)+'.png')

class BFont(BFile):
    def __init__(self, *args, **kwargs):
        super(BFont, self).__init__(*args, **kwargs)
        # TODO: INF1, WID1, MAP1
        self.sectionHandlers = {b"GLY1": Gly1}

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <bfn>\n"%sys.argv[0])
    exit(1)

fin = open(sys.argv[1], 'rb')
bfn = BFont()
bfn.read(fin)
fin.close()
bfn.gly1.export(sys.argv[1])
