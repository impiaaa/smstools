#!/usr/bin/env python

import sys, struct, array
from common import BFile, Section
from texture import readTextureData, decodeTexturePIL, calcTextureSize, TF
import os.path

class Gly1(Section):
    header = struct.Struct('>HHHHIhHHhh2x')
    
    def read(self, fin, start, size):
        self.minimumFontCode, self.maximumFontCode, self.glyphWidth, self.glyphHeight, self.arraySize, self.format, self.columns, self.rows, self.w, self.h = self.header.unpack(fin.read(self.header.size))
        self.format = TF(self.format)
        self.arrayCount = (size-self.header.size-8)/self.arraySize
        #self.h = (size-0x18)/w
        #if format == 0: self.h *= 2
        self.data = readTextureData(fin, self.format, self.w, self.h, arrayCount=self.arrayCount)
    
    def export(self, name):
        images = decodeTexturePIL(self.data, self.format, self.w, self.h, arrayCount=self.arrayCount)
        for arrayIdx, mips in enumerate(images):
            for mipIdx, im in enumerate(mips):
                im.save(name+str(arrayIdx)+".png")

class Map1(Section):
    header = struct.Struct('>hHHH')
    def read(self, fin, start, size):
        self.mappingType, self.startingCharacter, self.endingCharacter, spanCount = self.header.unpack(fin.read(self.header.size))
        self.spans = array.array('H')
        self.spans.fromfile(fin, spanCount)

class Inf1(Section):
    header = struct.Struct('>hhhhhH')
    def read(self, fin, start, size):
        self.fontType, self.ascent, self.descent, self.width, self.leading, self.defaultCharacterCode = self.header.unpack(fin.read(self.header.size))

class Wid1(Section):
    header = struct.Struct('>HH')
    def read(self, fin, start, size):
        self.minimumFontCode, self.maximumFontCode = self.header.unpack(fin.read(self.header.size))
        self.widths = array.array('H')
        self.widths.fromfile(fin, (self.maximumFontCode-self.minimumFontCode))

class BFont(BFile):
    sectionHandlers = {b'GLY1': Gly1, b'MAP1': Map1, b'INF1': Inf1, b'WID1': Wid1}

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <bfn>\n"%sys.argv[0])
    exit(1)

fin = open(sys.argv[1], 'rb')
bfn = BFont()
bfn.read(fin)
fin.close()
bfn.gly1.export(os.path.splitext(sys.argv[1])[0])

print("INF", bfn.inf1.fontType, bfn.inf1.ascent, bfn.inf1.descent, bfn.inf1.width, bfn.inf1.leading, bfn.inf1.defaultCharacterCode)
for chunk in bfn.chunks:
    if isinstance(chunk, Gly1):
        print("GLY", chunk.minimumFontCode, chunk.maximumFontCode, chunk.glyphWidth, chunk.glyphHeight, chunk.arraySize, chunk.format, chunk.columns, chunk.rows, chunk.w, chunk.h)
    if isinstance(chunk, Map1):
        print("MAP", chunk.mappingType, chunk.startingCharacter, chunk.endingCharacter)
        print(chunk.spans)
    if isinstance(chunk, Wid1):
        print("WID", chunk.minimumFontCode, chunk.maximumFontCode)
        print(chunk.widths)

