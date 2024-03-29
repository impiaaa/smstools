#!/usr/bin/env python

import sys, struct, array
from common import BFile, Section, swapArray
from texture import readTextureData, decodeTexturePIL, calcTextureSize, TexFmt
import os.path

class Gly1(Section):
    header = struct.Struct('>HHHHIhHHhh2x')
    fields = [
        'minimumFontCode', 'maximumFontCode',
        'glyphWidth', 'glyphHeight',
        'arraySize', ('format', TexFmt), 'columns', 'rows', 'w', 'h'
    ]
    
    def read(self, fin, start, size):
        super().read(fin, start, size)
        self.arrayCount = (size-self.header.size-8)//self.arraySize
        #self.h = (size-0x18)/w
        #if format == 0: self.h *= 2
        self.data = readTextureData(fin, self.format, self.w, self.h, arrayCount=arrayCount)
    
    def write(self, fout):
        super().write(fout)
        swapArray(self.data).tofile(fout)
    
    def export(self, name):
        images = decodeTexturePIL(self.data, self.format, self.w, self.h, arrayCount=self.arrayCount)
        for arrayIdx, mips in enumerate(images):
            for mipIdx, im in enumerate(mips):
                im.save(name+str(arrayIdx)+".png")


class Map1(Section):
    header = struct.Struct('>hHHH')
    fields = ['mappingType', 'startingCharacter', 'endingCharacter', 'spanCount']
    # mappingType 0: glyph = character - startingCharacter
    # mappingType 1: glyph = ((char&0xff)-0x40.5)+(((char>>8)-0x88)*0xbc)+0x2be
    # (see convertSjis. I assume useful for Kanji in Shift-JIS, which all have
    # high byte above 0x88 and low byte above 0x3f)
    # mappingType 2: glyph = spans[character - startingCharacter]
    # mappingType 3: glyph = spans[i*2 + 1] where spans[i*2] == character
    def read(self, fin, start, size):
        super().read(fin, start, size)
        self.spans = array.array('H')
        self.spans.fromfile(fin, self.spanCount*self.spans.itemsize)
        if sys.byteorder == 'little': self.spans.byteswap()
        self.spanCount = None
    
    def write(self, fout):
        self.spanCount = len(self.spans)//self.spans.itemsize
        super().write(fout)
        swapArray(self.spans).tofile(fout)
    

class Inf1(Section):
    header = struct.Struct('>hhhhhH')
    fields = ['fontType', 'ascent', 'descent', 'width', 'leading', 'defaultCharacterCode']
    # fontType 0: 1-byte (e.g. CP-1252)
    # fontType 1: 2-byte (e.g. UTF-16)
    # fontType 2: Shift-JIS


class Wid1(Section):
    header = struct.Struct('>HH')
    fields = ['minimumFontCode', 'maximumFontCode']
    def read(self, fin, start, size):
        super().read(fin, start, size)
        self.widths = array.array('B')
        self.widths.fromfile(fin, (size-self.header.size-8)//self.widths.itemsize)
        if sys.byteorder == 'little': self.widths.byteswap()
    
    def write(self, fout):
        super().write(fout)
        swapArray(self.widths).tofile(fout)


class BFont(BFile):
    sectionHandlers = {b'GLY1': Gly1, b'MAP1': Map1, b'INF1': Inf1, b'WID1': Wid1}
    
    def read(self, fin):
        super().read(fin)
        self.startingCharacter = min(chunk.startingCharacter for chunk in self.chunks if isinstance(chunk, Map1))
    

if __name__ == "__main__":
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

