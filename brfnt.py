#!/usr/bin/env python

import sys, os
from struct import Struct
from common import Section, BFile
from texture import readTextureData, decodeTexturePIL

import string

class Finf(Section):
    def read(self, fin, start, size):
        s = fin.read(size-8)
        print(' '.join(['%02X'%c for c in s]))
        s = map(chr, s)
        print('  '.join([c if c.isprintable() else '.' for c in s]))

class Tglp(Section):
    header = Struct('>4x2x2xHH2x2xHHI')
    def read(self, fin, start, size):
        self.count, self.format, self.width, self.height, offset = self.header.unpack(fin.read(0x18))
        print("Fmt:", self.format, "Sz:", self.width, self.height)
        fin.seek(offset)
        self.data = readTextureData(fin, self.format, self.width, self.height, arrayCount=self.count)
    
    def export(self, fname):
        images = decodeTexturePIL(self.data, self.format, self.width, self.height, arrayCount=self.count)
        for arrayIdx, mips in enumerate(images):
            mips[0].save(fname+"-"+str(arrayIdx)+".png")

class Cwdh(Section):
    header = Struct('>I3xHH')
    def read(self, fin, start, size):
        count, unk1, unk2 = self.header.unpack(fin.read(11))
        piece = Struct('3b')
        for i in range(count):
            print(*piece.unpack(fin.read(3)))

class Cmap(Section):
    header = Struct('>HHHII')
    def read(self, fin, start, size):
        self.rangeStart, self.rangeEnd, unk1, unk2, glyphCount = self.header.unpack(fin.read(14))
        self.codepointToGlyph = {}
        if unk1 == 0:
            # TODO
            for i in range(self.rangeStart, self.rangeEnd+1):
                self.codepointToGlyph[i] = i
        elif unk1 == 1:
            tableEntry = Struct('>H')
            for codepoint in range(self.rangeStart, self.rangeEnd):
                glyph, = tableEntry.unpack(fin.read(2))
                if glyph != 0xFFFF:
                    self.codepointToGlyph[codepoint] = glyph
        elif unk1 == 2:
            tableEntry = Struct('>HH')
            for i in range(glyphCount):
                codepoint, glyph = tableEntry.unpack(fin.read(4))
                self.codepointToGlyph[codepoint] = glyph
        else:
            print("Unknown CMAP format:", hex(self.rangeStart), hex(self.rangeEnd), hex(unk1), hex(unk2))
            return
        print("Map", len(self.codepointToGlyph), "glyphs from", hex(self.rangeStart), "to", hex(self.rangeEnd))

class BRFont(BFile):
    header = Struct('>8sLHH')
    sectionHandlers = {b'TGLP': Tglp, b'CWDH': Cwdh, b'CMAP': Cmap, b'FINF': Finf}
    def readHeader(self, fin):
        self.signature, self.fileLength, unk, self.chunkCount = self.header.unpack(fin.read(0x10))

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <brfnt>\n"%sys.argv[0])
    exit(1)

fin = open(sys.argv[1], 'rb')
brfnt = BRFont()
brfnt.read(fin)
fin.close()
brfnt.tglp.export(os.path.splitext(sys.argv[1])[0])
