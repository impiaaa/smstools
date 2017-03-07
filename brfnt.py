#!/usr/bin/env python

import sys
from PIL import Image
from struct import Struct, unpack
from common import Section, BFile
from texture import readTextureData, decodeTexturePIL

class Tglp(Section):
    header = Struct('>4x2x2xHH2x2xHHI')
    def read(self, fin, start, size):
        self.count, self.format, self.width, self.height, offset = self.header.unpack(fin.read(0x18))
        print(self.format, self.width, self.height)
        fin.seek(offset)
        self.data = readTextureData(fin, self.format, self.width, self.height, arrayCount=self.count)
    
    def export(self, fname):
        images = decodeTexturePIL(self.data, self.format, self.width, self.height, arrayCount=self.count)
        for arrayIdx, mips in enumerate(images):
            mips[0].save(fname+str(arrayIdx)+'.png')

class Cwdh(Section):
    header = Struct('>I4x3x')
    def read(self, fin, start, size):
        count, = self.header.unpack(fin.read(11))

class BRFont(BFile):
    header = Struct('>8sL2xH')
    sectionHandlers = {b'TGLP': Tglp, b'CWDH': Cwdh}
    def readHeader(self, fin):
        self.signature, self.fileLength, self.chunkCount = self.header.unpack(fin.read(0x10))

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <brfnt>\n"%sys.argv[0])
    exit(1)

fin = open(sys.argv[1], 'rb')
brfnt = BRFont()
brfnt.read(fin)
fin.close()
brfnt.tglp.export(os.path.splitext(sys.argv[1])[0])
