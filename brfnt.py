#!/usr/bin/env python

import sys
from PIL import Image
from struct import Struct, unpack
from common import Section, BFile

formatWidths = {
 0: .5,
 1:  1,
 2:  1,
 3:  2,
 4:  2,
 5:  2,
 6:  1,
 8: .5,
 9:  1,
10:  2,
14: .5
}

def unpackRGB5A3(c):
    if (c & 0x8000) == 0x8000:
        a = 0xff
        r = (c & 0x7c00) >> 10
        r = (r << (8-5)) | (r >> (10-8))
        g = (c & 0x3e0) >> 5
        g = (g << (8-5)) | (g >> (10-8))
        b = c & 0x1f
        b = (b << (8-5)) | (b >> (10-8))
    else:
        a = (c & 0x7000) >> 12
        a = (a << (8-3)) | (a << (8-6)) | (a >> (9-8))
        r = (c & 0xf00) >> 8
        r = (r << (8-4)) | r
        g = (c & 0xf0) >> 4
        g = (g << (8-4)) | g
        b = c & 0xf
        b = (b << (8-4)) | b
    return r, g, b, a

class Tglp(Section):
    header = Struct('>4x2x2xHH2x2xHHI')
    def read(self, fin, start, size):
        self.count, self.format, self.width, self.height, offset = self.header.unpack(fin.read(0x18))
        print(self.format, self.width, self.height)
        fin.seek(offset)
        self.data = fin.read(int(self.width*self.height*self.count*formatWidths[self.format]))
        print(self.data)
    
    def export(self, fname):
        dataIdx = 0
        for i in range(self.count):
            if self.format == 0:
                # I4
                im = Image.new('L', (self.width, self.height))
                for y in range(0, self.height, 8):
                    for x in range(0, self.width, 8):
                        for dy in range(8):
                            for dx in range(0, 8, 2):
                                c = ord(self.data[dataIdx])
                                dataIdx += 1
                                if x + dx < self.width and y + dy < self.height:
                                    t = c&0xF0
                                    im.putpixel((x+dx, y+dy), t | (t >> 4))
                                    t = c&0x0F
                                    im.putpixel((x+dx+1, y+dy), (t << 4) | t)
            elif self.format == 1:
                # I8
                im = Image.new('L', (self.width, self.height))
                for y in range(0, self.height, 4):
                    for x in range(0, self.width, 8):
                        for dy in range(4):
                            for dx in range(8):
                                c = ord(self.data[dataIdx])
                                dataIdx += 1
                                if x + dx < self.width and y + dy < self.height:
                                    im.putpixel((x+dx, y+dy), c)
            elif self.format == 2:
                # IA4
                im = Image.new('LA', (self.width, self.height))
                for y in range(0, self.height, 4):
                    for x in range(0, self.width, 8):
                        for dy in range(4):
                            for dx in range(8):
                                c = ord(self.data[dataIdx])
                                dataIdx += 1
                                if x + dx < self.width and y + dy < self.height:
                                    t = c&0xF0
                                    a = c&0x0F
                                    im.putpixel((x+dx, y+dy), (t | (t >> 4),(a << 4) | a))
            elif self.format == 3:
                # IA8
                im = Image.new('LA', (self.width, self.height))
                for y in range(0, self.height, 4):
                    for x in range(0, self.width, 4):
                        for dy in range(4):
                            for dx in range(4):
                                c1, c2 = ord(self.data[dataIdx]), ord(self.data[dataIdx+1])
                                dataIdx += 2
                                if x + dx < self.width and y + dy < self.height:
                                    im.putpixel((x+dx, y+dy), (c1,c2))
            elif self.format == 5:
                # RGB5A3
                im = Image.new('RGBA', (self.width, self.height))
                for y in range(0, self.height, 4):
                    for x in range(0, self.width, 4):
                        for dy in range(4):
                            for dx in range(4):
                                c, = unpack('>H', self.data[dataIdx:dataIdx+2])
                                dataIdx += 2
                                if x + dx < self.width and y + dy < self.height:
                                    im.putpixel((x+dx, y+dy), unpackRGB5A3(c))
            im.save(fname+str(i)+'.png')

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
brfnt.tglp.export(sys.argv[1])
