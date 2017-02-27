#!/usr/bin/env python

import sys, struct
from PIL import Image
from common import BFile, Section

if sys.version_info[0] <= 2:
    range = xrange

class Gly1(Section):
    header = struct.Struct('>H4xHH')
    
    def read(self, fin, start, size):
        fin.seek(0xC, 1)
        self.format, self.w, self.h = self.header.unpack(fin.read(0xa))
        #self.h = (size-0x18)/w
        #if format == 0: self.h *= 2
        fin.seek(2, 1)
        self.data = fin.read(size-0x18)
    
    def export(self, name):
        dataidx = 0
        sliceno = 0
        while dataidx < len(self.data):
            if self.format == 0:
                im = Image.new('L', (w, h))
                for y in range(0, h, 8):
                    for x in range(0, w, 8):
                        for dy in range(8):
                            for dx in range(0, 8, 2):
                                c = ord(self.data[dataidx])
                                dataidx += 1
                                if x + dx < w and y + dy < h:
                                    t = c&0xF0
                                    im.putpixel((x+dx, y+dy), t | (t >> 4))
                                    t = c&0x0F
                                    im.putpixel((x+dx+1, y+dy), (t << 4) | t)
            elif self.format == 2:
                im = Image.new('RGBA', (w, h))
                for y in xrange(0, h, 4):
                    for x in xrange(0, w, 8):
                        for dy in xrange(4):
                            for dx in xrange(0, 8):
                                c = ord(self.data[dataidx])
                                dataidx += 1
                                if x + dx < w and y + dy < h:
                                    t = c&0xF0
                                    #im.putpixel((x+dx, y+dy), (t | (t >> 4),)*3)
                                    a = c&0x0F
                                    im.putpixel((x+dx, y+dy), (t | (t >> 4),)*3+((a << 4) | a,))
            im.save(name+str(sliceno)+'.png')
            sliceno += 1

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
