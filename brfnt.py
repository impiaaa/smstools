import sys
from PIL import Image
from struct import Struct
from common import Section, BFile

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
        print self.format, self.width, self.height
        fin.seek(offset)
        self.data = fin.read(int(self.width*self.height*self.count*formatWidths[format]))
fin = open(sys.argv[1], 'rb')
signature, fileLength, chunkCount = unpack('>8sL2xH', fin.read(0x10))

for chunkNumber in xrange(chunkCount):
    chunkstart = fin.tell()
    try: chunk, chunksize = unpack('>4sL', fin.read(8))
    except struct.error:
        warn("File too small for chunk")
        continue
    print hex(fin.tell()), chunk, hex(chunksize)
    if chunk == "TGLP":
        
        for i in range(count):
            if format == 0:
                # I4
                im = Image.new('L', (width, height))
                for y in xrange(0, height, 8):
                    for x in xrange(0, width, 8):
                        for dy in xrange(8):
                            for dx in xrange(0, 8, 2):
                                c = ord(fin.read(1))
                                if x + dx < width and y + dy < height:
                                    t = c&0xF0
                                    im.putpixel((x+dx, y+dy), t | (t >> 4))
                                    t = c&0x0F
                                    im.putpixel((x+dx+1, y+dy), (t << 4) | t)
            elif format == 1:
                # I8
                im = Image.new('L', (width, height))
                for y in xrange(0, height, 4):
                    for x in xrange(0, width, 8):
                        for dy in xrange(4):
                            for dx in xrange(8):
                                c = ord(fin.read(1))
                                if x + dx < width and y + dy < height:
                                    im.putpixel((x+dx, y+dy), c)
            elif format == 2:
                # IA4
                im = Image.new('LA', (width, height))
                for y in xrange(0, height, 4):
                    for x in xrange(0, width, 8):
                        for dy in xrange(4):
                            for dx in xrange(8):
                                c = ord(fin.read(1))
                                if x + dx < width and y + dy < height:
                                    t = c&0xF0
                                    a = c&0x0F
                                    im.putpixel((x+dx, y+dy), (t | (t >> 4),(a << 4) | a))
            elif format == 3:
                # IA8
                im = Image.new('LA', (width, height))
                for y in xrange(0, height, 4):
                    for x in xrange(0, width, 4):
                        for dy in xrange(4):
                            for dx in xrange(4):
                                c1, c2 = ord(fin.read(1)), ord(fin.read(1))
                                if x + dx < width and y + dy < height:
                                    im.putpixel((x+dx, y+dy), (c1,c2))
            elif format == 5:
                # RGB5A3
                im = Image.new('RGBA', (width, height))
                for y in xrange(0, height, 4):
                    for x in xrange(0, width, 4):
                        for dy in xrange(4):
                            for dx in xrange(4):
                                c, = unpack('>H', fin.read(2))
                                if x + dx < width and y + dy < height:
                                    im.putpixel((x+dx, y+dy), unpackRGB5A3(c))
            im.save(sys.argv[1]+str(i)+'.png')
    elif chunk == "CWDH":
        count, = unpack('>I4x3x', fin.read(11))
    fin.seek(((chunkstart+chunksize+3)/4)*4)
