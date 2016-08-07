import sys
from PIL import Image
from struct import unpack

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

fin = open(sys.argv[1], 'rb')
i = 0
fin.seek(0,2)
endfile = fin.tell()
fin.seek(0)
while fin.tell() < endfile:
    fin.seek(0x14,1)
    height, width, format, offset = unpack('>HHII', fin.read(12))
    print format, width, height
    fin.seek(0x20,1)
    if format == 0:
        # I4
        im = Image.new('L', (width, height))
        for y in xrange(0, height, 8):
            for x in xrange(0, width, 8):
                for dy in xrange(8):
                    for dx in xrange(0, 8, 2):
                        if fin.tell() >= endfile: break
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
                        if fin.tell() >= endfile: break
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
                        if fin.tell() >= endfile: break
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
                        if fin.tell() >= endfile: break
                        c1, c2 = ord(fin.read(1)), ord(fin.read(1))
                        if x + dx < width and y + dy < height:
                            im.putpixel((x+dx, y+dy), (c1,c2))
    elif format == 4:
        # RGB565
        im = Image.new('RGB', (width, height))
        for y in xrange(0, height, 4):
            for x in xrange(0, width, 4):
                for dy in xrange(4):
                    for dx in xrange(4):
                        if fin.tell() >= endfile: break
                        rgb, = unpack('>H', fin.read(2))
                        if x + dx < width and y + dy < height:
                            di = 2*(width*(y + dy) + x + dx)
                            r = (rgb & 0xf100) >> 11
                            g = (rgb & 0x7e0) >> 5
                            b = (rgb & 0x1f)
                            im.putpixel((x+dx, y+dy), (r<<3,g<<2,b<<3))
    elif format == 5:
        # RGB5A3
        im = Image.new('RGBA', (width, height))
        for y in xrange(0, height, 4):
            for x in xrange(0, width, 4):
                for dy in xrange(4):
                    for dx in xrange(4):
                        if fin.tell() >= endfile: break
                        c, = unpack('>H', fin.read(2))
                        if x + dx < width and y + dy < height:
                            im.putpixel((x+dx, y+dy), unpackRGB5A3(c))
    elif format == 6:
        # RGBA8
        for y in xrange(0, mipheight, 4):
            for x in xrange(0, mipwidth, 4):
                for dy in xrange(4):
                    for dx in xrange(4):
                        if fin.tell() >= endfile: break
                        c = map(ord, fin.read(4))
                        if x + dx < mipwidth and y + dy < mipheight:
                            im.putpixel((x+dx, y+dy), c)
    im.save(sys.argv[1]+str(i)+'.png')
    i += 1

fin.close()
