#!/usr/bin/env python2

from struct import unpack
import sys, os
try:
	from PIL import Image
except ImportError:
	sys.stderr.write("Requires PIL or Pillow\n")
	raise

if len(sys.argv) != 2:
	sys.stderr.write("Usage: %s ymap.ymp\n"%sys.argv[0])
	exit(1)

fin = open(sys.argv[1], 'rb')

nRegions, zero1, eight = unpack('>HHI', fin.read(8))

assert eight == 8, "Not a YMP (8=%d)"%eight
assert zero1 == 0, hex(fin.tell())

print nRegions, "regions"

for i in xrange(nRegions):
    sz, zero2 = unpack('>II', fin.read(8))

    #assert sz == 0x20000, hex(fin.tell())
    #assert zero2 == 0, hex(fin.tell())

    x1, y1, z1, x2, y2, z2 = unpack('>ffffff', fin.read(24))

    widthPow, heightPow, unk3, dataOffset = unpack('>HHII', fin.read(12))
    width = 1<<widthPow
    height = 1<<heightPow

    print "(%f,%f,%f,%f,%f,%f) 0x%X"%(x1,y1,z1,x2,y2,z2,unk3)
    
    lastRegionHeader = fin.tell()
    
    fin.seek(dataOffset)
    im = Image.new('L', (width, height))
    for y in xrange(0, height, 4):
        for x in xrange(0, width, 8):
            for dy in xrange(4):
                for dx in xrange(8):
                    c = ord(fin.read(1))
                    if x + dx < width and y + dy < height:
                        im.putpixel((x+dx, y+dy), c)
    im.save(os.path.splitext(sys.argv[1])[0]+"-%d-%X.png"%(i, unk3))
    
    fin.seek(lastRegionHeader)

fin.close()
