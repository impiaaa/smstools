#!/usr/bin/env python

from struct import unpack
import sys, os
from texture import GX_TF_I8, readTextureData, decodeTexturePIL

if len(sys.argv) != 2:
	sys.stderr.write("Usage: %s ymap.ymp\n"%sys.argv[0])
	exit(1)

fin = open(sys.argv[1], 'rb')

nRegions, zero1, eight = unpack('>HHI', fin.read(8))

if eight != 8:
	sys.stderr.write("Not a YMP (8=%d)\n"%eight)
	exit(1)

assert zero1 == 0, hex(fin.tell())

print("%d regions"%nRegions)

for i in range(nRegions):
    sz, zero2 = unpack('>II', fin.read(8))

    #assert sz == 0x20000, hex(fin.tell())
    #assert zero2 == 0, hex(fin.tell())

    x1, y1, z1, x2, y2, z2 = unpack('>ffffff', fin.read(24))

    widthPow, heightPow, unk3, dataOffset = unpack('>HHII', fin.read(12))
    width = 1<<widthPow
    height = 1<<heightPow

    print("(%f,%f,%f,%f,%f,%f) 0x%X"%(x1,y1,z1,x2,y2,z2,unk3))
    
    lastRegionHeader = fin.tell()
    
    fin.seek(dataOffset)
    data = readTextureData(fin, GX_TF_I8, width, height)
    
    images = decodeTexturePIL(data, GX_TF_I8, width, height, 0, None)
    images[0][0].save(os.path.splitext(sys.argv[1])[0]+"-%d-%X.png"%(i, unk3))
    
    fin.seek(lastRegionHeader)

fin.close()
