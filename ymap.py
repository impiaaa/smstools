#!/usr/bin/env python

from struct import unpack
import sys, os
from texture import TexFmt, readTextureData, decodeTexturePIL

if len(sys.argv) != 2:
	sys.stderr.write("Usage: %s ymap.ymp\n"%sys.argv[0])
	exit(1)

fin = open(sys.argv[1], 'rb')

nRegions, zero1, dataOffset = unpack('>HHI', fin.read(8))

assert dataOffset == 8
assert zero1 == 0

fin.seek(dataOffset)

print("%d regions"%nRegions)

for i in range(nRegions):
    pollutionEffect, unk1, pollutionLayerType = unpack('>HHI', fin.read(8))

    #assert sz == 0x20000, hex(fin.tell())
    #assert zero2 == 0, hex(fin.tell())

    yOffset, texToWorldSize, xMin, zMin, xMax, zMax = unpack('>ffffff', fin.read(24))

    widthPow, heightPow, unk3, dataOffset = unpack('>HHII', fin.read(12))
    width = 1<<widthPow
    height = 1<<heightPow

    print("(%f,%f),(%f,%f),(%f,%f) 0x%X"%(yOffset, texToWorldSize, xMin, zMin, xMax, zMax, unk3))
    
    lastRegionHeader = fin.tell()
    
    fin.seek(dataOffset)
    data = readTextureData(fin, TexFmt.I8, width, height)
    
    images = decodeTexturePIL(data, TexFmt.I8, width, height, 0, None)
    images[0][0].save(os.path.splitext(sys.argv[1])[0]+"-%d-%X.png"%(i, unk3))
    
    fin.seek(lastRegionHeader)

fin.close()
