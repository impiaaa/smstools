#!/usr/bin/env python

import sys, os
from struct import unpack
from texture import *

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <bti>\n"%sys.argv[0])
    exit(1)

fin = open(sys.argv[1], 'rb')

format, width, height, wrapS, wrapT, paletteFormat, paletteNumEntries, paletteOffset, minFilter, magFilter, minLod, maxLod, mipmapCount, lodBias, dataOffset = unpack('>BxHHBBxBHL4xBBBBBxHL', fin.read(32))
format = TF(format)
paletteFormat = TL(paletteFormat)

mipmapCount = max(mipmapCount, 1)

print("%dx%d, fmt=%s, mips=%d, pfmt=%s" % (width, height, format, mipmapCount, paletteFormat))

palette = None
if format in (TF.C4, TF.C8, TF.C14X2):
    fin.seek(paletteOffset)
    palette = readPaletteData(fin, paletteFormat, paletteNumEntries)

fin.seek(dataOffset)
data = readTextureData(fin, format, width, height, mipmapCount)
fin.close()

images = decodeTexturePIL(data, format, width, height, paletteFormat, palette, mipmapCount)
images[0][0].save(os.path.splitext(sys.argv[1])[0]+'.png')

fout = open(os.path.splitext(sys.argv[1])[0]+".dds", 'wb')
decodeTextureDDS(fout, data, format, width, height, paletteFormat, palette, mipmapCount)
fout.close()
