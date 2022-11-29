#!/usr/bin/env python

import sys, os
from struct import Struct, unpack
from texture import *
from common import *

class Image(ReadableStruct):
    header = Struct('>BBHHBBBBHIBBBBBBBBBxHI')
    fields = [
        ("format", TexFmt),
        "transparency",
        "width",
        "height",
        "wrapS",
        "wrapT",
        ("usePalette", bool),
        ("paletteFormat", TlutFmt),
        "paletteNumEntries",
        "paletteOffset",
        ("isMipmap", bool),
        ("edgeLod", bool),
        ("biasClamp", bool),
        "maxAniso",
        "minFilter",
        "magFilter",
        "minLod",
        "maxLod",
        "mipmapCount",
        "lodBias",
        "dataOffset"
    ]
    def read(self, fin, start=None, textureHeaderOffset=None, texIndex=None):
        super().read(fin)
        self.mipmapCount = max(self.mipmapCount, 1)
        if self.format in (TexFmt.C4, TexFmt.C8, TexFmt.C14X2):
            self.hasAlpha = self.paletteFormat in (TlutFmt.IA8, TlutFmt.RGB5A3)
        else:
            self.hasAlpha = self.format in (TexFmt.IA4, TexFmt.IA8, TexFmt.RGB5A3, TexFmt.RGBA8)
        if start is not None:
            nextHeader = fin.tell()
            
            self.fullDataOffset = start+textureHeaderOffset+self.dataOffset+0x20*texIndex
            fin.seek(self.fullDataOffset)
            self.data = readTextureData(fin, self.format, self.width, self.height, self.mipmapCount)
            
            if self.format in (TexFmt.C4, TexFmt.C8, TexFmt.C14X2):
                self.fullPaletteOffset = start+textureHeaderOffset+self.paletteOffset+0x20*texIndex
                fin.seek(self.fullPaletteOffset)
                self.palette = readPaletteData(fin, self.paletteFormat, self.paletteNumEntries)
            else:
                self.palette = None
            
            fin.seek(nextHeader)
    
    def write(self, fout):
        self.dataOffset = fout.tell()+self.header.size
        self.paletteOffset = self.dataOffset + len(self.data)*self.data.itemsize
        super().write(fout)
        swapArray(self.data).tofile(fout)
        if self.palette is not None: swapArray(self.palette).tofile(fout)
    
    def getDataName(self, bmd):
        s = bmd.name+"@"+hex(self.fullDataOffset)
        if self.format in (TexFmt.C4, TexFmt.C8, TexFmt.C14X2):
            s += "p"+hex(self.fullPaletteOffset)
        return s

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: %s <bti>\n"%sys.argv[0])
        exit(1)

    img = Image()
    fin = open(sys.argv[1], 'rb')
    img.read(fin, 0, 0, 0)
    fin.close()
    print("%dx%d, fmt=%s, mips=%d, pfmt=%s" % (img.width, img.height, img.format, img.mipmapCount, img.paletteFormat))

    #images = decodeTexturePIL(data, format, width, height, paletteFormat, palette, mipmapCount)
    #images[0][0].save(os.path.splitext(sys.argv[1])[0]+'.png')

    fout = open(os.path.splitext(sys.argv[1])[0]+".dds", 'wb')
    decodeTextureDDS(fout, img.data, img.format, img.width, img.height, img.paletteFormat, img.palette, img.mipmapCount)
    fout.close()

    #fout = open(os.path.splitext(sys.argv[1])[0]+".ktx", 'wb')
    #decodeTextureKTX(fout, data, format, width, height, paletteFormat, palette, mipmapCount)
    #fout.close()

