import sys, os
from struct import unpack, pack
from texture import readTextureData, readPaletteData, decodeTextureDDS

GX_TF_I4 = 0x0
GX_TF_I8 = 0x1
GX_TF_IA4 = 0x2
GX_TF_IA8 = 0x3
GX_TF_RGB565 = 0x4
GX_TF_RGB5A3 = 0x5
GX_TF_RGBA8 = 0x6
GX_TF_C4 = 0x8
GX_TF_C8 = 0x9
GX_TF_C14X2 = 0xA
GX_TF_CMPR = 0xE # S3TC/DXT

GX_TL_IA8 = 0x0
GX_TL_RGB565 = 0x1
GX_TL_RGB5A3 = 0x2

IMAGE_FORMAT_RGBA8888 = 0,
IMAGE_FORMAT_ABGR8888 = 1
IMAGE_FORMAT_RGB888 = 2
IMAGE_FORMAT_BGR888 = 3
IMAGE_FORMAT_RGB565 = 4
IMAGE_FORMAT_I8 = 5
IMAGE_FORMAT_IA88 = 6
IMAGE_FORMAT_P8 = 7
IMAGE_FORMAT_A8 = 8
IMAGE_FORMAT_RGB888_BLUESCREEN = 9
IMAGE_FORMAT_BGR888_BLUESCREEN = 10
IMAGE_FORMAT_ARGB8888 = 11
IMAGE_FORMAT_BGRA8888 = 12
IMAGE_FORMAT_DXT1 = 13
IMAGE_FORMAT_DXT3 = 14
IMAGE_FORMAT_DXT5 = 15
IMAGE_FORMAT_BGRX8888 = 16
IMAGE_FORMAT_BGR565 = 17
IMAGE_FORMAT_BGRX5551 = 18
IMAGE_FORMAT_BGRA4444 = 19
IMAGE_FORMAT_DXT1_ONEBITALPHA = 20
IMAGE_FORMAT_BGRA5551 = 21
IMAGE_FORMAT_UV88 = 22
IMAGE_FORMAT_UVWQ8888 = 23
IMAGE_FORMAT_RGBA16161616F = 24
IMAGE_FORMAT_RGBA16161616 = 25
IMAGE_FORMAT_UVLX8888 = 26

BMD_TO_VTF_FMT = {
GX_TF_I8: IMAGE_FORMAT_I8,
GX_TF_IA8: IMAGE_FORMAT_IA88,
GX_TF_RGB565: IMAGE_FORMAT_RGB565,
GX_TF_CMPR: IMAGE_FORMAT_DXT1,
GX_TF_RGBA8: IMAGE_FORMAT_RGBA8888
}
formatWidths = {
 0: .5,
 1:  1,
 2:  1,
 3:  2,
 4:  2,
 5:  1,
 6:  1,
 8: .5,
 9:  1,
10:  2,
14: .5
}
vtfFormatWidths = {
 8: 1,
 1: 4,
11: 4,
17: 2,
 3: 3,
10: 3,
19: 2,
21: 2,
12: 4,
18: 2,
16: 4,
13: .5,
20: .5,
14: 1,
15: 1,
 5: 1,
 6: 2,
 7: 1,
 4: 2,
 2: 3,
 9: 3,
25: 8,
24: 8,
 0: 4,
22: 2,
26: 4,
23: 4
}

def s3tc1ReverseByte(b):
    b1 = b & 0x3
    b2 = b & 0xc
    b3 = b & 0x30
    b4 = b & 0xc0
    return (b1 << 6) | (b2 << 2) | (b3 >> 2) | (b4 >> 6)

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

format, width, height, wrapS, wrapT, paletteFormat, paletteNumEntries, paletteOffset, minFilter, magFilter, mipmapCount, dataOffset = unpack('>BxHHBBxBHL4xBB2xBx2xL', fin.read(32))

mipmapCount = max(mipmapCount, 1)

print "%dx%d, fmt=%d, mips=%d, pfmt=%d" % (width, height, format, mipmapCount, paletteFormat)

if width > height:
    lowResImageWidth = min(16, width)
    lowResImageHeight = (height*lowResImageWidth)/width
else:
    lowResImageHeight = min(16, height)
    lowResImageWidth = (width*lowResImageHeight)/height
lowResImageSize = (lowResImageWidth*lowResImageHeight)/2

if format in BMD_TO_VTF_FMT:
    vtfFormat = BMD_TO_VTF_FMT[format]
elif format == GX_TF_I4:
    vtfFormat = IMAGE_FORMAT_I8
elif format == GX_TF_IA4:
    vtfFormat = IMAGE_FORMAT_IA88
elif format == GX_TF_RGB5A3:
    vtfFormat = IMAGE_FORMAT_RGBA8888
elif format in (GX_TF_C4, GX_TF_C8, GX_TF_C14X2):
    if paletteFormat == 0:
        # IA8
        vtfFormat = 6
    elif paletteFormat == 1:
	    # RGB565
	    vtfFormat = 4
    elif paletteFormat == 2:
	    # RGB5A3
	    vtfFormat = 0
else:
    raise Exception("Unknown format 0x%x"%format)

flags = 0
if wrapS == 0: flags |= 0x04
if wrapT == 0: flags |= 0x08
if magFilter == 0: flags |= 0x01

palette = None
if format in (8, 9, 10):
    # read palette
    fin.seek(paletteOffset)
    palette = readPaletteData(fin, paletteFormat, paletteNumEntries)
    if 0:
        palette = [None]*paletteNumEntries
        for i in xrange(paletteNumEntries):
            if paletteFormat == 2:
                palette[i] = unpackRGB5A3(unpack('>H', fin.read(2))[0])
            else:
                palette[i] = unpack('>H', fin.read(2))[0]

fin.seek(dataOffset)
data = readTextureData(fin, format, width, height, mipmapCount)
fin.close()
fout = open(os.path.splitext(sys.argv[1])[0]+'.vtf', 'wb')
decodeTextureDDS(fout, data, format, width, height, paletteFormat, palette, mipmapCount)
fout.close()
exit()

mipData = [None]*mipmapCount
mipwidth = width
mipheight = height
lowResIndex = -1

for mip in xrange(mipmapCount):
    if format == 13 and mipwidth == lowResImageWidth and mipheight == lowResImageHeight:
        lowResIndex = mip
    vtfImageSize = int((mipwidth*mipheight)*vtfFormatWidths[vtfFormat])
    imageSize = int((mipwidth*mipheight)*formatWidths[format])
    dest = [255]*vtfImageSize
    if format == 0:
        # I4
        for y in xrange(0, mipheight, 8):
            for x in xrange(0, mipwidth, 8):
                for dy in xrange(8):
                    for dx in xrange(0, 8, 2):
                        c = ord(fin.read(1))
                        if x + dx < mipwidth and y + dy < mipheight:
                            #http://www.mindcontrol.org/~hplus/graphics/expand-bits.html
                            t = c & 0xf0
                            dest[mipwidth*(y + dy) + x + dx] = t | (t >> 4)
                            t = c & 0xf
                            if x + dx + 1 < mipwidth:
                                dest[mipwidth*(y + dy) + x + dx + 1] = (t << 4) | t
    elif format == 1:
        # I8
        for y in xrange(0, mipheight, 4):
            for x in xrange(0, mipwidth, 8):
                for dy in xrange(4):
                    for dx in xrange(8):
                        c = ord(fin.read(1))
                        if x + dx < mipwidth and y + dy < mipheight:
                            dest[mipwidth*(y + dy) + x + dx] = c
    elif format == 2:
        # IA4
        for y in xrange(0, mipheight, 4):
            for x in xrange(0, mipwidth, 8):
                for dy in xrange(4):
                    for dx in xrange(8):
                        c = ord(fin.read(1))
                        if x + dx < mipwidth and y + dy < mipheight:
                            lum = c & 0xf
                            lum |= lum << 4
                            alpha = c & 0xf0
                            alpha |= (alpha >> 4)
                            dest[2*(mipwidth*(y + dy) + x + dx)] = lum
                            dest[2*(mipwidth*(y + dy) + x + dx) + 1] = alpha
    elif format == 3:
        # IA8
        for y in xrange(0, mipheight, 4):
            for x in xrange(0, mipwidth, 4):
                for dy in xrange(4):
                    for dx in xrange(4):
                        c1, c2 = ord(fin.read(1)), ord(fin.read(1))
                        if x + dx < mipwidth and y + dy < mipheight:
                            di = 2*(mipwidth*(y + dy) + x + dx)
                            dest[di + 1] = c1
                            dest[di + 0] = c2
    elif format == 4:
        # RGB565
        for y in xrange(0, mipheight, 4):
            for x in xrange(0, mipwidth, 4):
                for dy in xrange(4):
                    for dx in xrange(4):
                        rgb, = unpack('>H', fin.read(2))
                        if x + dx < mipwidth and y + dy < mipheight:
                            di = 2*(mipwidth*(y + dy) + x + dx)
                            r = (rgb & 0xf100) >> 11
                            g = (rgb & 0x7e0) >> 5
                            b = (rgb & 0x1f)
                            bgr = (b << 11) | (g << 5) | r
                            dest[di + 0] = bgr&0xff
                            dest[di + 1] = (bgr&0xff00)>>8
    elif format == 5:
        # RGB5A3
        for y in xrange(0, mipheight, 4):
            for x in xrange(0, mipwidth, 4):
                for dy in xrange(4):
                    for dx in xrange(4):
                        c, = unpack('>H', fin.read(2))
                        if x + dx < mipwidth and y + dy < mipheight:
                            r, g, b, a = unpackRGB5A3(c)
                            dest[4*(mipwidth*(y + dy) + x + dx)] = r
                            dest[4*(mipwidth*(y + dy) + x + dx) + 1] = g
                            dest[4*(mipwidth*(y + dy) + x + dx) + 2] = b
                            dest[4*(mipwidth*(y + dy) + x + dx) + 3] = a
    elif format == 6:
        # RGBA8
        for y in xrange(0, mipheight, 4):
            for x in xrange(0, mipwidth, 4):
                for dy in xrange(4):
                    for dx in xrange(4):
                        c = ord(fin.read(1))
                        if x + dx < mipwidth and y + dy < mipheight:
                            dest[mipwidth*(y + dy) + x + dx] = c
    elif format == 8:
        # C4
        for y in xrange(0, mipheight, 8):
            for x in xrange(0, mipwidth, 8):
                for dy in xrange(8):
                    for dx in xrange(0, 8, 2):
                        c = ord(fin.read(1))
                        if x + dx < mipwidth and y + dy < mipheight:
                            p1, p2 = palette[(c & 0xf0) >> 4], palette[c & 0x0f]
                            if paletteFormat == 2:
                                dest[4*(mipwidth*(y + dy) + x + dx)    ] = p1[0]
                                dest[4*(mipwidth*(y + dy) + x + dx) + 1] = p1[1]
                                dest[4*(mipwidth*(y + dy) + x + dx) + 2] = p1[2]
                                dest[4*(mipwidth*(y + dy) + x + dx) + 3] = p1[3]
                                dest[4*(mipwidth*(y + dy) + x + dx) + 4] = p2[0]
                                dest[4*(mipwidth*(y + dy) + x + dx) + 5] = p2[1]
                                dest[4*(mipwidth*(y + dy) + x + dx) + 6] = p2[2]
                                dest[4*(mipwidth*(y + dy) + x + dx) + 7] = p2[3]
                            else:
                                dest[2*(mipwidth*(y + dy) + x + dx)    ] = (p1 & 0x00FF)
                                dest[2*(mipwidth*(y + dy) + x + dx) + 1] = (p1 & 0xFF00) >> 8
                                dest[2*(mipwidth*(y + dy) + x + dx) + 2] = (p2 & 0x00FF)
                                dest[2*(mipwidth*(y + dy) + x + dx) + 3] = (p2 & 0xFF00) >> 8
    elif format == 9:
        # C8
        for y in xrange(0, mipheight, 4):
            for x in xrange(0, mipwidth, 8):
                for dy in xrange(4):
                    for dx in xrange(0, 8, 1):
                        c = ord(fin.read(1))
                        if x + dx < mipwidth and y + dy < mipheight:
                            p = palette[c]
                            if paletteFormat == 2:
                                dest[4*(mipwidth*(y + dy) + x + dx)    ] = p[0]
                                dest[4*(mipwidth*(y + dy) + x + dx) + 1] = p[1]
                                dest[4*(mipwidth*(y + dy) + x + dx) + 2] = p[2]
                                dest[4*(mipwidth*(y + dy) + x + dx) + 3] = p[3]
                            else:
                                dest[2*(mipwidth*(y + dy) + x + dx)    ] = (p & 0x00FF)
                                dest[2*(mipwidth*(y + dy) + x + dx) + 1] = (p & 0xFF00) >> 8
	#GX_TF_C14X2  = 0xA,
    elif format == 14:
        # CMPR
        for y in xrange(0, mipheight/4, 2):
            for x in xrange(0, mipwidth/4, 2):
                for dy in xrange(2):
                    for dx in xrange(2):
                        for k in xrange(8):
                            c = ord(fin.read(1))
                            if x + dx < mipwidth and y + dy < mipheight:
                                dest[8*((y + dy)*mipwidth/4 + x + dx) + k] = c
        for k in xrange(0, mipwidth*mipheight/2, 8):
            a = dest[k]
            dest[k] = dest[k+1]
            dest[k+1] = a
            a = dest[k+2]
            dest[k+2] = dest[k+3]
            dest[k+3] = a
            dest[k+4] = s3tc1ReverseByte(dest[k+4])
            dest[k+5] = s3tc1ReverseByte(dest[k+5])
            dest[k+6] = s3tc1ReverseByte(dest[k+6])
            dest[k+7] = s3tc1ReverseByte(dest[k+7])
    mipData[mip] = dest
    mipwidth /= 2
    mipheight /= 2
mipData.reverse()
lowResFormat = -1 if lowResIndex == -1 else 13
fout = open(os.path.splitext(sys.argv[1])[0]+'.vtf', 'wb')
fout.write("VTF\0")
fout.write(pack('<LLLHHLHH4x3f4xfLBlBBH', 7, 2, 80, width, height, flags, 1, 0, 1.0, 1.0, 1.0, 1.0, vtfFormat, mipmapCount, lowResFormat, lowResImageWidth, lowResImageHeight, 1))
if lowResIndex != -1:
    for c in mipData[0]:
        fout.write(chr(c))
# ???
fout.write('\0\0\0')
fout.write('\0\0\0\0\0\0\0\0\0\0\0\0')
for dest in mipData:
    for c in dest:
        fout.write(chr(c))
fout.close()
