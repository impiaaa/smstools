# Common functions for reading, decoding, reformatting, and exporting block-based GameCube TEV/Flipper/GX texture data.

import struct
from array import array
import sys
from enum import Enum, Flag

class TexFmt(Enum):
    I4 = 0x0
    I8 = 0x1
    IA4 = 0x2
    IA8 = 0x3
    RGB565 = 0x4
    RGB5A3 = 0x5
    RGBA8 = 0x6
    C4 = 0x8
    C8 = 0x9
    C14X2 = 0xA
    CMPR = 0xE # S3TC/DXT

class TlutFmt(Enum):
    IA8 = 0x0
    RGB565 = 0x1
    RGB5A3 = 0x2

formatBytesPerPixel = {
TexFmt.I4:   0.5,
TexFmt.I8:     1,
TexFmt.IA4:    1,
TexFmt.IA8:    2,
TexFmt.RGB565: 2,
TexFmt.RGB5A3: 2,
TexFmt.RGBA8:  4,
TexFmt.C4:   0.5,
TexFmt.C8:     1,
TexFmt.C14X2:  2,
TexFmt.CMPR: 0.5
}

formatBlockWidth = {
TexFmt.I4:     8,
TexFmt.I8:     8,
TexFmt.IA4:    8,
TexFmt.IA8:    4,
TexFmt.RGB565: 4,
TexFmt.RGB5A3: 4,
TexFmt.RGBA8:  4,
TexFmt.C4:     8,
TexFmt.C8:     8,
TexFmt.C14X2:  4,
TexFmt.CMPR:   8
}

formatBlockHeight = {
TexFmt.I4:     8,
TexFmt.I8:     4,
TexFmt.IA4:    4,
TexFmt.IA8:    4,
TexFmt.RGB565: 4,
TexFmt.RGB5A3: 4,
TexFmt.RGBA8:  4,
TexFmt.C4:     8,
TexFmt.C8:     4,
TexFmt.C14X2:  4,
TexFmt.CMPR:   8
}

formatArrayTypes = {
TexFmt.I4:     'B',
TexFmt.I8:     'B',
TexFmt.IA4:    'B',
TexFmt.IA8:    'H',
TexFmt.RGB565: 'H',
TexFmt.RGB5A3: 'H',
TexFmt.RGBA8:  'H',
TexFmt.C4:     'B',
TexFmt.C8:     'B',
TexFmt.C14X2:  'H',
TexFmt.CMPR:   'B'
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

def rgb565toColor(rgb):
    r = (rgb & 0xf800) >> 11
    g = (rgb & 0x7e0) >> 5
    b = (rgb & 0x1f)
    #http://www.mindcontrol.org/~hplus/graphics/expand-bits.html
    r = (r << 3) | (r >> 2)
    g = (g << 2) | (g >> 4)
    b = (b << 3) | (b >> 2)
    return r,g,b

def fixS3TC1Block(data):
    return array(data.typecode, [
        data[1],
        data[0],
        data[3],
        data[2],
        s3tc1ReverseByte(data[4]),
        s3tc1ReverseByte(data[5]),
        s3tc1ReverseByte(data[6]),
        s3tc1ReverseByte(data[7])
    ])

# Decode a block (format-dependent size) of texture into pixels
def decodeBlock(format, data, dataidx, width, height, xoff, yoff, putpixel, palette=None):
    if format == TexFmt.I4:
        for y in range(yoff, yoff+8):
            for x in range(xoff, xoff+8, 2):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    t = c&0xF0
                    putpixel(x, y, t | (t >> 4))
                    t = c&0x0F
                    putpixel(x+1, y, (t << 4) | t)
    
    elif format == TexFmt.I8:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+8):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, c)
    
    elif format == TexFmt.IA4:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+8):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    l = c&0x0F
                    a = c&0xF0
                    putpixel(x, y, ((l << 4) | l,a | (a >> 4)))
    
    elif format == TexFmt.IA8:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, (c&0xFF, c>>8))
    
    elif format == TexFmt.RGB565:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, (rgb565toColor(c)))
    
    elif format == TexFmt.RGB5A3:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, unpackRGB5A3(c))
    
    elif format == TexFmt.RGBA8:
        for iy in range(4):
            for x in range(4):
                r = (data[dataidx   ] & 0x00FF)
                g = (data[dataidx+16] & 0xFF00)>>8
                b = (data[dataidx+16] & 0x00FF)
                a = (data[dataidx   ] & 0xFF00)>>8
                putpixel(xoff+x, yoff+iy, (r, g, b, a))
                dataidx += 1
        dataidx += 16
    
    elif format == TexFmt.C4:
        for y in range(yoff, yoff+8):
            for x in range(xoff, xoff+8, 2):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, palette[(c & 0xf0) >> 4])
                    putpixel(x+1, y, palette[c & 0x0f])
    
    elif format == TexFmt.C8:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+8):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, palette[c])
    
    elif format == TexFmt.C14X2:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, palette[c&0x3FFF])
    
    elif format == TexFmt.CMPR:
        for y in range(yoff, yoff+8, 4):
            for x in range(xoff, xoff+8, 4):
                if dataidx >= len(data): break
                c = data[dataidx:dataidx+8]
                dataidx += 8
                color0, color1, pixels = struct.unpack('HHI', bytes(fixS3TC1Block(c)))
                colors = [rgb565toColor(color0)+(255,),
                          rgb565toColor(color1)+(255,)]
                if color0 > color1:
                    colors += [tuple((colors[0][j] * 5 + colors[1][j] * 3) >> 3 for j in range(3))+(255,)]
                    colors += [tuple((colors[1][j] * 5 + colors[0][j] * 3) >> 3 for j in range(3))+(255,)]
                else:
                    colors += [tuple((colors[0][j] + colors[1][j]) >> 1 for j in range(3))+(255,)]
                    colors += [tuple((colors[0][j] + colors[1][j]) >> 1 for j in range(3))+(0,)]
                for j in range(16):
                    pixel = colors[(pixels>>(j*2))&3]
                    putpixel(x+(j&3), y+(j>>2), pixel)
    else:
        raise ValueError("Unsupported format %d"%format)
    return dataidx

# Just transform the pixel data from blocked to linear, so we can put it in a PC format
def deblock(format, data, width, height):
    dest = array(data.typecode, [0]*len(data))
    dataidx = 0
    for y in range(0, height, formatBlockHeight[format]):
        for x in range(0, width, formatBlockWidth[format]):
            if format == TexFmt.CMPR:
                for dy in range(0, 8, 4):
                    for dx in range(0, 8, 4):
                        if dataidx >= len(data): break
                        c = data[dataidx:dataidx+8]
                        dataidx += 8
                        if y+dy+4 <= height: dest[width*(y + dy)//2 + (x + dx)*2:width*(y + dy)//2 + (x + dx)*2 + 8] = fixS3TC1Block(c)
            elif format == TexFmt.RGBA8:
                 for dy in range(formatBlockHeight[format]):
                    for dx in range(int(formatBlockWidth[format])):
                        if dataidx >= len(data): break
                        idx = int((width*(y + dy) + x) + dx)*2
                        dest[idx  ] = data[dataidx   ]
                        dest[idx+1] = data[dataidx+16]
                        dataidx += 1
                 dataidx += 16
            else:
                for dy in range(formatBlockHeight[format]):
                    for i in range(int(formatBlockWidth[format])):
                        if dataidx >= len(data): break
                        c = data[dataidx]
                        dataidx += 1
                        idx = int((width*(y + dy) + x) + i)
                        dest[idx] = c
    return dest

def calcTextureSize(format, width, height):
    blockWidth = formatBlockWidth[format]
    blockHeight = formatBlockHeight[format]
    if width%blockWidth == 0: fullWidth = width
    else: fullWidth = width+blockWidth-(width%blockWidth)
    return int(fullWidth*height*formatBytesPerPixel[format])

# Read texture data into an array object, byte-swapped and with various data sizes for convenience
def readTextureData(fin, format, width, height, mipmapCount=1, arrayCount=1):
    data = array(formatArrayTypes[format])
    # data length = sum from i=0 to mipCount of (w*h/(4^i))
    mipSize = calcTextureSize(format, width, height)
    sliceSize = int(mipSize*(4-4**(1-mipmapCount))/3)
    start = fin.tell()
    try:
        data.fromfile(fin, int(arrayCount*sliceSize/data.itemsize))
    except EOFError:
        fin.seek(0, 2)
        end = fin.tell()
        fin.seek(start)
        data.fromfile(fin, int((end-start)/data.itemsize))
    if sys.byteorder == 'little': data.byteswap()
    return data

def readPaletteData(fin, paletteFormat, paletteNumEntries):
    data = array('H')
    data.fromfile(fin, paletteNumEntries)
    if sys.byteorder == 'little': data.byteswap()
    return data

def convertPalette(paletteData, paletteFormat):
    if paletteData is None: return paletteData
    palette = [None]*len(paletteData)
    for i, x in enumerate(paletteData):
        if paletteFormat == TlutFmt.IA8:
            palette[i] = x & 0x00FF, (x & 0xFF00) >> 8
        elif paletteFormat == TlutFmt.RGB565:
            palette[i] = rgb565toColor(x)
        elif paletteFormat == TlutFmt.RGB5A3:
            palette[i] = unpackRGB5A3(x)

## PIL

formatImageTypes = {
TexFmt.I4:     'L',
TexFmt.I8:     'L',
TexFmt.IA4:    'LA',
TexFmt.IA8:    'LA',
TexFmt.RGB565: 'RGB',
TexFmt.RGB5A3: 'RGBA',
TexFmt.RGBA8:  'RGBA',
TexFmt.CMPR:   'RGBA'
}

paletteFormatImageTypes = {
TlutFmt.IA8:    'LA',
TlutFmt.RGB565: 'RGB',
TlutFmt.RGB5A3: 'RGBA'
}

def decodeTexturePIL(data, format, width, height, paletteFormat=None, paletteData=None, mipmapCount=1, arrayCount=1):
    from PIL import Image
    
    dataIdx = 0
    imgs = [[None]*mipmapCount for i in range(arrayCount)]
    palette = convertPalette(paletteData, paletteFormat)
    for arrayIdx in range(arrayCount):
        for mipIdx in range(mipmapCount):
            im = Image.new(formatImageTypes[format] if format in formatImageTypes else paletteFormatImageTypes[paletteFormat],
                           (width>>mipIdx, height>>mipIdx))
            putpixelpil = lambda dx, dy, c: im.putpixel((dx, dy), c)
            for y in range(0, im.size[1], formatBlockHeight[format]):
                for x in range(0, im.size[0], formatBlockWidth[format]):
                    dataIdx = decodeBlock(format, data, dataIdx, im.size[0], im.size[1], x, y, putpixelpil, palette)
            imgs[arrayIdx][mipIdx] = im
    return imgs

## BPY

def decodeTextureBPY(im, data, format, width, height, paletteFormat=None, paletteData=None, mipmapCount=1, arrayCount=1):
    # Note: REALLY slow.
    # Like, EXTREMELY SLOW.
    # Should probably either profile or just export/import
    assert arrayCount <= 1
    dataIdx = 0
    def putpixelbpy(dx, dy, c):
        px = (dx+(height-dy-1)*width)*4
        if isinstance(c, int): c = (c,)
        if len(c) < 3:
            im.pixels[px  ] = c[0]/255.0
            im.pixels[px+1] = c[0]/255.0
            im.pixels[px+2] = c[0]/255.0
            if len(c) == 2:
                im.pixels[px+3] = c[1]/255.0
        else:
            im.pixels[px  ] = c[0]/255.0
            im.pixels[px+1] = c[1]/255.0
            im.pixels[px+2] = c[2]/255.0
            if len(c) == 4:
                im.pixels[px+3] = c[3]/255.0
    palette = convertPalette(paletteData, paletteFormat)
    for y in range(0, height, formatBlockHeight[format]):
        for x in range(0, width, formatBlockWidth[format]):
            dataIdx = decodeBlock(format, data, dataIdx, width, height, x, y, putpixelbpy, palette)
    im.update()

## DDS

class DDSD(Flag):
    CAPS = 0x00000001
    HEIGHT = 0x00000002
    WIDTH = 0x00000004
    PITCH = 0x00000008
    PIXELFORMAT = 0x00001000
    MIPMAPCOUNT = 0x00020000
    LINEARSIZE = 0x00080000

class DDPF(Flag):
    ALPHAPIXELS = 0x00000001
    FOURCC = 0x00000004
    RGB = 0x00000040
    LUMINANCE = 0x00020000

class DDSCAPS(Flag):
    COMPLEX = 0x00000008
    TEXTURE = 0x00001000
    MIPMAP = 0x00400000

ddsFormats = {
    TexFmt.I4:     (DDPF.RGB,                        b'',     24, 0x00FF0000, 0x0000FF00, 0x000000FF, 0x00000000),
    TexFmt.I8:     (DDPF.RGB,                        b'',     24, 0x00FF0000, 0x0000FF00, 0x000000FF, 0x00000000),
    TexFmt.IA4:    (DDPF.ALPHAPIXELS|DDPF.RGB,       b'',     32, 0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000),
    TexFmt.IA8:    (DDPF.ALPHAPIXELS|DDPF.RGB,       b'',     32, 0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000),
#    TexFmt.RGB565: (DDPF.RGB,                        b'',     16,     0x001F,     0x07E0,     0xF800,          0),
    TexFmt.RGB565: (DDPF.ALPHAPIXELS|DDPF.RGB,       b'',     24, 0x00FF0000, 0x0000FF00, 0x000000FF, 0x00000000),
    TexFmt.RGB5A3: (DDPF.ALPHAPIXELS|DDPF.RGB,       b'',     32, 0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000),
    TexFmt.RGBA8:  (DDPF.ALPHAPIXELS|DDPF.RGB,       b'',     32, 0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000),
    TexFmt.CMPR:   (DDPF.ALPHAPIXELS|DDPF.FOURCC,    b'DXT1',  0,          0,          0,          0,          0)
}
ddsPaletteFormats = {
    TlutFmt.IA8:    (DDPF.ALPHAPIXELS|DDPF.RGB,       b'',     32, 0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000),
    TlutFmt.RGB565: (DDPF.RGB,                        b'',     16,     0xF800,     0x07E0,     0x001F,          0),
    TlutFmt.RGB5A3: (DDPF.ALPHAPIXELS|DDPF.RGB,       b'',     32, 0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000),
}

def decodeTextureDDS(fout, data, format, width, height, paletteFormat=None, paletteData=None, mipmapCount=1, arrayCount=1):
    fout.write(b'DDS ')
    flags = DDSD.CAPS|DDSD.HEIGHT|DDSD.WIDTH|DDSD.PIXELFORMAT
    if format == TexFmt.CMPR:
        flags |= DDSD.LINEARSIZE
        pitchOrLinearSize = len(data)
    else:
        flags |= DDSD.PITCH
        bytesPerPixel = ddsFormats[format][2]//8
        pitchOrLinearSize = int(width*bytesPerPixel)
    if mipmapCount > 1:
        flags |= DDSD.MIPMAPCOUNT
    fout.write(struct.pack('<IIIIIII44x', 124, flags.value, height, width, pitchOrLinearSize, 1, mipmapCount))
    if format in ddsFormats:
        flags, fourCC, rgbBitCount, rBitMask, gBitMask, bBitMask, aBitMask = ddsFormats[format]
    else:
        flags, fourCC, rgbBitCount, rBitMask, gBitMask, bBitMask, aBitMask = ddsPaletteFormats[paletteFormat]
    fout.write(struct.pack('<II4sIIIII', 32, flags.value, fourCC, rgbBitCount, rBitMask, gBitMask, bBitMask, aBitMask))
    caps = DDSCAPS.TEXTURE
    if mipmapCount > 1:
        caps |= DDSCAPS.COMPLEX|DDSCAPS.MIPMAP
    elif arrayCount > 1:
        caps |= DDSCAPS.COMPLEX
    fout.write(struct.pack('<IIII4x', caps.value, 0, 0, 0))
    
    mipSize = int(calcTextureSize(format, width, height)/data.itemsize)
    sliceSize = int(mipSize*(4-4**(1-mipmapCount))/3)
    palette = convertPalette(paletteData, paletteFormat)
    if format in (TexFmt.I4, TexFmt.I8): componentsIn = 1
    elif format in (TexFmt.IA4, TexFmt.IA8): componentsIn = 2
    elif format == TexFmt.RGB565: componentsIn = 3
    elif format in (TexFmt.RGB5A3, TexFmt.RGBA8, TexFmt.CMPR): componentsIn = 4
    elif format in (TexFmt.C4, TexFmt.C8, TexFmt.C14X2):
        if paletteFormat == TlutFmt.IA8: componentsIn = 2
        elif paletteFormat == TlutFmt.RGB565: componentsIn = 3
        elif paletteFormat == TlutFmt.RGB5A3: componentsIn = 4
    if format in (TexFmt.IA4, TexFmt.IA8): componentsOut = 4
    else: componentsOut = max(3, componentsIn)

    for arrayIdx in range(arrayCount):
        for mipIdx in range(mipmapCount):
            mipWidth, mipHeight = width>>mipIdx, height>>mipIdx
            dataOffset = (arrayIdx*sliceSize + int(mipSize*(4-4**(1-mipIdx))/3))//data.itemsize
            if format in (TexFmt.I4, TexFmt.I8, TexFmt.IA4, TexFmt.IA8, TexFmt.RGB565, TexFmt.RGB5A3, TexFmt.C4, TexFmt.C8, TexFmt.C14X2):
                dest = array('B', (0,)*mipWidth*mipHeight*componentsOut)
                if componentsIn == 1:
                    def putpixelarray(dx, dy, c):
                        offset = (mipWidth*dy + dx)*componentsOut
                        dest[offset:offset + componentsOut] = array('B', [c]*componentsOut)
                elif componentsIn == 2:
                    def putpixelarray(dx, dy, c):
                        offset = (mipWidth*dy + dx)*componentsOut
                        dest[offset:offset + componentsOut] = array('B', [c[0], c[0], c[0], c[1]])
                elif componentsIn == 3:
                    def putpixelarray(dx, dy, c):
                        offset = (mipWidth*dy + dx)*componentsOut
                        dest[offset:offset + componentsOut] = array('B', [c[2], c[1], c[0]])
                elif componentsIn == 4:
                    def putpixelarray(dx, dy, c):
                        offset = (mipWidth*dy + dx)*componentsOut
                        dest[offset:offset + componentsOut] = array('B', [c[2], c[1], c[0], c[3]])
                for y in range(0, mipHeight, formatBlockHeight[format]):
                    for x in range(0, mipWidth, formatBlockWidth[format]):
                        dataOffset = decodeBlock(format, data, dataOffset, mipWidth, mipHeight, x, y, putpixelarray, palette)
                dest.tofile(fout)
            else:
                deblocked = deblock(format, data[dataOffset:dataOffset+(mipSize>>(mipIdx*2))], mipWidth, mipHeight)
                if sys.byteorder == 'big': deblocked.byteswap()
                deblocked.tofile(fout)

## KTX

class GL:
    UNSIGNED_BYTE                 = 0x1401
    RED                           = 0x1903
    RGB                           = 0x1907
    RGBA                          = 0x1908
    RGBA8                         = 0x8058
    RG                            = 0x8227
    R8                            = 0x8229
    RG8                           = 0x822B
    UNSIGNED_SHORT_5_6_5          = 0x8363
    COMPRESSED_RGB_S3TC_DXT1_EXT  = 0x83F0
    RGB565                        = 0x8D62

#                  glType                    glFormat glInternalFormat                 glBaseInternalFormat
glFormats = {
    TexFmt.I4:     (GL.UNSIGNED_BYTE,        GL.RED,  GL.R8,                           GL.RED),
    TexFmt.I8:     (GL.UNSIGNED_BYTE,        GL.RED,  GL.R8,                           GL.RED),
    TexFmt.IA4:    (GL.UNSIGNED_BYTE,        GL.RG,   GL.RG8,                          GL.RG),
    TexFmt.IA8:    (GL.UNSIGNED_BYTE,        GL.RG,   GL.RG8,                          GL.RG),
    TexFmt.RGB565: (GL.UNSIGNED_SHORT_5_6_5, GL.RGB,  GL.RGB565,                       GL.RGB),
    TexFmt.RGB5A3: (GL.UNSIGNED_BYTE,        GL.RGBA, GL.RGBA8,                        GL.RGBA),
    TexFmt.RGBA8:  (GL.UNSIGNED_BYTE,        GL.RGBA, GL.RGBA8,                        GL.RGBA),
    TexFmt.CMPR:   (                      0,       0, GL.COMPRESSED_RGB_S3TC_DXT1_EXT, GL.RGBA)
}
glPaletteFormats = {
    TlutFmt.IA8:    (GL.UNSIGNED_BYTE,        GL.RG,   GL.RG8,                          GL.RG),
    TlutFmt.RGB565: (GL.UNSIGNED_SHORT_5_6_5, GL.RGB,  GL.RGB565,                       GL.RGB),
    TlutFmt.RGB5A3: (GL.UNSIGNED_BYTE,        GL.RGBA, GL.RGBA8,                        GL.RGBA),
}

def decodeTextureKTX(fout, data, format, width, height, paletteFormat=None, paletteData=None, mipmapCount=1, arrayCount=0):
    fout.write(bytes([0xAB, 0x4B, 0x54, 0x58, 0x20, 0x31, 0x31, 0xBB, 0x0D, 0x0A, 0x1A, 0x0A]))
    if format in glFormats:
        glType, glFormat, glInternalFormat, glBaseInternalFormat = glFormats[format]
    else:
        glType, glFormat, glInternalFormat, glBaseInternalFormat = glPaletteFormats[paletteFormat]
    fout.write(struct.pack('IIIIIIIIIIIII',
        0x04030201,
        glType,
        1, # glTypeSize
        glFormat,
        glInternalFormat,
        glBaseInternalFormat,
        width,
        height,
        0, # depth
        arrayCount,
        1, # face count
        mipmapCount,
        28)) # key-value length
    
    fout.write(struct.pack('I', 23))
    fout.write(b'KTXorientation\0S=r,T=d\0\0')

    mipSize = int(calcTextureSize(format, width, height)/data.itemsize)
    sliceSize = int(mipSize*(4-4**(1-mipmapCount))/3)
    palette = convertPalette(paletteData, paletteFormat)
    if format in (TexFmt.I4, TexFmt.I8): components = 1
    elif format in (TexFmt.IA4, TexFmt.IA8): components = 2
    elif format == TexFmt.RGB565: components = 3
    elif format in (TexFmt.RGB5A3, TexFmt.RGBA8, TexFmt.CMPR): components = 4
    elif format in (TexFmt.C4, TexFmt.C8, TexFmt.C14X2):
        if paletteFormat == TlutFmt.IA8: components = 2
        elif paletteFormat == TlutFmt.RGB565: components = 3
        elif paletteFormat == TlutFmt.RGB5A3: components = 4

    for mipIdx in range(mipmapCount):
        for arrayIdx in range(max(1, arrayCount)):
            mipWidth, mipHeight = width>>mipIdx, height>>mipIdx
            dataOffset = (arrayIdx*sliceSize + int(mipSize*(4-4**(1-mipIdx))/3))//data.itemsize
            if format in (TexFmt.I4, TexFmt.IA4, TexFmt.RGB5A3) or (format in (TexFmt.C4, TexFmt.C8, TexFmt.C14X2) and paletteFormat in (TlutFmt.IA8, TlutFmt.RGB5A3)):
                pixelData = array('B', (0,)*mipWidth*mipHeight*components)
                if components == 1:
                    def putpixelarray(dx, dy, c):
                        pixelData[mipWidth*dy + dx] = c
                else:
                    def putpixelarray(dx, dy, c):
                        offset = (mipWidth*dy + dx)*components
                        pixelData[offset:offset + components] = array('B', c)
                for y in range(0, mipHeight, formatBlockHeight[format]):
                    for x in range(0, mipWidth, formatBlockWidth[format]):
                        dataOffset = decodeBlock(format, data, dataOffset, mipWidth, mipHeight, x, y, putpixelarray, palette)
            elif format in (TexFmt.C4, TexFmt.C8, TexFmt.C14X2) and paletteFormat == TlutFmt.RGB565:
                pixelData = deblock(format, data[dataOffset:dataOffset+(mipSize>>(mipIdx*2))], mipWidth, mipHeight)
                if sys.byteorder == 'big': pixelData.byteswap()
                pixelData = array('H', [paletteData[px] for px in deblocked])
            else:
                pixelData = deblock(format, data[dataOffset:dataOffset+(mipSize>>(mipIdx*2))], mipWidth, mipHeight)
                if sys.byteorder == 'big': pixelData.byteswap()
            fout.write(struct.pack('I', len(pixelData)*pixelData.itemsize))
            pixelData.tofile(fout)

