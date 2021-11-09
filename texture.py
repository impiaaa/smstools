# Common functions for reading, decoding, reformatting, and exporting block-based GameCube TEV/Flipper/GX texture data.

import struct
from array import array
import sys
from enum import Enum, Flag

class TF(Enum):
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

class TL(Enum):
    IA8 = 0x0
    RGB565 = 0x1
    RGB5A3 = 0x2

formatBytesPerPixel = {
TF.I4:   0.5,
TF.I8:     1,
TF.IA4:    1,
TF.IA8:    2,
TF.RGB565: 2,
TF.RGB5A3: 2,
TF.RGBA8:  4,
TF.C4:   0.5,
TF.C8:     1,
TF.C14X2:  2,
TF.CMPR: 0.5
}

formatBlockWidth = {
TF.I4:     8,
TF.I8:     8,
TF.IA4:    8,
TF.IA8:    4,
TF.RGB565: 4,
TF.RGB5A3: 4,
TF.RGBA8:  4,
TF.C4:     8,
TF.C8:     8,
TF.C14X2:  4,
TF.CMPR:   8
}

formatBlockHeight = {
TF.I4:     8,
TF.I8:     4,
TF.IA4:    4,
TF.IA8:    4,
TF.RGB565: 4,
TF.RGB5A3: 4,
TF.RGBA8:  4,
TF.C4:     8,
TF.C8:     4,
TF.C14X2:  4,
TF.CMPR:   8
}

formatArrayTypes = {
TF.I4:     'B',
TF.I8:     'B',
TF.IA4:    'B',
TF.IA8:    'B',
TF.RGB565: 'H',
TF.RGB5A3: 'H',
TF.RGBA8:  'B',
TF.C4:     'B',
TF.C8:     'B',
TF.C14X2:  'H',
TF.CMPR:   'B'
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
    if format == TF.I4:
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
    
    elif format == TF.I8:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+8):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, c)
    
    elif format == TF.IA4:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+8):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    t = c&0xF0
                    a = c&0x0F
                    putpixel(x, y, (t | (t >> 4),(a << 4) | a))
    
    elif format == TF.IA8:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c1, c2 = data[dataidx], data[dataidx+1]
                dataidx += 2
                if x < width and y < height:
                    putpixel(x, y, (c1,c2))
    
    elif format == TF.RGB565:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, (rgb565toColor(c)))
    
    elif format == TF.RGB5A3:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, unpackRGB5A3(c))
    
    elif format == TF.RGBA8:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c = data[dataidx:dataidx+4]
                dataidx += 4
                if x < width and y < height:
                    putpixel(x, y, c)
    
    elif format == TF.C4:
        for y in range(yoff, yoff+8):
            for x in range(xoff, xoff+8, 2):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, palette[(c & 0xf0) >> 4])
                    putpixel(x+1, y, palette[c & 0x0f])
    
    elif format == TF.C8:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+8):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, palette[c])
    
    elif format == TF.C14X2:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, palette[c&0x3FFF])
    
    elif format == TF.CMPR:
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
    dest = array(data.typecode, [0]*int(width*height*formatBytesPerPixel[format]))
    dataidx = 0
    for y in range(0, height, formatBlockHeight[format]):
        for x in range(0, width, formatBlockWidth[format]):
            if format == TF.CMPR:
                for dy in range(0, 8, 4):
                    for dx in range(0, 8, 4):
                        if dataidx >= len(data): break
                        c = data[dataidx:dataidx+8]
                        dataidx += 8
                        if y+dy+4 <= height: dest[width*(y + dy)//2 + (x + dx)*2:width*(y + dy)//2 + (x + dx)*2 + 8] = fixS3TC1Block(c)
            else:
                for dy in range(formatBlockHeight[format]):
                    for i in range(int(formatBlockWidth[format]/data.itemsize)):
                        if dataidx >= len(data): break
                        c = data[dataidx]
                        dataidx += 1
                        idx = int((width*(y + dy) + x)/data.itemsize + i)
                        if idx < len(dest): dest[idx] = c
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
        if paletteFormat == TL.IA8:
            palette[i] = x & 0x00FF, (x & 0xFF00) >> 8
        elif paletteFormat == TL.RGB565:
            palette[i] = rgb565toColor(x)
        elif paletteFormat == TL.RGB5A3:
            palette[i] = unpackRGB5A3(x)

formatImageTypes = {
TF.I4:     'L',
TF.I8:     'L',
TF.IA4:    'LA',
TF.IA8:    'LA',
TF.RGB565: 'RGB',
TF.RGB5A3: 'RGBA',
TF.RGBA8:  'RGBA',
TF.CMPR:   'RGBA'
}

paletteFormatImageTypes = {
TL.IA8:    'LA',
TL.RGB565: 'RGB',
TL.RGB5A3: 'RGBA'
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
    TF.I4:     (DDPF.LUMINANCE,                  b'',      8,       0xFF,          0,          0,          0),
    TF.I8:     (DDPF.LUMINANCE,                  b'',      8,       0xFF,          0,          0,          0),
    TF.IA4:    (DDPF.ALPHAPIXELS|DDPF.LUMINANCE, b'',      8,       0xF0,          0,          0,       0x0F),
    TF.IA8:    (DDPF.ALPHAPIXELS|DDPF.LUMINANCE, b'',     16,     0x00FF,          0,          0,     0xFF00),
    TF.RGB565: (DDPF.RGB,                        b'',     16,     0xF800,     0x07E0,     0x001F,          0),
#    TF.RGB5A3: (DDPF.ALPHAPIXELS|DDPF.RGB,       b'',     32, 0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000),
    TF.RGB5A3: (DDPF.ALPHAPIXELS|DDPF.RGB,       b'',     32, 0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000),
    TF.RGBA8:  (DDPF.ALPHAPIXELS|DDPF.RGB,       b'',     32, 0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000),
    TF.CMPR:   (DDPF.ALPHAPIXELS|DDPF.FOURCC,    b'DXT1',  0,          0,          0,          0,          0)
}
ddsPaletteFormats = {
    TL.IA8:    (DDPF.ALPHAPIXELS|DDPF.LUMINANCE, b'',     16,     0x00FF,          0,          0,     0xFF00),
    TL.RGB565: (DDPF.RGB,                        b'',     16,     0xF800,     0x07E0,     0x001F,          0),
    TL.RGB5A3: (DDPF.ALPHAPIXELS|DDPF.RGB,       b'',     32, 0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000),
}

def decodeTextureDDS(fout, data, format, width, height, paletteFormat=None, paletteData=None, mipmapCount=1, arrayCount=1):
    fout.write(b'DDS ')
    flags = DDSD.CAPS|DDSD.HEIGHT|DDSD.WIDTH|DDSD.PIXELFORMAT
    if format == TF.CMPR:
        flags |= DDSD.LINEARSIZE
        pitchOrLinearSize = len(data)
    else:
        flags |= DDSD.PITCH
        if format == TF.RGB5A3: bytesPerPixel = 4
        elif format == TF.I4: bytesPerPixel = 1
        elif format in (TF.C4, TF.C8, TF.C14X2): 
            if paletteFormat == TL.RGB5A3: bytesPerPixel = 4
            else: bytesPerPixel = 2
        else: bytesPerPixel = formatBytesPerPixel[format]
        #bytesPerPixel = 2
        pitchOrLinearSize = int(width*bytesPerPixel)
    if mipmapCount > 1:
        flags |= DDSD.MIPMAPCOUNT
    fout.write(struct.pack('<IIIIIII44x', 124, flags.value, height, width, pitchOrLinearSize, 0, mipmapCount))
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
    if format in (TF.I4, TF.I8): components = 1
    elif format in (TF.IA4, TF.IA8): components = 2
    elif format == TF.RGB565: components = 3
    elif format in (TF.RGB5A3, TF.RGBA8, TF.CMPR): components = 4
    elif format in (TF.C4, TF.C8, TF.C14X2):
        if paletteFormat == TL.IA8: components = 2
        elif paletteFormat == TL.RGB565: components = 3
        elif paletteFormat == TL.RGB5A3: components = 4

    for arrayIdx in range(arrayCount):
        for mipIdx in range(mipmapCount):
            mipWidth, mipHeight = width>>mipIdx, height>>mipIdx
            dataOffset = arrayIdx*sliceSize + int(mipSize*(4-4**(1-mipIdx))/3)
            if format in (TF.I4, TF.RGB5A3, TF.C4, TF.C8, TF.C14X2):
                dest = array('B', (0,)*mipWidth*mipHeight*components)
                if format == TF.I4:
                    def putpixelarray(dx, dy, c):
                        dest[mipWidth*dy + dx] = c
                else:
                    def putpixelarray(dx, dy, c):
                        offset = (mipWidth*dy + dx)*components
                        dest[offset:offset + components] = array('B', [c[2], c[1], c[0], c[3]])
                for y in range(0, mipHeight, formatBlockHeight[format]):
                    for x in range(0, mipWidth, formatBlockWidth[format]):
                        dataOffset = decodeBlock(format, data, dataOffset, mipWidth, mipHeight, x, y, putpixelarray, palette)
                dest.tofile(fout)
            else:
                deblocked = deblock(format, data[dataOffset:dataOffset+mipSize>>(mipIdx*2)], mipWidth, mipHeight)
                if sys.byteorder == 'big': deblocked.byteswap()
                deblocked.tofile(fout)
