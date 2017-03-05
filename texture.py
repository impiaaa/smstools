import struct
from array import array

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

formatBytesPerPixel = {
GX_TF_I4:   0.5,
GX_TF_I8:     1,
GX_TF_IA4:    1,
GX_TF_IA8:    2,
GX_TF_RGB565: 2,
GX_TF_RGB5A3: 2,
GX_TF_RGBA8:  4,
GX_TF_C4:   0.5,
GX_TF_C8:     1,
GX_TF_C14X2:  2,
GX_TF_CMPR: 0.5
}

formatBlockWidth = {
GX_TF_I4:     8,
GX_TF_I8:     8,
GX_TF_IA4:    8,
GX_TF_IA8:    4,
GX_TF_RGB565: 4,
GX_TF_RGB5A3: 4,
GX_TF_RGBA8:  4,
GX_TF_C4:     8,
GX_TF_C8:     8,
GX_TF_C14X2:  4,
GX_TF_CMPR:   8
}

formatBlockHeight = {
GX_TF_I4:     8,
GX_TF_I8:     4,
GX_TF_IA4:    4,
GX_TF_IA8:    4,
GX_TF_RGB565: 4,
GX_TF_RGB5A3: 4,
GX_TF_RGBA8:  4,
GX_TF_C4:     8,
GX_TF_C8:     4,
GX_TF_C14X2:  4,
GX_TF_CMPR:   8
}

formatArrayTypes = {
GX_TF_I4:     'B',
GX_TF_I8:     'B',
GX_TF_IA4:    'B',
GX_TF_IA8:    'B',
GX_TF_RGB565: 'H',
GX_TF_RGB5A3: 'H',
GX_TF_RGBA8:  'B',
GX_TF_C4:     'B',
GX_TF_C8:     'B',
GX_TF_C14X2:  'H',
GX_TF_CMPR:   'B'
}

formatImageTypes = {
GX_TF_I4:     'L',
GX_TF_I8:     'L',
GX_TF_IA4:    'LA',
GX_TF_IA8:    'LA',
GX_TF_RGB565: 'RGB',
GX_TF_RGB5A3: 'RGBA',
GX_TF_RGBA8:  'RGBA',
GX_TF_CMPR:   'RGBA'
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
    r = (rgb & 0xf100) >> 11
    g = (rgb & 0x7e0) >> 5
    b = (rgb & 0x1f)
    #http://www.mindcontrol.org/~hplus/graphics/expand-bits.html
    r = (r << 3) | (r >> 2)
    g = (g << 2) | (g >> 4)
    b = (b << 3) | (b >> 2)
    return r,g,b

def fixS3TC1Block(data):
    dest = [0]*8
    dest[0] = data[1]
    dest[1] = data[0]
    dest[2] = data[3]
    dest[3] = data[2]
    dest[4] = s3tc1ReverseByte(data[4])
    dest[5] = s3tc1ReverseByte(data[5])
    dest[6] = s3tc1ReverseByte(data[6])
    dest[7] = s3tc1ReverseByte(data[7])
    return dest

def decodeBlock(format, data, dataidx, width, height, xoff, yoff, putpixel, palette=None):
    if format == GX_TF_I4:
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
    
    elif format == GX_TF_I8:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+8):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, c)
    
    elif format == GX_TF_IA4:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+8):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    t = c&0xF0
                    a = c&0x0F
                    putpixel(x, y, (t | (t >> 4),(a << 4) | a))
    
    elif format == GX_TF_IA8:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c1, c2 = data[dataidx], data[dataidx+1]
                dataidx += 2
                if x < width and y < height:
                    putpixel(x, y, (c1,c2))
    
    elif format == GX_TF_RGB565:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, (rgb565toColor(c)))
    
    elif format == GX_TF_RGB5A3:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c = data[dataidx]
                dataidx += 1
                if x < width and y < height:
                    putpixel(x, y, unpackRGB5A3(c))
    
    elif format == GX_TF_RGBA8:
        for y in range(yoff, yoff+4):
            for x in range(xoff, xoff+4):
                if dataidx >= len(data): break
                c = data[dataidx:dataidx+4]
                dataidx += 4
                if x < width and y < height:
                    putpixel(x, y, c)
    #GX_TF_C4
    #GX_TF_C8
    #GX_TF_C14X2
    elif format == GX_TF_CMPR:
        for x in range(xoff, xoff+8, 4):
            for y in range(yoff, yoff+8, 4):
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
        raise Exception("Unsupported format %d"%format)
    return dataidx

def calcTextureSize(format, width, height):
    return int(width*height*formatBytesPerPixel[format])

def readTextureData(fin, format, width, height, mipmapCount=1, arrayCount=1):
    data = array(formatArrayTypes[format])
    # data length = sum from i=0 to mipCount of (w*h/(4^i))
    mipSize = calcTextureSize(format, width, height)
    sliceSize = int(mipSize*(4-4**(1-mipmapCount))/3)
    data.fromfile(fin, int(arrayCount*sliceSize/struct.calcsize(data.typecode)))
    data.byteswap()
    return data

def decodeTexturePIL(data, format, width, height, paletteFormat=None, palette=None, mipmapCount=1, arrayCount=1):
    from PIL import Image
    
    dataIdx = 0
    imgs = [[None]*mipmapCount for i in range(arrayCount)]
    for arrayIdx in range(arrayCount):
        for mipIdx in range(mipmapCount):
            im = Image.new(formatImageTypes[format], (width>>mipIdx, height>>mipIdx))
            putpixelpil = lambda dx, dy, c: im.putpixel((dx, dy), c)
            for y in range(0, im.height, formatBlockHeight[format]):
                for x in range(0, im.width, formatBlockWidth[format]):
                    dataIdx = decodeBlock(format, data, dataIdx, im.width, im.height, x, y, putpixelpil, palette)
            imgs[arrayIdx][mipIdx] = im
    return imgs

def decodeTextureBPY(im, data, format, width, height, paletteFormat=None, palette=None, mipmapCount=1, arrayCount=1):
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
    for y in range(0, height, formatBlockHeight[format]):
        for x in range(0, width, formatBlockWidth[format]):
            dataIdx = decodeBlock(format, data, dataIdx, width, height, x, y, putpixelbpy, palette)
    im.update()
