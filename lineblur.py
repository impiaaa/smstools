from PIL import Image, ImageChops

def clampBlur(blur, extend):
    for y in range(blur.size[1]):
        for x in range(blur.size[0]):
            px = blur.getpixel((x,y))
            mnpx = extend.getpixel((x,y))&0xF0
            mxpx = mnpx+15
            px = max(mnpx, min(mxpx, px))
            blur.putpixel((x,y),px)

def doLineBlur(blur, extend, flip, mask):
    for y in range(blur.size[0] if flip else blur.size[1]):
        start = None
        last = None
        #print("row", y)
        for x in range(blur.size[1] if flip else blur.size[0]):
            px = extend.getpixel((y,x) if flip else (x,y))
            if last is not None:
                if x == 1 and px == last and False:
                    start = 0
                elif abs(px-last) <= 17 and px != last:
                    #print("at", start, "is", last, "- at", x, "is", px)
                    if start is not None and (x-start) > 1 and (x-start) < 16:
                        if start == 0:
                            startColor = extend.getpixel((y,start) if flip else (start,y))
                            if px > startColor: startColor -= 17
                            else: startColor += 17
                        else:
                            startColor = extend.getpixel((y,start-1) if flip else (start-1,y))
                        #print("prior is", startColor)
                        endColor = px
                        if startColor != endColor:
                            if startColor > endColor:
                                startColor &= 0xF0
                                endColor = (endColor&0xF0)+0x10
                                #print("downward from", hex(startColor), "to", hex(endColor))
                            else:
                                startColor = (startColor&0xF0)+0x10
                                endColor &= 0xF0
                                #print("upward from", hex(startColor), "to", hex(endColor))
                            for dx in range(start, x):
                                blur.putpixel((y,dx) if flip else (dx,y), int(((endColor-startColor)*(dx+0.5-start)/(x-start))+startColor))
                                mask.putpixel((y,dx) if flip else (dx,y), 1)
                    start = x
                elif abs(px-last) > 17:
                    start = None
            last = px

def bidirLineBlurOneChannel(extend):
    blurHoriz = Image.new('L', extend.size)
    horizMask = Image.new('1', extend.size, 0)
    doLineBlur(blurHoriz, extend, False, horizMask)
    blurVert = Image.new('L', extend.size)
    vertMask = Image.new('1', extend.size, 0)
    doLineBlur(blurVert, extend, True, vertMask)
    combinedBlur = Image.blend(blurHoriz, blurVert, 0.5)
    combinedMask = ImageChops.darker(horizMask, vertMask)
    maskedBlur = ImageChops.composite(combinedBlur, ImageChops.composite(blurVert, ImageChops.composite(blurHoriz, extend, horizMask), vertMask), combinedMask)
    clampBlur(maskedBlur, extend) # shouldn't be needed
    return maskedBlur

def bidirLineBlur(extend):
    bandNames = extend.getbands()
    if len(bandNames) == 1:
        return bidirLineBlurOneChannel(extend)
    else:
        return Image.merge(extend.mode, [bidirLineBlurOneChannel(extend.getchannel(channelName)) for channelName in bandNames])

if __name__ == "__main__":
    from bmd import BModel
    from texture import TexFmt, decodeTexturePIL
    bmd = BModel(open("scene/dolpic10/map/map/map.bmd", 'rb'))
    for img in bmd.tex1.textures:
        if img.format in (TexFmt.I4, TexFmt.IA4):
            extend = decodeTexturePIL(img.data, img.format, img.width, img.height, img.paletteFormat, img.palette, img.mipmapCount)[0][0]
            extend.transpose(method=1).save(img.name+"-extend.png")
            bidirLineBlur(extend).transpose(method=1).save(img.name+"-lineBlur.png")

