import sys, struct, Image

fin = open(sys.argv[1], 'rb')
signature, fileLength, chunkCount, svr = struct.unpack('>8sLL4s12x', fin.read(0x20))
for i in xrange(chunkCount):
    chunkstart = fin.tell()
    try: chunk, chunksize = struct.unpack('>4sL', fin.read(8))
    except struct.error:
        warn("File too small for chunk count of "+str(chunkCount))
        continue
    if chunk == "GLY1":
        fin.seek(0xC, 1)
        format, w, h = struct.unpack('>H4xHH', fin.read(0xa))
        h = (chunksize-0x18)/w
        if format == 0: h *= 2
        fin.seek(2, 1)
        if format == 0:
            im = Image.new('L', (w, h))
            for y in xrange(0, h, 8):
                for x in xrange(0, w, 8):
                    for dy in xrange(8):
                        for dx in xrange(0, 8, 2):
                            c = ord(fin.read(1))
                            if x + dx < w and y + dy < h:
                                t = c&0xF0
                                im.putpixel((x+dx, y+dy), t | (t >> 4))
                                t = c&0x0F
                                im.putpixel((x+dx+1, y+dy), (t << 4) | t)
        elif format == 2:
            im = Image.new('RGBA', (w, h))
            for y in xrange(0, h, 4):
                for x in xrange(0, w, 8):
                    for dy in xrange(4):
                        for dx in xrange(0, 8):
                            c = ord(fin.read(1))
                            if x + dx < w and y + dy < h:
                                t = c&0xF0
                                #im.putpixel((x+dx, y+dy), (t | (t >> 4),)*3)
                                a = c&0x0F
                                im.putpixel((x+dx, y+dy), (t | (t >> 4),)*3+((a << 4) | a,))
        im.save(sys.argv[1]+'.png')
    # TODO: INF1, WID1, MAP1
    fin.seek(chunkstart+chunksize)

