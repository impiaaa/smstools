import sys, os
from struct import pack, unpack
import struct
from warnings import warn

fin = open(sys.argv[1], 'rb')
signature, fileLength, chunkCount, svr = unpack('>8sLL4s12x', fin.read(0x20))

indent = 0
htmlout = open(os.path.splitext(sys.argv[1])[0]+".html", 'w')
htmlout.write("<html><head><title></title></head><body>\n")
toWrite = '<div>\n'
chunks = []
grayimages = ["coin_back", "error_window", "juice_liquid", "juice_mask", "juice_surface", "sc_mask", "standard_window", "telop_window_1", "telop_window_2", "telop_window_3", "telop_window_4", "water_back", "water_icon_1", "water_icon_2", "water_icon_3"]
for chunkno in xrange(chunkCount):
    start = fin.tell()
    try: chunk, size = unpack('>4sL', fin.read(8))
    except struct.error:
        warn("File too small for chunk count of "+str(chunkCount))
        continue
    chunks.append((chunk, fin.read(size-8)))

def parsechunks(chunklist, i=0, indent=0, parentx=0, parenty=0):
    toWrite = '<div>\n'
    lastX = lastY = 0
    newx = newy = 0
    while i < len(chunklist):
        chunk, data = chunklist[i]
        print ' '*indent+chunk
        if chunk == "BGN1":
            htmlout.write(toWrite)
            i = parsechunks(chunklist, i+1, indent+1, newx+parentx, newy+parenty)
            htmlout.write("</div>\n")
        elif chunk == "END1":
            return i
        elif chunk == "INF1":
            width, height = unpack('>HH4x', data)
        elif chunk == "PIC1":
            u = [None]*10
            u[0], u[1], u[2], u[4], id = unpack(">BBBB4s", data[:8])
            c = 8
            if u[0] == 0x06:
                # relative to parent
                x, y, width, height = unpack(">hhhh", data[8:16])
                c = 16
            elif u[0] == 0x07:
                # relative to last
                x, y, width, height, u[4], u[5], u[6], u[7] = unpack(">xbxbhhBBBB", data[8:20])
                c = 20
                x += lastX
                y += lastY
            elif u[0] == 0x08:
                # relative to parent, but different order, and set last
                x, y, width, height, u[4], u[5], u[6], u[7] = unpack(">hhhhBBBB", data[8:20])
                c = 20
                lastX = x
                lastY = y
            elif u[0] == 0x09:
                # ???
                x, y, width, height, u[4], u[5], u[6], u[7] = unpack(">hhhhBBBB", data[8:20])
                c = 20
            else:
                raise Exception("Unknown rel type 0x%02X"%u[0])
            u[8], u[9], namelen = unpack(">BBB", data[c:c+3])
            c += 3
            name = os.path.splitext(data[c:c+namelen])[0]
            c += namelen
            c += 4-(c%4)
            u += map(ord, data[c:])
            htmlout.write('<img style="position:absolute; left:%dpx; top:%dpx; width:%dpx; height: %dpx; border: black 0px solid" src="../timg/%s.png" id="%s">\n'%(x,y,width,height,name,id))
        elif chunk == "PAN1":
            unknown1, id, x, y, width, height = unpack(">H2x4shhhh", data[:16])
            if unknown1 == 0x00000801:
                unknown2, = unpack(">L", data[16:])
            toWrite = '<div style="position:absolute; left:%dpx; top:%dpx; width:%dpx; height: %dpx; border: black 0px solid">\n'%(x, y, width, height)
            lastX = x
            lastY = y
            newx = x
            newy = y
        i += 1
    return i

parsechunks(chunks)
htmlout.write("</body></html>")
htmlout.close()
fin.close()
