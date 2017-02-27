import sys, os
from struct import pack, unpack, Struct, error as StructError
from warnings import warn
from common import Section, BFile

class Bgn1(Section): pass

class End1(Section): pass

class Inf1(Section):
    header = Struct('>HH4x')
    def read(self, fin, start, size):
        self.width, self.height = self.header.unpack(fin.read(size-8))

class Pic1(Section):
    header = Struct('>BBBB4s')
    def read(self, fin, start, size):
        u = [None]*9
        self.rel, u[0], u[1], u[2], self.id = self.header.unpack(fin.read(8))
        if self.rel == 0x06:
            self.x, self.y, self.width, self.height = unpack(">hhhh", fin.read(8))
        elif self.rel == 0x07:
            self.x, self.y, self.width, self.height, u[3], u[4], u[5], u[6] = unpack(">xbxbhhBBBB", fin.read(12))
        elif self.rel == 0x08:
            self.x, self.y, self.width, self.height, u[3], u[4], u[5], u[6] = unpack(">hhhhBBBB", fin.read(12))
        elif self.rel == 0x09:
            self.x, self.y, self.width, self.height, u[3], u[4], u[5], u[6] = unpack(">hhhhBBBB", fin.read(12))
        else:
            raise Exception("Unknown rel type 0x%02X"%self.rel)
        u[7], u[8], namelen = unpack(">BBB", fin.read(3))
        self.name = os.path.splitext(fin.read(namelen).decode('shift-jis'))[0]
        u += map(ord, fin.read(fin.tell()+size-start))

class Pan1(Section):
    def read(self, fin, start, size):
        unknown1, self.id, self.x, self.y, self.width, self.height = unpack(">H2x4shhhh", fin.read(16))
        if unknown1 == 0x00000801:
            unknown2, = unpack(">L", fin.read(4))

class BLayout(BFile):
    sectionHandlers = {
        b'BGN1': Bgn1,
        b'END1': End1,
        b'PIC1': Pic1,
        b'PAN1': Pan1
    }

fin = open(sys.argv[1], 'rb')
blo = BLayout()
blo.read(fin)
fin.close()

indent = 0
htmlout = open(os.path.splitext(sys.argv[1])[0]+".html", 'w')
htmlout.write("<html><head><title></title></head><body>\n")
toWrite = '<div>\n'
chunks = []
grayimages = ["coin_back", "error_window", "juice_liquid", "juice_mask", "juice_surface", "sc_mask", "standard_window", "telop_window_1", "telop_window_2", "telop_window_3", "telop_window_4", "water_back", "water_icon_1", "water_icon_2", "water_icon_3"]

def parsechunks(chunklist, i=0, indent=0, parentx=0, parenty=0):
    toWrite = '<div>\n'
    lastX = lastY = 0
    newx = newy = 0
    while i < len(chunklist):
        print ' '*indent+chunk
        if chunk == "":
            htmlout.write(toWrite)
            i = parsechunks(chunklist, i+1, indent+1, newx+parentx, newy+parenty)
            htmlout.write("</div>\n")
        elif chunk == "":
            return i
        elif chunk == "":
            if u[0] == 0x06:
                # relative to parent
            elif u[0] == 0x07:
                # relative to last
                x += lastX
                y += lastY
            elif u[0] == 0x08:
                # relative to parent, but different order, and set last
                lastX = x
                lastY = y
            elif u[0] == 0x09:
                # ???
            else:
                raise Exception("Unknown rel type 0x%02X"%u[0])
            htmlout.write('<img style="position:absolute; left:%dpx; top:%dpx; width:%dpx; height: %dpx; border: black 0px solid" src="../timg/%s.png" id="%s">\n'%(x,y,width,height,name,id))
        elif chunk == "":
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
