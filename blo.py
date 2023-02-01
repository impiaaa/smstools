#!/usr/bin/env python

import sys, os
from struct import unpack, Struct
from common import Section, BFile
from enum import Enum

class Bgn1(Section):
    header = Struct('')
    fields = []

class End1(Section):
    header = Struct('')
    fields = []

class Ext1(Section):
    header = Struct('')
    fields = []

class Inf1(Section):
    header = Struct('>HHI')
    fields = ['width', 'height', 'tintColor']

class J2DBasePosition(Enum):
	TopLeft = 0
	TopMiddle = 1
	TopRight = 2

	CenterLeft = 3
	CenterMiddle = 4
	CenterRight = 5

	BottomLeft = 6
	BottomMiddle = 7
	BottomRight = 8

class Pan1(Section):
    def __init__(self, fin=None, pos=None):
        self.visible = False
        self.paneId = b'\0\0\0\0'
        self.x = 0
        self.y = 0
        self.width = 0
        self.height = 0
        self.angle = 0
        self.anchor = J2DBasePosition.TopLeft
        self.alpha = 0xFF
        self.inheritAlpha = 0
        super().__init__(fin, pos)
    
    def read(self, fin, start, size):
        numParams, = unpack('B', fin.read(1))
        self.fields = ['visible', 'paneId', 'x', 'y', 'width', 'height', 'angle', ('anchor', J2DBasePosition), 'alpha', 'inheritAlpha'][:numParams]
        self.header = Struct('>'+''.join(['?2x','4s','h','h','h','h','h','B','B','?'][:numParams]))
        super().read(fin, start, size)

def getResource(fin):
    resourceType, namelen = unpack('>BB', fin.read(2))
    return resourceType, fin.read(namelen).decode('shift-jis')

class Pic1(Pan1):
    def __init__(self, fin=None, pos=None):
        self.image = (0, '')
        self.lut = (0, '')
        self.binding = 0
        self.mirrorFlags = 0
        self.wrapFlags = 0
        self.fromColor = 0xFFFFFFFF
        self.toColor = 0xFFFFFFFF
        self.colors = [0xFFFFFFFF]*4
        super().__init__(fin, pos)
        
    def read(self, fin, start, size):
        super().read(fin, start, size)
        numParams, = unpack('B', fin.read(1))
        if numParams > 0:
            self.image = getResource(fin)
            numParams -= 1
        if numParams > 0:
            self.lut = getResource(fin)
            numParams -= 1
        parentFields = self.fields
        self.fields = ['binding', 'mirrorFlags', 'wrapFlags', 'fromColor', 'toColor'][:numParams]
        parentHeader = self.header
        self.header = Struct('>'+'BBII'[:numParams])
        Section.read(self, fin, start, size)
        numParams -= 4
        self.fields = parentFields + self.fields
        self.header = Struct(parentHeader.format + self.header.format[1:])
        for i in range(4):
            if numParams > 0:
                self.colors[i], = unpack('>I', fin.read(4))
                numParams -= 1
    
    def __repr__(self):
        return "{} image={} lut={} binding={} mirrorFlags={} wrapFlags={} fromColor={} toColor={} colors={}".format(super().__repr__(), self.image, self.lut, self.binding, self.mirrorFlags, self.wrapFlags, self.fromColor, self.toColor, self.colors)

class Tbx1(Pan1):
    def __init__(self, fin=None, pos=None):
        self.topColor = 0
        self.bottomColor = 0
        self.binding = 0
        self.fontSpacing = 0
        self.fontLeading = 0
        self.fontWidth = 0
        self.fontHeight = 0
        self.strlen = 0
        self.connectParent = False
        self.fromColor = 0xFFFFFFFF
        self.toColor = 0xFFFFFFFF
        super().__init__(fin, pos)
    
    def read(self, fin, start, size):
        super().read(fin, start, size)
        numParams, = unpack('B', fin.read(1))
        if numParams > 0:
            self.font = getResource(fin)
            numParams -= 1
        parentFields = self.fields
        self.fields = ['topColor', 'bottomColor', 'binding', 'fontSpacing', 'fontLeading', 'fontWidth', 'fontHeight', 'strlen']
        parentHeader = self.header
        self.header = Struct('>'+'IIBhhHHH'[:numParams])
        Section.read(self, fin, start, size)
        numParams -= 8
        self.fields = parentFields + self.fields
        self.header = Struct(parentHeader.format + self.header.format[1:])
        self.string = fin.read(self.strlen).decode('shift-jis')
        parentFields = self.fields
        self.fields = ['connectParent', 'fromColor', 'toColor'][:numParams]
        parentHeader = self.header
        self.header = Struct('>'+'?II'[:numParams])
        Section.read(self, fin, start, size)
        numParams -= 3
        self.fields = parentFields + self.fields
        self.header = Struct(parentHeader.format + self.header.format[1:])

class BLayout(BFile):
    sectionHandlers = {
        b'BGN1': Bgn1,
        b'END1': End1,
        b'PIC1': Pic1,
        b'PAN1': Pan1,
        b'INF1': Inf1,
        b'TBX1': Tbx1,
        b'EXT1': Ext1
    }

def parsechunks(chunklist, i=0, indent=0):
    toWrite = "<div>"
    while i < len(chunklist):
        chunk = chunklist[i]
        print(' '*indent+str(chunk))
        if isinstance(chunk, Bgn1):
            htmlout.write(toWrite)
            i = parsechunks(chunklist, i+1, indent+1)
            htmlout.write("</div>")
        elif isinstance(chunk, End1):
            return i
        elif isinstance(chunk, Pan1):
            style = 'style="position: absolute; left: %dpx; top: %dpx; width: %dpx; height: %dpx; visibility: %s'%(chunk.x, chunk.y, chunk.width, chunk.height, ["hidden", "inherit"][chunk.visible])
            if chunk.angle != 0:
                style += '; transform: rotate(%fdeg)'%(chunk.angle*180/0x7FFF)
            if chunk.alpha != 255:
                style += '; opacity: %f'%(chunk.alpha/255)
            style += '"'
            cId = chunk.paneId.replace(b'\0', b'').decode()
            if len(cId) > 0:
                style += ' id="%s"'%(cId)
            if isinstance(chunk, Pic1):
                htmlout.write('<img %s src="../timg/%s">'%(style, chunk.image[1].replace('.bti', '.png')))
            elif isinstance(chunk, Tbx1):
                htmlout.write('<div %s>%s</div>'%(style, chunk.string))
            else:
                toWrite = '<div %s>'%(style)
        i += 1
    return i

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: %s <blo>\n"%sys.argv[0])
        exit(1)

    fin = open(sys.argv[1], 'rb')
    blo = BLayout()
    blo.read(fin)
    fin.close()

    htmlout = open(os.path.splitext(sys.argv[1])[0]+".html", 'w')
    htmlout.write('<html><head><title></title></head><body style="width: %dpx; height: %dpx">'%(blo.inf1.width, blo.inf1.height))
    parsechunks(blo.chunks)
    htmlout.write("</body></html>")
    htmlout.close()

