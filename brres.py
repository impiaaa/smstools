import sys
from struct import Struct
from common import BFile, Section
from texture import readTextureData, decodeTexturePIL

class Tex0(Section):
    header = struct.Struct('>L16xHH32x')
    
    def read(self, fin, start, size):
        self.mipmapCount, self.width, self.height = self.header.unpack(fin.read(0x38))
        self.data = readTextureData(fin, self.format, self.width, self.height, mipmapCount=self.mipmapCount)
    
    def export(self, name):
        images = decodeTexturePIL(self.data, self.format, self.width, self.height, mipmapCount=self.mipmapCount)
        for arrayIdx, mips in enumerate(images):
            for mipIdx, im in enumerate(mips):
                im.save(name+str(arrayIdx)+'.png')

class BFont(BFile):
    align = True
    header = Struct('>8sL2xH4xL')
    sectionHandlers = {b'TEX0': Tex0}
    def readHeader(self, fin):
        self.signature, self.fileLength, self.chunkCount, extraHeaderSize = self.header.unpack(fin.read(0x18))
        fin.seek(extraHeaderSize, 1)

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <brres>\n"%sys.argv[0])
    exit(1)

fin = open(sys.argv[1], 'rb')



for chunkNumber in xrange(chunkCount-1):
    chunkstart = fin.tell()
    try: chunk, chunksize = unpack('>4sL', fin.read(8))
    except struct.error:
        warn("File too small for chunk")
        continue
    print hex(fin.tell()), chunk, hex(chunksize)
    if chunk == 'TEX0':
        
        mipData = [None]*mipmapCount
        mipwidth = width
        mipheight = height
        lowResIndex = -1
        if width > height:
            lowResImageWidth = min(16, width)
            lowResImageHeight = (height*lowResImageWidth)/width
        else:
            lowResImageHeight = min(16, height)
            lowResImageWidth = (width*lowResImageHeight)/height
        lowResImageSize = (lowResImageWidth*lowResImageHeight)/2
        for mip in xrange(mipmapCount):
            if format == 13 and mipwidth == lowResImageWidth and mipheight == lowResImageHeight:
                lowResIndex = mip
            vtfImageSize = int((mipwidth*mipheight)*0.5)
            imageSize = int((mipwidth*mipheight)*0.5)
            dest = [0]*vtfImageSize
            for y in xrange(0, mipheight/4, 2):
                for x in xrange(0, mipwidth/4, 2):
                    for dy in xrange(2):
                        for dx in xrange(2):
                            for k in xrange(8):
                                dest[8*((y + dy)*mipwidth/4 + x + dx) + k] = ord(fin.read(1))
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
        mipData.reverse()
        fout = open(hex(fin.tell())+'.vtf', 'wb')
        fout.write("VTF\0")
        fout.write(pack('<LLLHHLHH4x3f4xfLBlBBH', 7, 2, 80, width, height, 0, 1, 0, 1.0, 1.0, 1.0, 1.0, 13, mipmapCount, -1, lowResImageWidth, lowResImageHeight, 1))
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
    fin.seek(((chunkstart+chunksize+3)/4)*4)

fin.close()
