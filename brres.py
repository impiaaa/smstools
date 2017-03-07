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
        
        fout = open(name+".dds", 'wb')
        decodeTextureDDS(fout, self.data, self.format, self.width, self.height, 0, None, self.mipmapCount)
        fout.close()

class BRres(BFile):
    aligned = True
    header = Struct('>8sL2xH4xL')
    sectionHandlers = {b'TEX0': Tex0}
    def readHeader(self, fin):
        self.signature, self.fileLength, self.chunkCount, extraHeaderSize = self.header.unpack(fin.read(0x18))
        fin.seek(extraHeaderSize, 1)

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <brres>\n"%sys.argv[0])
    exit(1)

fin = open(sys.argv[1], 'rb')
brres = BRres()
brres.read(fin)
fin.close()
brres.tex0.export(os.path.splitext(sys.argv[1])[0])
