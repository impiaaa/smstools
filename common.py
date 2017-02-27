import sys
import struct
import warnings

class Readable(object):
    def __init__(self, fin=None):
        super(Readable, self)
        if fin is not None: self.read(fin)

class Section(object): pass

def getString(pos, f):
    t = f.tell()
    f.seek(pos)
    if sys.version_info[0] >= 3: ret = bytes()
    else: ret = str()

    c = f.read(1)
    while ord(c) != 0 and len(c) != 0:
        ret += c
        c = f.read(1)

    f.seek(t)

    return ret.decode('shift-jis')

class BFile(Readable):
    header = struct.Struct('>8sLL4s12x')
    def readHeader(self, fin):
        self.signature, self.fileLength, self.chunkCount, svr = self.header.unpack(fin.read(0x20))
    
    def readChunks(self, fin):
        for chunkno in range(self.chunkCount):
            start = fin.tell()
            try: chunkId, size = struct.unpack('>4sL', fin.read(8))
            except struct.error:
                warn("File too small for chunk count of "+str(chunkCount))
                continue
            if chunkId in self.sectionHandlers:
                chunk = self.sectionHandlers[chunkId]
                chunk.read(fin, start, size)
                setattr(self, self.sectionHandlers[chunkId].__name__.lower(), chunk)
            else:
                warnings.warn("Unsupported section %r" % chunk)
            fin.seek(start+size)
    
    def read(self, fin):
        self.readHeader(fin)
        self.readChunks(fin)
