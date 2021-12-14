# Common functions and templates for (chunked) Mario/Zelda data files

import sys
import struct
import warnings

class Readable(object):
    def __init__(self, fin=None, pos=None):
        super(Readable, self)
        if fin is not None:
            if pos is not None:
                fin.seek(pos)
            self.read(fin)

class ReadableStruct(Readable): # name???
    @classmethod
    def try_make(cls, fin, pos=None):
        return cls(fin=fin, pos=pos)
    def read(self, fin):
        for field, value in zip(self.fields, self.header.unpack(fin.read(self.header.size))):
            if isinstance(field, str):
                setattr(self, field, value)
            else:
                fieldName, fieldType = field
                setattr(self, fieldName, fieldType(value))
    def write(self, fout):
        fout.write(self.header.pack([getattr(self, field) if isinstance(field, str) else getattr(self, field[0]).value for field in self.fields]))
    def __repr__(self):
        return self.__class__.__name__ + " " + " ".join([(field if isinstance(field, str) else field[0])+"="+repr(getattr(self, (field if isinstance(field, str) else field[0]))) for field in self.fields])

class Section(object):
    def read(self, fin, start, size):
        pass
    def write(self, fout):
        pass

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
    
    def __init__(self, *args, **kwargs):
        super(BFile, self).__init__(*args, **kwargs)
        self.aligned = False
    
    def readHeader(self, fin):
        self.signature, self.fileLength, self.chunkCount, self.svr = self.header.unpack(fin.read(0x20))
    
    def readChunks(self, fin):
        self.chunks = []
        for chunkno in range(self.chunkCount):
            start = fin.tell()
            try: chunkId, size = struct.unpack('>4sL', fin.read(8))
            except struct.error:
                warnings.warn("File too small for chunk count of "+str(self.chunkCount))
                break
            if chunkId in self.sectionHandlers:
                chunk = self.sectionHandlers[chunkId]()
                chunk.read(fin, start, size)
                setattr(self, self.sectionHandlers[chunkId].__name__.lower(), chunk)
                self.chunks.append(chunk)
            else:
                warnings.warn("Unsupported section %r" % chunkId)
            if self.aligned: fin.seek(((start+size+3)/4)*4)
            else: fin.seek(start+size)
    
    def read(self, fin):
        self.readHeader(fin)
        self.readChunks(fin)

    def writeHeader(self, fout):
        fout.write(self.header.pack(self.signature, self.fileLength, self.chunkCount, self.svr))
    
    def writeChunks(self, fout):
        for chunk in self.chunks:
            chunk.write(fout)
