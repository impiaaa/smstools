# Common functions and templates for (chunked) Mario/Zelda data files

import io
import sys
import struct
import warnings
from array import array
from enum import Enum

class Readable(object):
    def __init__(self, fin=None, pos=None):
        super().__init__()
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
    def as_tuple(self):
        return tuple(getattr(self, field) if isinstance(field, str) else getattr(self, field[0]).value if isinstance(getattr(self, field[0]), Enum) else int(getattr(self, field[0])) for field in self.fields)
    def write(self, fout):
        fout.write(self.header.pack(*self.as_tuple()))
    def __repr__(self):
        return self.__class__.__name__ + " " + " ".join([(field if isinstance(field, str) else field[0])+"="+repr(getattr(self, (field if isinstance(field, str) else field[0]))) for field in self.fields])
    def __hash__(self):
        return hash(self.as_tuple())

class Section(ReadableStruct):
    def read(self, fin, start, size):
        super().read(fin)

def swapArray(a):
    if sys.byteorder == 'little':
        b = array(a.typecode, a)
        b.byteswap()
        return b
    else:
        return a

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
        self.aligned = False
        super().__init__(*args, **kwargs)
    
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
                className = self.sectionHandlers[chunkId].__name__
                setattr(self, className[0].lower()+className[1:], chunk)
                setattr(self, chunkId.decode().lower(), chunk)
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
            chunkId = type(chunk).__name__.upper().encode()
            buffer = io.BytesIO()
            chunk.write(buffer)
            buffer.write(b'\0'*((32-(buffer.tell()+8))%32))
            data = buffer.getvalue()
            fout.write(struct.pack('>4sL', chunkId, len(data)+8))
            fout.write(data)
    
    def write(self, fout):
        buffer = io.BytesIO()
        self.writeChunks(buffer)
        data = buffer.getvalue()
        self.fileLength = len(data)+self.header.size
        self.chunkCount = len(self.chunks)
        self.writeHeader(fout)
        fout.write(data)

def calcKeyCode(name):
    if isinstance(name, str):
        name = name.encode('shift-jis')
    x = 0
    for c in name:
        x = (c + x*3)&0xFFFF
    return x

