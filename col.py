import struct, array, sys

class ColGroup:
    def readHeader(self, fin):
        self.unknown2, self.numTriIndices, self.unknown3, self.indicesOffset, self.unknownOffset1, self.unknownOffset2, self.unknownOffset3 = struct.unpack(">HHIIIII", fin.read(24))
        self.indexBuffer = array.array('H')
        self.tribuf1 = array.array('B')
        self.tribuf2 = array.array('B')
        self.tribuf3 = array.array('H')
    
    def readBuffers(self, fin):
        fin.seek(self.indicesOffset)
        self.indexBuffer.fromfile(fin, self.numTriIndices*3)
        if sys.byteorder != 'big': self.indexBuffer.byteswap()
        
        fin.seek(self.unknownOffset1)
        self.tribuf1.fromfile(fin, self.numTriIndices)
    
        fin.seek(self.unknownOffset2)
        self.tribuf2.fromfile(fin, self.numTriIndices)
        
        if self.unknownOffset3 > 0:
            fin.seek(self.unknownOffset3)
            self.tribuf3.fromfile(fin, self.numTriIndices)
            if sys.byteorder != 'big': self.tribuf3.byteswap()
        
    def __repr__(self):
        return "ntri=%d, unknown2 = %x, unknown3 = %x"%(len(self.indexBuffer)/3, self.unknown2, self.unknown3)

class ColReader:
    def read(self, fin):
        numCoords, coordsOffset, numGroups, self.unknown0 = struct.unpack('>IIII', fin.read(16))
        assert self.unknown0 == 16
        
        self.groups = [ColGroup() for i in range(numGroups)]
        for group in self.groups:
            group.readHeader(fin)
        
        for i in range(len(self.groups)-1):
            assert self.groups[i+1].unknownOffset1 - self.groups[i].unknownOffset1 == self.groups[i].numTriIndices
            assert self.groups[i+1].unknownOffset2 - self.groups[i].unknownOffset2 == self.groups[i].numTriIndices
        
        assert fin.tell() == coordsOffset
        
        fin.seek(coordsOffset)
        self.vertexBuffer = array.array('f')
        self.vertexBuffer.fromfile(fin, numCoords*3)
        if sys.byteorder != 'big': self.vertexBuffer.byteswap()
        
        for group in self.groups:
            group.readBuffers(fin)
            assert max(group.indexBuffer) < len(self.vertexBuffer)/3, (max(group.indexBuffer), len(self.vertexBuffer))
    
    def __repr__(self):
        return hex(self.unknown0)+'|'+repr(self.groups)

if 0:
    import os
    for dirpath, dirnames, filenames in os.walk("."):
        for name in filenames:
            if not name.endswith(".col"): continue
            fin = open(os.path.join(dirpath, name), 'rb')
            c = ColReader()
            c.read(fin)
            fin.close()
if __name__ == "__main__":
    fin = open(sys.argv[1], 'rb')
    c = ColReader()
    c.read(fin)
    fin.close()
    for g in c.groups: print(g)

