import struct, array, sys

class ColGroup:
    def readHeader(self, fin):
        self.surfaceId, self.numTriIndices, self.flags, self.unknown3, self.indicesOffset, self.terrainTypesOffset, self.unknownOffset2, self.unknownOffset3 = struct.unpack(">HHHHIIII", fin.read(24))
        self.indexBuffer = array.array('H')
        self.terrainTypes = array.array('B')
        self.tribuf2 = array.array('B')
        self.tribuf3 = array.array('h')
    
    def readBuffers(self, fin):
        fin.seek(self.indicesOffset)
        self.indexBuffer.fromfile(fin, self.numTriIndices*3)
        if sys.byteorder != 'big': self.indexBuffer.byteswap()
        
        fin.seek(self.terrainTypesOffset)
        self.terrainTypes.fromfile(fin, self.numTriIndices)
    
        fin.seek(self.unknownOffset2)
        self.tribuf2.fromfile(fin, self.numTriIndices)
        
        if self.unknownOffset3 != 0:
            fin.seek(self.unknownOffset3)
            self.tribuf3.fromfile(fin, self.numTriIndices)
            if sys.byteorder != 'big': self.tribuf3.byteswap()
        
    def __repr__(self):
        return "surfaceId=%x, ntri=%d, flags=%d"%(self.surfaceId, len(self.indexBuffer)//3, self.flags)

class ColReader:
    def read(self, fin):
        numCoords, coordsOffset, numGroups, groupsOffset = struct.unpack('>IIII', fin.read(16))
        
        assert fin.tell() == groupsOffset
        fin.seek(groupsOffset)
        self.groups = [ColGroup() for i in range(numGroups)]
        for group in self.groups:
            group.readHeader(fin)
        
        assert len({group.surfaceId for group in self.groups}) == len(self.groups)
        
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

