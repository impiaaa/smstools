#!/usr/bin/env python

from struct import Struct, pack, unpack
from common import getString, Readable, ReadableStruct, alignOffset, alignFile

class Keyframe(ReadableStruct):
    header = Struct('>hhhh2xhhhhh')
    fields = ["x", "y", "z", "connectionCount", "unk3", "pitch", "yaw", "roll", "speed"]
    def read(self, fin):
        super().read(fin)
        self.connections = unpack('>8h', fin.read(8*2))[:self.connectionCount]
        self.periods = unpack('>8f', fin.read(8*4))[:self.connectionCount]
        self.connectionCount = None
    def write(self, fout):
        if len(self.connections) != len(self.periods):
            raise ValueError("Connection count %d does not match period count %d"%(len(self.connections), len(self.periods)))
        if len(self.connections) > 8:
            raise ValueError("%d is more than 8 connections"%len(self.connections))
        self.connectionCount = len(self.connections)
        super().write(fout)
        fout.write(pack('>8h', *(self.connections+(0,)*(8-self.connectionCount))))
        fout.write(pack('>8f', *(self.periods+(0,)*(8-self.connectionCount))))
    def __repr__(self):
        return super().__repr__()+' connections='+repr(self.connections)+' periods='+repr(self.periods)

class RalSection(ReadableStruct):
    header = Struct('>III')
    fields = ["keyframeCount", "strOffset", "sectionOffset"]
    def read(self, fin):
        super().read(fin)
        if self.keyframeCount == 0:
            return
        self.name = getString(self.strOffset, fin)
        self.strOffset = None
    def readData(self, fin):
        fin.seek(self.sectionOffset)
        self.keyframes = []
        for i in range(self.keyframeCount):
            self.keyframes.append(Keyframe(fin))
        self.sectionOffset = None
        self.keyframeCount = None
    def write(self, fout):
        self.keyframeCount = len(self.keyframes)
        super().write(fout)

class RalFile(Readable):
    def read(self, fin):
        self.sections = []
        while True:
            s = RalSection()
            s.read(fin)
            if s.keyframeCount == 0:
                break
            self.sections.append(s)
        for s in self.sections:
            s.readData(fin)
    def write(self, fout):
        offset = RalSection.header.size*(len(self.sections)+1)
        for s in self.sections:
            s.strOffset = offset
            offset += len(s.name.encode('shift-jis'))+1
        offset = alignOffset(offset)
        for s in self.sections:
            s.sectionOffset = offset
            offset += (Keyframe.header.size+8*2+8*4)*len(s.keyframes)
        
        for s in self.sections:
            s.write(fout)
        fout.write(b'\0'*RalSection.header.size)
        for s in self.sections:
            fout.write(s.name.encode('shift-jis')+b'\0')
        alignFile(fout)
        for s in self.sections:
            for k in s.keyframes:
                k.write(fout)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
	    sys.stderr.write("Usage: %s scene.ral\n"%sys.argv[0])
	    exit(1)

    fin = open(sys.argv[1], 'rb')
    r = RalFile(fin)
    for s in r.sections:
        print(s.name)
        for k in s.keyframes:
            print(k)
        print()
    fin.close()

