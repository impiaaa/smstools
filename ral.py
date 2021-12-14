#!/usr/bin/env python

from struct import Struct, unpack
from common import getString, Readable, ReadableStruct

class Keyframe(ReadableStruct):
    header = Struct('>hhhh2xhhhhh')
    fields = ["x", "y", "z", "connectionCount", "unk3", "pitch", "yaw", "roll", "speed"]
    def read(self, fin):
        super().read(fin)
        self.connections = unpack('>8h', fin.read(8*2))[:self.connectionCount]
        self.periods = unpack('>8f', fin.read(8*4))[:self.connectionCount]
    def __repr__(self):
        return super().__repr__()+' connections='+repr(self.connections)+' periods='+repr(self.periods)

class RalSection:
    def readHeader(self, fin):
        self.keyframeCount, strOffset, self.sectionOffset = unpack('>III', fin.read(12))
        if self.keyframeCount == 0:
            return
        self.name = getString(strOffset, fin)
    def readData(self, fin):
        fin.seek(self.sectionOffset)
        self.keyframes = []
        for i in range(self.keyframeCount):
            self.keyframes.append(Keyframe(fin))

class RalFile(Readable):
    def read(self, fin):
        self.sections = []
        while True:
            s = RalSection()
            s.readHeader(fin)
            if s.keyframeCount == 0:
                break
            self.sections.append(s)
        for s in self.sections:
            s.readData(fin)

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

