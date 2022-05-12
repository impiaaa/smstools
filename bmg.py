#!/usr/bin/env python

from struct import unpack, Struct
from common import Section, BFile

fpms = 0.02997
def frameToHMSMS(frame):
    totalms = frame/fpms
    ms = totalms%1000
    seconds = (totalms/1000)%60
    minutes = (totalms/60000)%60
    hours = totalms/3600000
    return (hours,minutes,seconds,ms)

class Inf1(Section):
    header = Struct('>HH4x')
    def read(self, fin, start, chunksize):
        count, self.size = self.header.unpack(fin.read(8))
        assert chunksize-16 >= self.size*count, (chunksize, self.size, count)
        self.inf = [None]*count
        for j in range(count):
            if self.size == 24:
                self.inf[j] = unpack('>LHHLLLL', fin.read(self.size))
            elif self.size == 12:
                self.inf[j] = unpack('>LHHL', fin.read(self.size))
            elif self.size == 4:
                self.inf[j] = unpack('>L', fin.read(self.size))
            elif self.size == 8:
                self.inf[j] = unpack('>LL', fin.read(self.size))
            else:
                raise Exception("Unknown size %d" % self.size)
        #self.inf.sort(key=lambda a: a[0])

class Dat1(Section):
    def read(self, fin, start, size):
        self.data = fin.read(size-8)

class BMessages(BFile):
    sectionHandlers = {b'INF1': Inf1, b'DAT1': Dat1}
    def readHeader(self, fin):
        super().readHeader(fin)
        assert self.signature == b'MESGbmg1', self.signature
    def read(self, fin):
        super().read(fin)
        self.strings = [None]*len(self.inf1.inf)
        for i in range(len(self.inf1.inf)):
            offset = self.inf1.inf[i][0]
            end = self.dat1.data.find(b'\0', offset)
            data = self.dat1.data[offset:end]
            self.strings[i] = (data,)+tuple(self.inf1.inf[i][1:])

if __name__ == "__main__":
    import sys
    import os.path
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: %s <bmg>\n"%sys.argv[0])
        exit(1)

    fin = open(sys.argv[1], 'rb')
    bmg = BMessages()
    bmg.read(fin)
    fin.close()

    if bmg.inf1.size == 12:
        # subtitle format
        srtout = open(os.path.splitext(sys.argv[1])[0]+".srt", 'w')
        for data, start, end, unknown in enumerate(bmg.strings):
            srtout.write(u"%d\n"%(j+1))
            srtout.write(u"%02d:%02d:%02d,%03d --> "%frameToHMSMS(start))
            srtout.write(u"%02d:%02d:%02d,%03d\n"%frameToHMSMS(end))
            srtout.write(u"# %x\n"%unknown)
            srtout.write(data.decode('shift-jis'))
            srtout.write(u"\n\n")
        srtout.close()
    else:
        txtout = open(os.path.splitext(sys.argv[1])[0]+".txt", 'wb')
        for data in enumerate(bmg.inf1.inf):
            if isinstance(data, tuple):
                data = data[0]
            txtout.write(data)#.decode('shift-jis'))
            txtout.write(b"\n\n")
        txtout.close()

