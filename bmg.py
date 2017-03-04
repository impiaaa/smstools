#!/usr/bin/env python

import sys
from struct import unpack, pack, Struct
from warnings import warn
from array import array
import os.path
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
        super(BMessages, self).readHeader(fin)
        assert self.signature == b'MESGbmg1', self.signature

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
    for j, (offset, start, end, unknown) in enumerate(bmg.inf1.inf):
        srtout.write(u"%d\n"%(j+1))
        srtout.write(u"%02d:%02d:%02d,%03d --> "%frameToHMSMS(start))
        srtout.write(u"%02d:%02d:%02d,%03d\n"%frameToHMSMS(end))
        if j+1 < len(bmg.inf1.inf):
            nextOffset = bmg.inf1.inf[j+1][0]
        else:
            nextOffset = len(bmg.dat1.data)
        srtout.write(bmg.dat1.data[offset:bmg.dat1.data.find(b'\0', offset)].decode('shift-jis'))
        srtout.write(u"\n\n")
    srtout.close()
else:
    txtout = open(os.path.splitext(sys.argv[1])[0]+".txt", 'wb')
    for j, indices in enumerate(bmg.inf1.inf):
        offset = indices[0]
        if j+1 < len(bmg.inf1.inf):
            nextOffset = bmg.inf1.inf[j+1][0]
        else:
            nextOffset = len(bmg.dat1.data)
        end = bmg.dat1.data.find(b'\0', offset)
        data = bmg.dat1.data[offset:end]
        txtout.write(data)#.decode('shift-jis'))
        txtout.write(b"\n\n")
    txtout.close()
