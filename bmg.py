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
        assert chunksize-16 >= size*count, (chunksize, size, count)
        self.inf = [None]*count
        for j in xrange(count):
            if size == 12:
                self.inf[j] = unpack('>LHHL', fin.read(size))
            elif size == 4:
                self.inf[j] = unpack('>L', fin.read(size))
            elif size == 8:
                warn("Unknown format")
                self.inf[j] = unpack('>LL', fin.read(size))
            else:
                raise Exception("Unknown size", size)
        self.inf.sort(key=lambda a: a[0])

class Dat1(Section):
    def read(self, fin, start, size):
        self.data = fin.read(size-8)

class BMessages(BFile):
    sectionHandlers = {b'INF1': Inf1, b'DAT1': Dat1}
    def readHeader(self, fin):
        super(BMessages, self).readHeader(fin)
        assert self.signature == "MESGbmg1", self.signature

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <b lo>\n"%sys.argv[0])
    exit(1)

fin = open(sys.argv[1], 'rb')
bmg = BMessages()
bmg.read(fin)
fin.close()

for i in xrange(chunkCount):
    chunkstart = fin.tell()
    try: chunk, chunksize = unpack('>4sL', fin.read(8))
    except StructError:
        warn("File too small for chunk count of "+str(chunkCount))
        continue
    if chunk == "INF1":
        
    elif chunk == "":
        if size >= 12:
            # subtitle format
            srtout = open(os.path.splitext(sys.argv[1])[0]+".srt", 'w')
            for j, (offset, start, end, unknown) in enumerate(inf):
                srtout.write(u"%d\n"%(j+1))
                srtout.write(u"%02d:%02d:%02d,%03d --> "%frameToHMSMS(start))
                srtout.write(u"%02d:%02d:%02d,%03d\n"%frameToHMSMS(end))
                fin.seek(chunkstart+8+offset)
                if j+1 < len(inf):
                    nextOffset = inf[j+1][0]
                else:
                    nextOffset = chunkstart+chunksize
                srtout.write(fin.read(nextOffset-offset-1).strip('\0').decode('shift-jis').encode('utf-8'))
                srtout.write(u"\n\n")
            srtout.close()
        else:
            txtout = open(os.path.splitext(sys.argv[1])[0]+".txt", 'w')
            for j, indices in enumerate(inf):
                offset = indices[0]
                fin.seek(chunkstart+8+offset)
                if j+1 < len(inf):
                    nextOffset = inf[j+1][0]
                else:
                    nextOffset = chunkstart+chunksize
                txtout.write(fin.read(nextOffset-offset-1).strip('\0').decode('shift-jis').encode('utf-8'))
                txtout.write(u"\n")
            txtout.close()
    fin.seek(chunkstart+chunksize)
