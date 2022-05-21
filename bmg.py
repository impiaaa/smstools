#!/usr/bin/env python

from struct import unpack, Struct
from common import Section, BFile

fpms = 0.03/1.001
mspf = 1.001/0.03
def frameToHMSMS(frame):
    totalms = round(frame*mspf)
    ms = totalms%1000
    seconds = (totalms//1000)%60
    minutes = (totalms//60000)%60
    hours = totalms//3600000
    return (hours,minutes,seconds,ms)

def HMSMStoFrame(hours, minutes, seconds, ms):
    totalms = hours*3600000+minutes*60000+seconds*1000+ms
    return round(totalms*fpms)

class Inf1(Section):
    header = Struct('>HHH2x')
    entryStructs = {24: Struct('>LHHLLLL'), 12: Struct('>LHHB3x'), 4: Struct('>L'), 8: Struct('>LL')}
    def read(self, fin, start, chunksize):
        count, self.size, self.someMessageIndex = self.header.unpack(fin.read(8))
        assert chunksize-16 >= self.size*count, (chunksize, self.size, count)
        if self.size not in self.entryStructs:
            raise Exception("Unknown size %d" % self.size)
        entryStruct = self.entryStructs[self.size]
        self.inf = [entryStruct.unpack(fin.read(self.size)) for j in range(count)]
                
    def write(self, fout):
        fout.write(self.header.pack(len(self.inf), self.size, self.someMessageIndex))
        entryStruct = self.entryStructs[self.size]
        for entry in self.inf:
            fout.write(entryStruct.pack(*entry))

class Dat1(Section):
    def read(self, fin, start, size):
        self.data = fin.read(size-8)
    def write(self, fout):
        fout.write(self.data)

class BMessages(BFile):
    sectionHandlers = {b'INF1': Inf1, b'DAT1': Dat1}
    def readHeader(self, fin):
        super().readHeader(fin)
        assert self.signature == b'MESGbmg1', self.signature
    def writeHeader(self, fout):
        self.signature = b'MESGbmg1'
        self.svr = b'\0\0\0\0'
        super().writeHeader(fout)
    def read(self, fin):
        super().read(fin)
        self.strings = [None]*len(self.inf1.inf)
        for i in range(len(self.inf1.inf)):
            offset = self.inf1.inf[i][0]
            end = self.dat1.data.find(b'\0', offset)
            data = self.dat1.data[offset:end]
            self.strings[i] = (data,)+tuple(self.inf1.inf[i][1:])
    def write(self, fout):
        self.inf1.inf = []
        bmg.dat1 = Dat1()
        self.dat1.data = b'\0'
        bmg.chunks = [bmg.inf1, bmg.dat1]
        for entry in self.strings:
            data = entry[0]
            offset = len(self.dat1.data)
            self.inf1.inf.append((offset,)+(entry[1:]))
            self.dat1.data += data+b'\0'
        super().write(fout)

if __name__ == "__main__":
    import sys
    import os.path
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: %s <bmg/srt>\n"%sys.argv[0])
        exit(1)
    
    if sys.argv[1].casefold().endswith('.srt'):
        import re
        timecodeFormat = re.compile("(\d{2}):(\d{2}):(\d{2}),(\d{3})")
        fin = open(sys.argv[1])
        bmg = BMessages()
        bmg.strings = []
        bmg.inf1 = Inf1()
        bmg.inf1.size = 12
        bmg.inf1.someMessageIndex = 0
        counter = fin.readline()
        while True:
            if counter == '': break
            assert counter.rstrip().isdigit()
            times = fin.readline().rstrip()
            startTime, endTime = times.split(" --> ")
            startFrame = HMSMStoFrame(*map(int, timecodeFormat.match(startTime).groups()))
            endFrame = HMSMStoFrame(*map(int, timecodeFormat.match(endTime).groups()))
            data = ''
            while True:
                line = fin.readline()
                if line.rstrip().isdigit() or line == '':
                    counter = line
                    break
                data += line
            data = data[:-2]
            bmg.strings.append((data.encode('shift-jis'), startFrame, endFrame, 69))
        bmg.write(open(os.path.splitext(sys.argv[1])[0]+".bmg", 'wb'))
    else:
        fin = open(sys.argv[1], 'rb')
        bmg = BMessages()
        bmg.read(fin)
        fin.close()

        if bmg.inf1.size == 12 and (len(bmg.strings) == 0 or bmg.strings[0][2] > bmg.strings[0][1]):
            # subtitle format
            srtout = open(os.path.splitext(sys.argv[1])[0]+".srt", 'w', encoding='utf_8_sig')
            for j, (data, start, end, soundIndex) in enumerate(bmg.strings):
                assert soundIndex == 69, soundIndex
                srtout.write(u"%d\n"%(j+1))
                srtout.write(u"%02d:%02d:%02d,%03d --> "%frameToHMSMS(start))
                srtout.write(u"%02d:%02d:%02d,%03d\n"%frameToHMSMS(end))
                srtout.write(data.decode('shift-jis'))
                srtout.write(u"\n\n")
            srtout.close()
        else:
            # TODO: find a more appropriate format
            txtout = open(os.path.splitext(sys.argv[1])[0]+".txt", 'wb')
            for data in bmg.strings:
                if isinstance(data, tuple):
                    data = data[0]
                txtout.write(data)#.decode('shift-jis'))
                txtout.write(b"\n\n")
            txtout.close()

