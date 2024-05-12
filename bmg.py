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
    fields = ["count_", "size", "someMessageIndex"]
    entryStructs = [Struct('>LHHLLLL'), Struct('>LHHB3x'), Struct('>L'), Struct('>LL')]
    sizeToStruct = {s.size: s for s in entryStructs}
    countToSize = {7: 24, 4: 12, 1: 4, 2: 8}
    def read(self, fin, start, chunksize):
        super().read(fin, start, chunksize)
        assert chunksize-16 >= self.size*self.count_, (chunksize, self.size, self.count_)
        if self.size not in self.sizeToStruct:
            raise Exception("Unknown size %d" % self.size)
        entryStruct = self.sizeToStruct[self.size]
        self.inf = [entryStruct.unpack(fin.read(self.size)) for j in range(self.count_)]
                
    def write(self, fout):
        self.count_ = len(self.inf)
        super().write(fout)
        entryStruct = self.sizeToStruct[self.size]
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
            end = self.inf1.inf[i+1][0]-1 if i < len(self.inf1.inf)-1 else len(self.dat1.data)-1
            data = self.dat1.data[offset:end]
            self.strings[i] = (data,)+tuple(self.inf1.inf[i][1:])
    def write(self, fout):
        self.inf1.inf = []
        self.dat1 = Dat1()
        self.dat1.chunkId = b'DAT1'
        self.dat1.data = b'\0'
        self.chunks = [self.inf1, self.dat1]
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
    
    basename, ext = os.path.splitext(sys.argv[1])
    
    if ext.casefold() == '.srt':
        import re
        timecodeFormat = re.compile("(\d{2}):(\d{2}):(\d{2}),(\d{3})")
        fin = open(sys.argv[1])
        bmg = BMessages()
        bmg.strings = []
        bmg.inf1 = Inf1()
        bmg.inf1.chunkId = b'INF1'
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
        fin.close()
        bmg.write(open(basename+".bmg", 'wb'))
    elif ext.casefold() == '.bmg':
        fin = open(sys.argv[1], 'rb')
        bmg = BMessages()
        bmg.read(fin)
        fin.close()

        if bmg.inf1.size == 12 and (len(bmg.strings) == 0 or bmg.strings[0][2] > bmg.strings[0][1]):
            # subtitle format
            srtout = open(basename+".srt", 'w', encoding='utf_8_sig')
            for j, (data, start, end, soundIndex) in enumerate(bmg.strings):
                assert soundIndex == 69, soundIndex
                srtout.write(u"%d\n"%(j+1))
                srtout.write(u"%02d:%02d:%02d,%03d --> "%frameToHMSMS(start))
                srtout.write(u"%02d:%02d:%02d,%03d\n"%frameToHMSMS(end))
                srtout.write(data.decode('shift-jis'))
                srtout.write(u"\n\n")
            srtout.close()
        else:
            import csv
            csvout = open(basename+".csv", 'w', encoding='utf_8_sig')
            writer = csv.writer(csvout)
            for data in bmg.strings:
                writer.writerow([data[0].decode('shift-jis', 'backslashreplace').replace('\0', r'\x00')]+list(map(str, data[1:])))
            csvout.close()
    elif ext.casefold() == '.csv':
        import re, csv
        hexescapes = re.compile(rb"\\x([0-9a-fA-F][0-9a-fA-F])")
        fin = open(sys.argv[1], encoding='utf_8_sig')
        bmg = BMessages()
        bmg.strings = []
        bmg.inf1 = Inf1()
        bmg.inf1.chunkId = b'INF1'
        bmg.inf1.size = 0
        bmg.inf1.someMessageIndex = 0
        for line in csv.reader(fin):
            bmg.inf1.size = max(bmg.inf1.size, Inf1.countToSize[len(line)])
            enc = line[0].encode('shift-jis')
            matchh = hexescapes.search(enc)
            while matchh is not None:
                enc = enc[:matchh.start()] + bytes([int(matchh[1], 16)]) + enc[matchh.end():]
                matchh = hexescapes.search(enc)
            bmg.strings.append((enc,)+tuple(map(int, line[1:])))
        fin.close()
        bmg.write(open(basename+".bmg", 'wb'))

