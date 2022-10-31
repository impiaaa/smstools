import struct, sys, os.path

fin = open(sys.argv[1], 'rb')
tag, version, maxBufferSize, maxAudioSamples, fps, numFrames, firstFrameSize, dataSize, componentDataOffset, offsetsDataOffset, firstFrameOffset, lastFrameOffset = struct.unpack(">4sIIIfIIIIIII", fin.read(12*4))
assert tag == b"THP\0", tag
assert offsetsDataOffset == 0, offsetsDataOffset

fin.seek(componentDataOffset)
numComponents, = struct.unpack(">I", fin.read(4))
componentTypes = struct.unpack(">16B", fin.read(16))
componentTypes = componentTypes[:numComponents]

streamInfos = [None]*numComponents
maxWidth = maxHeight = 0
for i, streamType in enumerate(componentTypes):
    if streamType == 0:
        width, height = struct.unpack(">II", fin.read(8))
        if version >= 0x00011000:
            struct.unpack(">I", fin.read(4))
        streamInfos[i] = (width, height)
        maxWidth = max(maxWidth, width)
        maxHeight = max(maxHeight, height)

class Chunk:
    def __init__(self, f, fourcc):
        self.f = f
        self.fourcc = fourcc
        self.pos = f.tell()
        self.len = 0
        self.write(fourcc)
        self.write(b'\0\0\0\0')
        assert self.len == 8
    def write(self, data):
        self.f.write(data)
        self.len = max(self.len, self.tell())
    def fix(self):
        t = self.tell()
        self.seek(4)
        self.write(struct.pack("<I", self.len-8))
        self.seek(t)
    def seek(self, pos):
        self.f.seek(self.pos+pos)
    def tell(self):
        return self.f.tell()-self.pos

fout = open(os.path.splitext(sys.argv[1])[0]+".avi", 'wb')
avi = Chunk(fout, b'RIFF')
avi.write(b'AVI ')
hdrl = Chunk(avi, b'LIST')
hdrl.write(b'hdrl')
hdrl.write(struct.pack('<4sIIIIIIIIIIIIIII',
    b'avih', # fcc
    56, # cb
    int(1000000/fps), # dwMicroSecPerFrame
    int(maxBufferSize*fps), # dwMaxBytesPerSec
    0, # dwPaddingGranularity
    0x00910, # dwFlags
    numFrames, # dwTotalFrames
    0, # dwInitialFrames
    numComponents, # dwStreams
    0x100000, # dwSuggestedBufferSize
    maxWidth, # dwWidth
    maxHeight, # dwHeight
    0, 0, 0, 0 # dwReserved
))
for streamType, streamInfo in zip(componentTypes, streamInfos):
    strl = Chunk(hdrl, b'LIST')
    strl.write(b'strl')
    if streamType == 0:
        width, height = streamInfo
        strh = Chunk(strl, b'strh')
        strh.write(struct.pack('<4s4sIHHIIIIIIII4H',
            b'vids', # fccType
            b'MJPG', # fccHandler
            0, # dwFlags
            0, # wPriority
            0, # wLanguage
            0, # dwInitialFrames
            0x80000, # dwScale
            int(fps*0x80000), # dwRate
            0, # dwStart
            numFrames, # dwLength
            maxBufferSize, # dwSuggestedBufferSize
            0xFFFFFFFF, # dwQuality
            0, # dwSampleSize
            0, 0, width, height # rcFrame
        ))
        strh.fix()
        strf = Chunk(strl, b'strf')
        strf.write(struct.pack('<IiiHH4sIiiHHI',
            0x28, # biSize
            width, # biWidth
            height, # biHeight
            1, # biPlanes
            24, # biBitCount
            b'MJPG', # biCompression
            int((width*height*24+7)/8), # biSizeImage
            0, # biXPelsPerMeter
            0, # biYPelsPerMeter
            0, # biClrUsed
            0, # biClrImportant
            0
        ))
        strf.fix()
    strl.fix()
hdrl.fix()

movi = Chunk(avi, b'LIST')
movi.write(b'movi')

fin.seek(firstFrameOffset)
totalSize = firstFrameSize

chunkPositions = [None]*numFrames

for i in range(numFrames):
    nextOffset = fin.tell()+totalSize
    nextTotalSize, prevTotalSize, imageSize = struct.unpack(">III", fin.read(12))
    if 1 in componentTypes:
        audioSize, = struct.unpack(">I", fin.read(4))
    totalSize = nextTotalSize
    frameData = fin.read(imageSize)
    startImage = frameData.find(b"\xff\xda")+2
    endImage = frameData.rfind(b"\xff\xd9")
    jpegData = frameData[:startImage]+(frameData[startImage:endImage].replace(b"\xff", b"\xff\x00"))+frameData[endImage:]
    maxBufferSize = max(maxBufferSize, len(jpegData))
    fin.seek(nextOffset)
    
    chunkPositions[i] = (movi.tell()-8, len(jpegData))
    dc = Chunk(movi, b'00dc')
    dc.write(jpegData)
    dc.fix()
    if movi.tell()%2 != 0: movi.write(b'\0')

movi.fix()

idx1 = Chunk(avi, b'idx1')
for pos, sz in chunkPositions:
    idx1.write(struct.pack('<4sIII', b'00dc', 0x10, pos, sz))
idx1.fix()

avi.fix()

fin.close()
fout.close()

