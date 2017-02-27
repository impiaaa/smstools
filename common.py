import sys

class Readable(object):
    def __init__(self, fin=None):
        super()
        if fin is not None: self.read(fin)

class Section(object): pass

def getString(pos, f):
    t = f.tell()
    f.seek(pos)
    if sys.version_info[0] >= 3: ret = bytes()
    else: ret = str()

    c = f.read(1)
    while ord(c) != 0 and len(c) != 0:
        ret += c
        c = f.read(1)

    f.seek(t)

    return ret.decode('shift-jis')

class BFile(Readable):
    header = Struct('>8sLL4s12x')
    def read(self, fin):
        signature, fileLength, chunkCount, svr = self.header.unpack(fin.read(0x20))
        if signature[:4] == "bres": fin.seek(0xa0, 1)

        for chunkno in range(chunkCount):
            start = fin.tell()
            try: chunk, size = unpack('>4sL', fin.read(8))
            except StructError:
                warn("File too small for chunk count of "+str(chunkCount))
                continue
