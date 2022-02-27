import sys, struct

def dumpsection(name, fin, offset, size):
    oldpos = fin.tell()
    fin.seek(offset)
    open(name, 'wb').write(fin.read(size))
    fin.seek(oldpos)
    
if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <aaf>\n"%sys.argv[0])
    exit(1)

fin = open(sys.argv[1], 'rb')

i = 0

while True:
    s = fin.read(4)
    if len(s) == 0: break
    chunkid, = struct.unpack('>I', s)
    if chunkid in (1, 4, 5, 6, 7):
        offset, size = struct.unpack('>II4x', fin.read(12))
        if chunkid == 4: name = "BARC"
        elif chunkid == 5: name = "strm"
        else: name = str(chunkid)
        print(i, chunkid, hex(offset), hex(size))
        dumpsection(name+"-"+str(i)+".bin", fin, offset, size)
        i += 1
    elif chunkid in (2, 3):
        while True:
            s = fin.read(4)
            if len(s) == 0: break
            offset, = struct.unpack('>I', s)
            if offset == 0: break
            size, id = struct.unpack('>II', fin.read(8))
            if chunkid == 3: name = "WSYS"
            elif chunkid == 2: name = "IBNK"
            else: name = str(chunkid)
            print(i, chunkid, hex(offset), hex(size))
            dumpsection(name+"-"+str(id)+"-"+str(i)+".bin", fin, offset, size)
            i += 1
    elif chunkid == 0:
        break

fin.close()
