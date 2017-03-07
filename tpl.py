import sys
from texture import *
from struct import unpack

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <tpl>\n"%sys.argv[0])
    exit(1)

fin = open(sys.argv[1], 'rb')
i = 0
fin.seek(0,2)
endfile = fin.tell()
fin.seek(0)
while fin.tell() < endfile:
    fin.seek(0x14,1)
    height, width, format, offset = unpack('>HHII', fin.read(12))
    print(format, width, height)
    fin.seek(0x20,1)
    data = readTextureData(fin, format, width, height)
    images = decodeTexturePIL(data, format, width, height, 0, None)
    images[0][0].save(os.path.splitext(sys.argv[1])[0]+str(i)+'.png')
    i += 1

fin.close()
