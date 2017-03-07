# real editor here http://kuribo64.net/board/thread.php?id=126&page=2
# spktable.bct and metable.bmt look similar; this code supports reading strings from them

import sys
from struct import unpack, Struct

def readString(fin):
    s = ''
    while True:
        c = fin.read(1)
        if c == '\0': break
        elif c == '': raise Exception("EOF found while reading string")
        s += c
    return s.decode('shift-jis')

def printHex(s):
    for i in range(0, len(s), 4):
        print ''.join(['%02X'%ord(x) for x in s[i:min(i+4, len(s))]]),

fin = open(sys.argv[1], 'rb')
fin.seek(0, 2)
fileSize = fin.tell()
fin.seek(0)
count, fieldCount, offset, itemLen = unpack('>IIII', fin.read(16))
isBMT = itemLen == 0

if isBMT:
    # BMT
    fieldCount = count
    count = 1
    itemLen = 4*fieldCount

print fieldCount, "fields"
fields = []
rowStructFmt = '>'
fieldTypeFormats = ['I', 'I', 'f', 'i', 'h', 'b', 'I', 'I']
fieldTypeSizes =   [  4,   4,   4,   4,   2,   1,   4,   4]
for i in range(fieldCount):
    if isBMT:
        fieldId, = unpack('>Q', fin.read(8))
        fieldOffset, fieldType = i*4, 6
    else:
        fieldId, fieldOffset, fieldType = unpack('>I4xHH', fin.read(12))
    fields.append((fieldId, fieldOffset, fieldType))
fields.sort(key=lambda a: a[1])
currentFieldOffset = 0
for (fieldId, fieldOffset, fieldType) in fields:
    assert currentFieldOffset == fieldOffset
    print hex(fieldId), fieldType
    rowStructFmt += fieldTypeFormats[fieldType]
    currentFieldOffset += fieldTypeSizes[fieldType]
assert fin.tell() <= offset
rowStruct = Struct(rowStructFmt)
if rowStruct.size < itemLen:
    rowStructFmt += str(itemLen-rowStruct.size)+'x'
    rowStruct = Struct(rowStructFmt)

if isBMT:
    strTableOffset = 0
else:
    strTableOffset = offset+(count*itemLen)
print "string table is at 0x%X"%strTableOffset

print count, "items,", itemLen, "bytes each"
fin.seek(offset)
for i in range(count):
    row = rowStruct.unpack(fin.read(itemLen))
    nextEntry = fin.tell()
    for val, (fieldId, fieldOffset, fieldType) in zip(row, fields):
        if fieldType == 6: # string
            if val == 0xFFFFFFFF:
                val = None
            else:
                val = getString(val+strTableOffset, fin)
        elif fieldType in (1, 7):
            val = None
        print repr(val)+",",
    print
    fin.seek(nextEntry)

fin.close()