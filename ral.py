#!/usr/bin/env python

from struct import unpack
import sys
from common import getString

if len(sys.argv) != 2:
	sys.stderr.write("Usage: %s scene.ral\n"%sys.argv[0])
	exit(1)

fin = open(sys.argv[1], 'rb')
while True:
    sectionCount, strOffset, sectionOffset = unpack('>III', fin.read(12))
    if sectionCount == 0: break
    sectionSize = sectionCount * 68
    name = getString(strOffset, fin)
    print(u"%s @ 0x%X+0x%X"%(name, sectionOffset, sectionSize))
fin.close()
