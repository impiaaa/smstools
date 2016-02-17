import sys, os

functions = {}
symbolfile = open(sys.argv[2])

for line in symbolfile:
  if not line.startswith('  0'): continue
  sline = line.split()
  starting, size, vaddr, x, name, obj = sline[:6]
  if x != '4': continue
  if len(sline) > 6: src = sline[6]
  functions[int(vaddr, 16)] = name

symbolfile.close()

fin = open(sys.argv[1])
splitext = os.path.splitext(sys.argv[1])
fout = open(splitext[0]+'_sym'+splitext[1], 'w')

for line in fin:
  if line[-13:-9] == '->0x':
    addr = int(line[-9:-1], 16)
    if addr in functions:
      fout.write(line[:-11]+functions[addr]+'\n')
    else:
      fout.write(line)
  else:
    fout.write(line)

fin.close()
fout.close()
