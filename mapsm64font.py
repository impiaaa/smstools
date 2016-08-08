import os, shutil, codecs

hiresdir = '/Volumes/ExtraData/smg2/LocalizeData/UsEnglish/LayoutData/Font/MessageFontPieces32x16/'
hiresnames = sorted(os.listdir(hiresdir), key=lambda a: a.rjust(7, '0'))
hashdir = "/Volumes/OS X Home/Users/spenceralves/.local/share/mupen64plus/hires_texture/SUPER MARIO 64/png_all/"

for i, line in enumerate(codecs.open("/Volumes/OS X Home/Users/spenceralves/Desktop/mappings16x8.txt", encoding='utf-8')):
    if len(line) < 38:
        continue
    elif len(line) > 38:
        print "Long line", i+1, repr(line)
        continue
    hashname = line[:35]
    chrnum = ord(line[36])
    if chrnum >= len(hiresnames)+ord(' '): continue
    hiresname = hiresnames[chrnum-ord(' ')]
    if os.path.exists(hashdir+hashname):
        print "Skipping", hiresname, "to", hashname
    else:
        shutil.copyfile(hiresdir+hiresname, hashdir+hashname)
