import struct, sys

COMPRESSED_RGB_S3TC_DXT1_EXT  = 0x83F0
COMPRESSED_RGBA_S3TC_DXT5_EXT = 0x83F3

fin = open(sys.argv[1], 'rb')
identifier, endianness = struct.unpack('12sI', fin.read(16))
assert identifier == bytes([0xAB, 0x4B, 0x54, 0x58, 0x20, 0x31, 0x31, 0xBB, 0x0D, 0x0A, 0x1A, 0x0A]), identifier.hex()
assert endianness == 0x04030201, hex(endianness)
glType, glTypeSize, glFormat, glInternalFormat, glBaseInternalFormat, pixelWidth, pixelHeight, pixelDepth, numberOfArrayElements, numberOfFaces, numberOfMipmapLevels, bytesOfKeyValueData = struct.unpack('IIIIIIIIIIII', fin.read(48))
assert glType == 0, glType
assert glFormat == 0, glFormat
assert glInternalFormat == COMPRESSED_RGB_S3TC_DXT1_EXT, glInternalFormat

fout = open(sys.argv[1][:sys.argv[1].rfind('.')]+"-dxt5.ktx", 'wb')
fout.write(struct.pack('12sI', identifier, endianness))
fout.write(struct.pack('IIIIIIIIIIII', glType, glTypeSize, glFormat, COMPRESSED_RGBA_S3TC_DXT5_EXT, glBaseInternalFormat, pixelWidth, pixelHeight, pixelDepth, numberOfArrayElements, numberOfFaces, numberOfMipmapLevels, bytesOfKeyValueData))
fout.write(fin.read(bytesOfKeyValueData))

hasTransparency = False
for mipmap_level in range(max(1, numberOfMipmapLevels)):
    imageSize, = struct.unpack('I', fin.read(4))
    fout.write(struct.pack('I', imageSize*2))
    for i in range(imageSize//8):
        color0, color1, pixels = struct.unpack('HHI', fin.read(8))
        alphas = 0
        if color0 > color1:
            for j in range(16): alphas |= 1<<(j*3)
            #print('o', bin(alphas))
        else:
            for j in range(16): alphas |= ((pixels>>(j*2))&3 != 3)<<(j*3)
            #print('x', bin(alphas))
            hasTransparency = True
        fout.write(struct.pack('BB3HHHI', 0, 255, alphas&0xFFFF, (alphas>>16)&0xFFFF, alphas>>32, color0, color1, pixels))
if not hasTransparency:
    print("Warning:", sys.argv[1], "doesn't have any transparent pixels. Converting is a waste", file=sys.stderr)
fout.close()
fin.close()
