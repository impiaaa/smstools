GX_TF_I4 = 0x0
GX_TF_I8 = 0x1
GX_TF_IA4 = 0x2
GX_TF_IA8 = 0x3
GX_TF_RGB565 = 0x4
GX_TF_RGB5A3 = 0x5
GX_TF_RGBA8 = 0x6
GX_TF_C4 = 0x8
GX_TF_C8 = 0x9
GX_TF_C14X2 = 0xA
GX_TF_CMPR = 0xE # S3TC/DXT

formatBytesPerPixel = {
GX_TF_I4:   0.5,
GX_TF_I8:     1,
GX_TF_IA4:    1,
GX_TF_IA8:    2,
GX_TF_RGB565: 2,
GX_TF_RGB5A3: 1,
GX_TF_RGBA8:  1,
GX_TF_C4:   0.5,
GX_TF_C8:     1,
GX_TF_C14X2:  2,
GX_TF_CMPR: 0.5
}

formatBlockWidth = {
GX_TF_I4:     8,
GX_TF_I8:     8,
GX_TF_IA4:    8,
GX_TF_IA8:    4,
GX_TF_RGB565: 4,
GX_TF_RGB5A3: 4,
GX_TF_RGBA8:  4,
GX_TF_C4:     8,
GX_TF_C8:     8,
GX_TF_C14X2:  4,
GX_TF_CMPR:   8
}

formatBlockHeight = {
GX_TF_I4:     8,
GX_TF_I8:     4,
GX_TF_IA4:    4,
GX_TF_IA8:    4,
GX_TF_RGB565: 4,
GX_TF_RGB5A3: 4,
GX_TF_RGBA8:  4,
GX_TF_C4:     8,
GX_TF_C8:     4,
GX_TF_C14X2:  4,
GX_TF_CMPR:   8
}
