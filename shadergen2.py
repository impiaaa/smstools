from bmd import *

class ShaderWriter:
    def __init__(self, file):
        self.file = file
        self.indent = 0
    
    def writeLine(self, line):
        self.file.write('    '*self.indent)
        self.file.write(line)
        self.file.write('\n')
    
    def __enter__(self):
        self.file.write('    '*self.indent)
        self.file.write('{\n')
        self.indent += 1
    
    def __exit__(self, type, value, traceback):
        self.indent -= 1
        self.file.write('    '*self.indent)
        self.file.write('}\n')

tev_ksel_table_c = {
    TevKColorSel.CONST_1: "(fixed3)(8.0/8.0)",
    TevKColorSel.CONST_7_8: "(fixed3)(7.0/8.0)",
    TevKColorSel.CONST_3_4: "(fixed3)(6.0/8.0)",
    TevKColorSel.CONST_5_8: "(fixed3)(5.0/8.0)",
    TevKColorSel.CONST_1_2: "(fixed3)(4.0/8.0)",
    TevKColorSel.CONST_3_8: "(fixed3)(3.0/8.0)",
    TevKColorSel.CONST_1_4: "(fixed3)(2.0/8.0)",
    TevKColorSel.CONST_1_8: "(fixed3)(1.0/8.0)",
    TevKColorSel.K0: "_TevKColor0.rgb",
    TevKColorSel.K0_R: "_TevKColor0.rrr",
    TevKColorSel.K0_G: "_TevKColor0.ggg",
    TevKColorSel.K0_B: "_TevKColor0.bbb",
    TevKColorSel.K0_A: "_TevKColor0.aaa",
    TevKColorSel.K1: "_TevKColor1.rgb",
    TevKColorSel.K1_R: "_TevKColor1.rrr",
    TevKColorSel.K1_G: "_TevKColor1.ggg",
    TevKColorSel.K1_B: "_TevKColor1.bbb",
    TevKColorSel.K1_A: "_TevKColor1.aaa",
    TevKColorSel.K2: "_TevKColor2.rgb",
    TevKColorSel.K2_R: "_TevKColor2.rrr",
    TevKColorSel.K2_G: "_TevKColor2.ggg",
    TevKColorSel.K2_B: "_TevKColor2.bbb",
    TevKColorSel.K2_A: "_TevKColor2.aaa",
    TevKColorSel.K3: "_TevKColor3.rgb",
    TevKColorSel.K3_R: "_TevKColor3.rrr",
    TevKColorSel.K3_G: "_TevKColor3.ggg",
    TevKColorSel.K3_B: "_TevKColor3.bbb",
    TevKColorSel.K3_A: "_TevKColor3.aaa"
}
tev_ksel_table_a = {
    TevKColorSel.CONST_1: "8.0/8.0",
    TevKColorSel.CONST_7_8: "7.0/8.0",
    TevKColorSel.CONST_3_4: "6.0/8.0",
    TevKColorSel.CONST_5_8: "5.0/8.0",
    TevKColorSel.CONST_1_2: "4.0/8.0",
    TevKColorSel.CONST_3_8: "3.0/8.0",
    TevKColorSel.CONST_1_4: "2.0/8.0",
    TevKColorSel.CONST_1_8: "1.0/8.0",
    TevKColorSel.K0_R: "_TevKColor0.r",
    TevKColorSel.K0_G: "_TevKColor0.g",
    TevKColorSel.K0_B: "_TevKColor0.b",
    TevKColorSel.K0_A: "_TevKColor0.a",
    TevKColorSel.K1_R: "_TevKColor1.r",
    TevKColorSel.K1_G: "_TevKColor1.g",
    TevKColorSel.K1_B: "_TevKColor1.b",
    TevKColorSel.K1_A: "_TevKColor1.a",
    TevKColorSel.K2_R: "_TevKColor2.r",
    TevKColorSel.K2_G: "_TevKColor2.g",
    TevKColorSel.K2_B: "_TevKColor2.b",
    TevKColorSel.K2_A: "_TevKColor2.a",
    TevKColorSel.K3_R: "_TevKColor3.r",
    TevKColorSel.K3_G: "_TevKColor3.g",
    TevKColorSel.K3_B: "_TevKColor3.b",
    TevKColorSel.K3_A: "_TevKColor3.a"
}
tev_c_input_table = {
    TevColorArg.CPREV: "colorPrev.rgb",
    TevColorArg.APREV: "colorPrev.aaa",
    TevColorArg.C0: "color0.rgb",
    TevColorArg.A0: "color0.aaa",
    TevColorArg.C1: "color1.rgb",
    TevColorArg.A1: "color1.aaa",
    TevColorArg.C2: "color2.rgb",
    TevColorArg.A2: "color2.aaa",
    TevColorArg.TEXC: "texTemp.rgb",
    TevColorArg.TEXA: "texTemp.aaa",
    TevColorArg.RASC: "rasTemp.rgb",
    TevColorArg.RASA: "rasTemp.aaa",
    TevColorArg.ONE: "(half3)(1)",
    TevColorArg.HALF: "(half3)(1.0/2.0)",
    TevColorArg.KONST: "konstTemp.rgb",
    TevColorArg.ZERO: "(half3)(0)"
}
tev_a_input_table = {
    TevAlphaArg.APREV: "colorPrev.a",
    TevAlphaArg.A0: "color0.a",
    TevAlphaArg.A1: "color1.a",
    TevAlphaArg.A2: "color2.a",
    TevAlphaArg.TEXA: "texTemp.a",
    TevAlphaArg.RASA: "rasTemp.a",
    TevAlphaArg.KONST: "konstTemp.a",
    TevAlphaArg.ZERO: "0"
}
tev_output_table = {
    Register.PREV: "colorPrev",
    Register.REG0: "color0",
    Register.REG1: "color1",
    Register.REG2: "color2",
}

# Copied from Dolphin
class DXShaderGen:
    def genSpotFunction(self, fout, litMask):
        # NOTE: hardcoded to Sunshine
        if litMask&5 == 1<<0:
            # assume SpotFunction.OFF
            fout.writeLine("float spotFunction = 1.0;")
        elif litMask&5 == 1<<2:
            # assume SpotFunction.COS2
            fout.writeLine("float cr = saturate(unity_LightAtten[0].x);")
            fout.writeLine("float spotFunction = max(0.0, lightAttn*(-cr/(1-cr)) + lightAttn*lightAttn/(1-cr));")
        else:
            raise ValueError(bin(litMask))
    
    def genLightShader(self, fout, colorChannel, suffix):
        if colorChannel.attenuationFunction == 0:
            fout.writeLine("// Spec")
            fout.writeLine("float3 lightDir = normalize(unity_LightPosition[0].xyz - viewpos * unity_LightPosition[0].w);")
            if colorChannel.litMask&5 == 1<<0:
                fout.writeLine("float3 spotDir = -unity_SpotDirection[0].xyz;")
            elif colorChannel.litMask&5 == 1<<2:
                fout.writeLine("float3 spotDir = normalize(normalize(unity_LightPosition[0].xyz)+float3(0,0,1));")
            fout.writeLine("float lightAttn = (dot(viewN, lightDir) >= 0.0) ? max(0.0, dot(viewN, spotDir)) : 0.0;")
            self.genSpotFunction(fout, colorChannel.litMask)
            if colorChannel.litMask&5 == 1<<0:
                fout.writeLine("float distFunction = 1;")
            elif colorChannel.litMask&5 == 1<<2:
                fout.writeLine("float3 distAttn = {}(float3(25, 0, -24));".format("normalize" if (colorChannel.diffuseFunction == DiffuseFunction.NONE) else ""))
                fout.writeLine("float distFunction = dot(distAttn, float3(1.0, lightAttn, lightAttn*lightAttn));")
            fout.writeLine("lightAttn = spotFunction / distFunction;")
        elif colorChannel.attenuationFunction == 1:
            fout.writeLine("// Spot")
            fout.writeLine("float3 lightDir = unity_LightPosition[0].xyz - viewpos * unity_LightPosition[0].w;")
            fout.writeLine("float lightDistSq = dot(lightDir, lightDir);")
            fout.writeLine("float lightDist = sqrt(lightDistSq);")
            fout.writeLine("lightDir = lightDir / lightDist;")
            #if colorChannel.litMask&5 == 1<<0:
            #    fout.writeLine("float3 spotDir = -unity_SpotDirection[0].xyz;")
            #    fout.writeLine("float lightAttn = max(0.0, dot(lightDir, spotDir));")
            if colorChannel.litMask&5 == 1<<2:
                fout.writeLine("float3 spotDir = normalize(normalize(unity_LightPosition[0].xyz)+float3(0,0,1));")
                fout.writeLine("float lightAttn = max(0.0, dot(lightDir, spotDir));")
            else:
                fout.writeLine("float lightAttn;")
            self.genSpotFunction(fout, colorChannel.litMask)
            if colorChannel.litMask&5 == 1<<0:
                fout.writeLine("float distFunction = 1;")
            elif colorChannel.litMask&5 == 1<<2:
                fout.writeLine("float3 distAttn = float3(25, 0, -24);")
                fout.writeLine("float distFunction = dot(distAttn, float3(1.0, lightDist, lightDistSq));")
            fout.writeLine("lightAttn = spotFunction / distFunction;")
        else:
            fout.writeLine("// None/dir")
            fout.writeLine("float3 lightDir = normalize(unity_LightPosition[0].xyz - viewpos * unity_LightPosition[0].w);")
            fout.writeLine("float lightAttn = 1.0;")
            fout.writeLine("if (length(lightDir) == 0.0)")
            with fout: fout.writeLine("lightDir = viewN;")
        
        if colorChannel.attenuationFunction == 0:
            diffFn = DiffuseFunction.NONE
        else:
            diffFn = colorChannel.diffuseFunction
        fout.writeLine("// "+str(diffFn))
        if diffFn == DiffuseFunction.NONE:
            fout.writeLine("lightAccum{0} += lightAttn * unity_LightColor[0]{0};".format(suffix))
        else:
            fout.writeLine("lightAccum{0} += lightAttn * {1}dot(lightDir, viewN)) * unity_LightColor[0]{0};".format(suffix, "max(0.0," if diffFn == DiffuseFunction.CLAMP else "("))
    
    def genVertLighting(self, mat, fout, useColor1, alphaOnly=False, ambientEnabled=True, lightShaderEnabled=True):
        # numColorChans controls the number of color channels available to TEV, but
        # we still need to generate all channels here, as it can be used in texgen.
        fout.writeLine("float4 vertexColor0, vertexColor1;")
        
        # To use color 1, the vertex descriptor must have color 0 and 1.
        # If color 1 is present but not color 0, it is used for lighting channel 0.
        for i in range(2):
            if i*2+1 >= len(mat.colorChans) or mat.colorChans[i*2+1] is None: continue
            if mat.colorChans[i*2].matColorSource == ColorSrc.VTX or mat.colorChans[i*2].ambColorSource == ColorSrc.VTX or mat.colorChans[i*2+1].matColorSource == ColorSrc.VTX or mat.colorChans[i*2+1].ambColorSource == ColorSrc.VTX:
                if i == 0 or useColor1:
                    # Use color0 for channel 0, and color1 for channel 1 if both colors 0 and 1 are present.
                    fout.writeLine("vertexColor{0} = v.color{0};".format(i))
                elif i == 0:
                    # Use color1 for channel 0 if color0 is not present.
                    fout.writeLine("vertexColor0 = v.color1;")
                #else:
                #    fout.writeLine("vertexColor{0} = missing_color_value;".format(i))
        
        for i in range(2):
            if i*2+1 >= len(mat.colorChans) or mat.colorChans[i*2+1] is None: continue
            fout.writeLine("fixed4 colorChannel{};".format(i))
            with fout:
                colorChannel = mat.colorChans[i*2]
                if colorChannel.matColorSource == ColorSrc.VTX:
                    fout.writeLine("fixed4 baseColor = vertexColor{};".format(i))
                else:
                    fout.writeLine("fixed4 baseColor = _MatColor{};".format(i))
                
                if colorChannel.lightingEnabled and ambientEnabled:
                    if colorChannel.ambColorSource == ColorSrc.VTX:
                        fout.writeLine("half4 lightAccum = vertexColor{};".format(i))
                    else:
                        if i == 0:
                            fout.writeLine("half4 lightAccum = fixed4(LinearToGammaSpace(UNITY_LIGHTMODEL_AMBIENT.rgb), UNITY_LIGHTMODEL_AMBIENT.a);")
                        else:
                            fout.writeLine("half4 lightAccum = _AmbColor{};".format(i))
                else:
                    fout.writeLine("half4 lightAccum = 1;")
                
                alphaChannel = mat.colorChans[i*2+1]
                if alphaChannel.matColorSource != colorChannel.matColorSource:
                    if alphaChannel.matColorSource == ColorSrc.VTX:
                        fout.writeLine("baseColor.a = vertexColor{}.a;".format(i))
                    else:
                        fout.writeLine("baseColor.a = _MatColor{}.a;".format(i))
                
                if alphaChannel.lightingEnabled != colorChannel.lightingEnabled or alphaChannel.ambColorSource != colorChannel.ambColorSource:
                    if alphaChannel.lightingEnabled and ambientEnabled:
                        if alphaChannel.ambColorSource == ColorSrc.VTX:
                            fout.writeLine("lightAccum.a = vertexColor{}.a;".format(i))
                        else:
                            if i == 0:
                                fout.writeLine("lightAccum.a = UNITY_LIGHTMODEL_AMBIENT.a;")
                            else:
                                fout.writeLine("lightAccum.a = _AmbColor{}.a;".format(i))
                    else:
                        fout.writeLine("lightAccum.a = 1;")
                
                if lightShaderEnabled:
                    # on GX, need to have different light for diffuse/specular, so
                    # just assume 1 light and use it for all calcs
                    if not alphaOnly and colorChannel.lightingEnabled == alphaChannel.lightingEnabled and colorChannel.litMask == alphaChannel.litMask and colorChannel.diffuseFunction == alphaChannel.diffuseFunction and colorChannel.attenuationFunction == alphaChannel.attenuationFunction:
                        if colorChannel.lightingEnabled and colorChannel.litMask != 0:
                            with fout:
                                self.genLightShader(fout, colorChannel, "")
                    else:
                        if colorChannel.lightingEnabled and colorChannel.litMask != 0 and not alphaOnly:
                            with fout:
                                self.genLightShader(fout, colorChannel, ".rgb")
                        if alphaChannel.lightingEnabled and alphaChannel.litMask != 0:
                            with fout:
                                self.genLightShader(fout, alphaChannel, ".a")
                
                fout.writeLine("lightAccum = saturate(lightAccum);")
                fout.writeLine("colorChannel{} = baseColor * lightAccum;".format(i))
                if i < mat.colorChanNum: fout.writeLine("o.color{0} = colorChannel{0};".format(i))
        
    def genTexGen(self, mat, fout):
        for i in range(mat.texGenNum):
            texInfo = mat.texCoords[i]
            with fout:
                fout.writeLine("float4 src = float4(0, 0, 1, 1);")
                if texInfo.source == TexGenSrc.POS:
                    fout.writeLine("src.xyz = v.vertex.xyz;") # only 4d in the meta pass
                elif texInfo.source == TexGenSrc.NRM:
                    fout.writeLine("src.xyz = v.normal;")
                elif texInfo.source == TexGenSrc.BINRM:
                    fout.writeLine("src.xyz = cross(v.normal, v.tangent);")
                elif texInfo.source == TexGenSrc.TANGENT:
                    fout.writeLine("src.xyz = v.tangent;")
                elif texInfo.source >= TexGenSrc.TEX0 and texInfo.source <= TexGenSrc.TEX7:
                    fout.writeLine("src.xy = v.texcoord{}.xy;".format(texInfo.source-TexGenSrc.TEX0))
                elif texInfo.source >= TexGenSrc.TEXCOORD0 and texInfo.source <= TexGenSrc.TEXCOORD6:
                    prevIdx = texInfo.source-TexGenSrc.TEXCOORD0
                    prevTexGen = mat.texCoords[prevIdx]
                    suffix = "xy" if texGen.type == TexGenType.MTX2x4 or texGen.type == TexGenType.SRTG else "xyz"
                    fout.writeLine("src.{} = outTexCoord{};".format(suffix, prevIdx))
                else:
                    fout.writeLine("src = colorChannel{};".format(texInfo.source-TexGenSrc.COLOR0))
                
                if texInfo.matrix >= TexGenMatrix.TEXMTX0 and texInfo.matrix <= TexGenMatrix.TEXMTX9:
                    texMtxIdx = (texInfo.matrix-TexGenMatrix.TEXMTX0)//3
                    texMtx = mat.texMtxs[texMtxIdx]
                    matrixMode = texMtx.info&0x3F
                    if matrixMode in (2, 8):
                        # Projmap
                        fout.writeLine("src = mul(unity_ObjectToWorld, src);")
                    elif matrixMode in (3, 9):
                        # ViewProjmap
                        fout.writeLine("src = mul(UNITY_MATRIX_V, mul(unity_ObjectToWorld, src));")
                    elif matrixMode in (10, 11):
                        # EnvmapEffectMtx
                        fout.writeLine("src = float4(mul((float3x3)unity_ObjectToWorld, src.xyz), src.w);")
                    elif matrixMode in (1, 6, 7):
                        # Envmap
                        fout.writeLine("src = float4(mul((float3x3)UNITY_MATRIX_V, mul((float3x3)unity_ObjectToWorld, src.xyz)), src.w);")
                    if matrixMode in (1, 2, 3, 6, 7, 8, 9, 10, 11) and texInfo.source in (TexGenSrc.NRM, TexGenSrc.BINRM, TexGenSrc.TANGENT):
                        fout.writeLine("src.xyz *= {};".format(self.objectScale))
                    
                    if matrixMode == 1:
                        # EnvmapBasic
                        # projection, SRT
                        pass
                    elif matrixMode in (2, 3, 5):
                        # ProjmapBasic, ViewProjmapBasic
                        # projection, effect, SRT
                        fout.writeLine("src = mul(_EffectMtx{}, src);".format(texMtxIdx))
                    elif matrixMode == 4:
                        # effect, SRT
                        fout.writeLine("src = mul(_EffectMtx{}, src);".format(texMtxIdx))
                    elif matrixMode == 6:
                        # EnvmapOld
                        # projection, env, SRT
                        fout.writeLine("src.xy = (src.xy*0.5)+(0.5*src.w);")
                    elif matrixMode == 7:
                        # Envmap
                        # projection, env, SRT
                        fout.writeLine("src.xy = (src.xy*0.5)+(0.5*src.z);")
                    elif matrixMode in (8, 9, 11):
                        # Projmap, ViewProjmap, EnvmapEffectMtx
                        # projection, effect, env, SRT
                        fout.writeLine("src = mul(_EffectMtx{}, src);".format(texMtxIdx))
                        fout.writeLine("src.xy = (src.xy*0.5)+(0.5*src.z);")
                    elif matrixMode == 10:
                        # EnvmapOldEffectMtx
                        # projection, effect, env, SRT
                        fout.writeLine("src = mul(_EffectMtx{}, src);".format(texMtxIdx))
                        fout.writeLine("src.xy = (src.xy*0.5)+(0.5*src.w);")
                
                if texInfo.type in (TexGenType.MTX3x4, TexGenType.MTX2x4):
                    if texInfo.type == TexGenType.MTX3x4:
                        fout.writeLine("float3 texcoord;")
                        suffix = ".xyz"
                    else:
                        fout.writeLine("float2 texcoord;")
                        suffix = ".xy"
                    if texInfo.matrix >= TexGenMatrix.PNMTX0 and texInfo.matrix <= TexGenMatrix.PNMTX9:
                        fout.writeLine("texcoord = UnityObjectToViewPos(src){};".format(suffix))
                    elif texInfo.matrix >= TexGenMatrix.TEXMTX0 and texInfo.matrix <= TexGenMatrix.TEXMTX9:
                        texMtxIdx = (texInfo.matrix-TexGenMatrix.TEXMTX0)//3
                        fout.writeLine("float cosR, sinR;")
                        fout.writeLine("sincos(_Tex{}_CR.w, sinR, cosR);".format(texMtxIdx))
                        fout.writeLine("texcoord = (")
                        fout.writeLine("    float3(")
                        fout.writeLine("        dot(float4(cosR, -sinR, 0, dot(float2(-cosR,  sinR), _Tex{0}_CR.xy)), src),".format(texMtxIdx))
                        fout.writeLine("        dot(float4(sinR,  cosR, 0, dot(float2(-sinR, -cosR), _Tex{0}_CR.xy)), src),".format(texMtxIdx))
                        fout.writeLine("        src.z")
                        fout.writeLine("    ) * float3(_Tex{0}_ST.xy, 1.0) + float3(_Tex{0}_ST.zw, 0.0) + _Tex{0}_CR.xyz".format(texMtxIdx))
                        fout.writeLine("){};".format(suffix))
                    elif texInfo.matrix == TexGenMatrix.IDENTITY:
                        fout.writeLine("texcoord = src{};".format(suffix))
                    else:
                        raise ValueError(texInfo.matrix)
                elif texInfo.type == TexGenType.SRTG:
                    fout.writeLine("float3 texcoord = src.xyz;")
                else:
                    raise ValueError(texInfo.type)
                
                if i >= len(mat.postTexGens) or mat.postTexGens[i] is None or mat.postTexGens[i].matrix == TexGenMatrix.DTTIDENTITY:
                    fout.writeLine("outTexCoord{} = texcoord;".format(i))
                else:
                    texMtxIdx = (mat.postTexGens[i].matrix-TexGenMatrix.DTTMTX0)//3
                    fout.writeLine("outTexCoord{} = mul(_PostTexMtx{}, texcoord);".format(i, texMtxIdx))
    
    def getTevOp(self, suffix, op, bias, scale):
        fmt = "half" if len(suffix) <= 1 else "half"+str(len(suffix))
        if op in (TevOp.ADD, TevOp.SUB):
            return "(tevD.{suffix} + ({fmt})({bias}) {sign} lerp(tevA.{suffix}, tevB.{suffix}, tevC.{suffix})) * {scale}".format(suffix=suffix, fmt=fmt, bias={TevBias.ZERO: 0, TevBias.ADDHALF: 0.5, TevBias.SUBHALF: -0.5}[bias], sign=("+" if op == TevOp.ADD else "-"), scale={TevScale.SCALE_1: 1, TevScale.SCALE_2: 2, TevScale.SCALE_4: 4, TevScale.DIVIDE_2: 0.5}[scale])
        elif op == TevOp.COMP_R8_GT:
            return "((tevA.r > tevB.r) ? tevC.{suffix} : ({fmt})(0)) + tevD.{suffix}".format(suffix=suffix, fmt=fmt)
        elif op == TevOp.COMP_R8_EQ:
            return "((tevA.r == tevB.r) ? tevC.{suffix} : ({fmt})(0)) + tevD.{suffix}".format(suffix=suffix, fmt=fmt)
        elif op ==TevOp.COMP_GR16_GT:
            return "((TevPack16(tevA.rg) >  TevPack16(tevB.rg)) ? tevC.{suffix} : ({fmt})(0)) + tevD.{suffix}".format(suffix=suffix, fmt=fmt)
        elif op == TevOp.COMP_GR16_EQ:
            return "((TevPack16(tevA.rg) == TevPack16(tevB.rg)) ? tevC.{suffix} : ({fmt})(0)) + tevD.{suffix}".format(suffix=suffix, fmt=fmt)
        elif op == TevOp.COMP_BGR24_GT:
            return "((TevPack24(tevA.rgb) >  TevPack24(tevB.rgb)) ? tevC.{suffix} : ({fmt})(0)) + tevD.{suffix}".format(suffix=suffix, fmt=fmt)
        elif op == TevOp.COMP_BGR24_EQ:
            return "((TevPack24(tevA.rgb) == TevPack24(tevB.rgb)) ? tevC.{suffix} : ({fmt})(0)) + tevD.{suffix}".format(suffix=suffix, fmt=fmt)
        elif op == TevOp.COMP_RGB8_GT:
            return "((tevA.rgb > tevB.rgb) * tevC.{suffix}) + tevD.{suffix}".format(suffix=suffix)
        elif op == TevOp.COMP_RGB8_EQ:
            return "((tevA.rgb == tevB.rgb) * tevC.{suffix}) + tevD.{suffix}".format(suffix=suffix) 
       
    def genFrag(self, mat, indirect, textures, fout):
        if any(i is not None and textures[i].mipmapCount > 1 for i in mat.texNos):
            fout.writeLine("float sceneTextureLODBias = log2(min(_ScreenParams.x / 640, _ScreenParams.y / 528));")
        fout.writeLine("half4 colorPrev = 1;")
        for i in range(3): fout.writeLine("half4 color{0} = _TevColor{0};".format(i))
        
        for i in range(indirect.indTexStageNum if indirect.hasIndirect else 0):
            indTexOrder = indirect.indTexOrder[i]
            indTexCoordScale = indirect.indTexCoordScale[i]
            texture = textures[mat.texNos[indTexOrder.texture]]
            fout.writeLine("int3 indTex{} = 255*{}.abg;".format(i, self.sampleTexture(indTexOrder.texture, texture, "i.texcoord{}/float2({}, {})".format(indTexOrder.texCoordId, 1<<indTexCoordScale.scaleS, 1<<indTexCoordScale.scaleT))))
        
        fout.writeLine("float2 tevCoord = 0;")
        for i in range(mat.tevStageNum):
            fout.writeLine("// TEV stage {}".format(i))
            with fout:
                tevInd = indirect.indTevStage[i]
                tevOrder = mat.tevOrders[i]
                if tevInd.alphaSel == 0: # Off
                    fout.writeLine("fixed alphaBump = 0;")
                else:
                    fout.writeLine("int alphaBump = indTex{}.{}&{};".format(tevInd.indTexId, "wxyz"[tevInd.alphaSel], [0xF8,0xE0,0xF0,0xF8][tevInd.format]))
                if tevInd.mtxId == 0: # Off
                    fout.writeLine("float2 indTevTrans = 0;")
                else:
                    fout.writeLine("int3 indTevCrd = indTex{};".format(tevInd.indTexId))
                    if tevInd.bias > 0:
                        fout.writeLine("indTevCrd.{} += {};".format(["", "x", "y", "xy", "z", "xz", "yz", "xyz"][tevInd.bias], "-128" if tevInd.format == 0 else "1"))
                    
                    if tevInd.mtxId == 0:
                        fout.writeLine("float2 indTevTrans = 0;")
                    elif tevInd.mtxId in (1, 2, 3):
                        fout.writeLine("float2 indTevTrans = mul(_IndTexMtx{}, float4(indTevCrd, 0));".format(tevInd.mtxId-1))
                    elif tevInd.mtxId in (5, 6, 7):
                        fout.writeLine("float2 indTevTrans = i.texcoord{}*indTevCrd.xx;".format(tevOrder.texCoordId))
                    elif tevInd.mtxId in (9, 10, 11):
                        fout.writeLine("float2 indTevTrans = i.texcoord{}*indTevCrd.yy;".format(tevOrder.texCoordId))
                if tevOrder.texCoordId == 0xFF:
                    fout.writeLine("float2 wrappedCoord = 0;")
                else:
                    fout.writeLine("float2 wrappedCoord = i.texcoord{};".format(tevOrder.texCoordId))
                    if tevInd.wrapS == 6:
                        fout.writeLine("wrappedCoord.x = 0;")
                    elif tevInd.wrapS != 0:
                        fout.writeLine("wrappedCoord.x %= {}/255.0;".format([0, 256, 128, 64, 32, 16][tevInd.wrapS]))
                    if tevInd.wrapT == 6:
                        fout.writeLine("wrappedCoord.y = 0;")
                    elif tevInd.wrapT != 0:
                        fout.writeLine("wrappedCoord.y %= {}/255.0;".format([0, 256, 128, 64, 32, 16][tevInd.wrapT]))
                    
                if tevInd.addPrev:
                    fout.writeLine("tevCoord += wrappedCoord + indTevTrans/255.0;")
                else:
                    fout.writeLine("tevCoord = wrappedCoord + indTevTrans/255.0;")
            
                tevStage = mat.tevStages[i]
                if TevColorArg.RASA in (tevStage.colorInA, tevStage.colorInB, tevStage.colorInC, tevStage.colorInD) or \
                    TevColorArg.RASC in (tevStage.colorInA, tevStage.colorInB, tevStage.colorInC, tevStage.colorInD) or \
                    TevAlphaArg.RASA in (tevStage.alphaInA, tevStage.alphaInB, tevStage.alphaInC, tevStage.alphaInD):
                    if tevOrder.chanId in (ColorChannelID.COLOR0, ColorChannelID.ALPHA0, ColorChannelID.COLOR0A0):
                        rasSrc = "i.color0"
                    elif tevOrder.chanId in (ColorChannelID.COLOR1, ColorChannelID.ALPHA1, ColorChannelID.COLOR1A1):
                        rasSrc = "i.color1"
                    elif tevOrder.chanId == ColorChannelID.ALPHA_BUMP:
                        rasSrc = "alphaBump"
                    elif tevOrder.chanId == ColorChannelID.ALPHA_BUMP_N:
                        rasSrc = "(alphaBump*(255.0/248.0))"
                    elif tevOrder.chanId in (ColorChannelID.COLOR_ZERO, ColorChannelID.COLOR_NULL):
                        rasSrc = "(fixed4)(0)"
                    tbl = mat.tevSwapModeTables[mat.tevSwapModes[i].rasSel]
                    fout.writeLine("fixed4 rasTemp = {}.{}{}{}{};".format(rasSrc, "rgba"[tbl.rSel], "rgba"[tbl.gSel], "rgba"[tbl.bSel], "rgba"[tbl.aSel]))
                
                if TevColorArg.TEXA in (tevStage.colorInA, tevStage.colorInB, tevStage.colorInC, tevStage.colorInD) or \
                    TevColorArg.TEXC in (tevStage.colorInA, tevStage.colorInB, tevStage.colorInC, tevStage.colorInD) or \
                    TevAlphaArg.TEXA in (tevStage.alphaInA, tevStage.alphaInB, tevStage.alphaInC, tevStage.alphaInD):
                    texSrc = self.sampleTexture(tevOrder.texMap, textures[mat.texNos[tevOrder.texMap]], "tevCoord")
                    tbl = mat.tevSwapModeTables[mat.tevSwapModes[i].texSel]
                    fout.writeLine("fixed4 texTemp = {}.{}{}{}{};".format(texSrc, "rgba"[tbl.rSel], "rgba"[tbl.gSel], "rgba"[tbl.bSel], "rgba"[tbl.aSel]))
                
                if TevColorArg.KONST in (tevStage.colorInA, tevStage.colorInB, tevStage.colorInC, tevStage.colorInD) or \
                    TevAlphaArg.KONST in (tevStage.alphaInA, tevStage.alphaInB, tevStage.alphaInC, tevStage.alphaInD):
                    fout.writeLine("fixed4 konstTemp = fixed4({}, {});".format(tev_ksel_table_c[mat.tevKColorSels[i]], tev_ksel_table_a[mat.tevKAlphaSels[i]]))
                
                fout.writeLine("half4 tevA = half4({}, {})%(256.0/255.0);".format(tev_c_input_table[tevStage.colorInA], tev_a_input_table[tevStage.alphaInA]))
                fout.writeLine("half4 tevB = half4({}, {})%(256.0/255.0);".format(tev_c_input_table[tevStage.colorInB], tev_a_input_table[tevStage.alphaInB]))
                fout.writeLine("half4 tevC = half4({}, {})%(256.0/255.0);".format(tev_c_input_table[tevStage.colorInC], tev_a_input_table[tevStage.alphaInC]))
                fout.writeLine("half4 tevD = half4({}, {});".format(tev_c_input_table[tevStage.colorInD], tev_a_input_table[tevStage.alphaInD]))
                
                fout.writeLine("{}.rgb = clamp({}, {}, {});".format(tev_output_table[tevStage.colorRegId], self.getTevOp("rgb", tevStage.colorOp, tevStage.colorBias, tevStage.colorScale), 0 if tevStage.colorClamp else -4, 1 if tevStage.colorClamp else 4))
                if i == mat.tevStageNum-1 and tevStage.colorRegId != Register.PREV:
                    fout.writeLine("colorPrev.rgb = {}.rgb;".format(tev_output_table[tevStage.colorRegId]))
                fout.writeLine("{}.a = clamp({}, {}, {});".format(tev_output_table[tevStage.alphaRegId], self.getTevOp("a", tevStage.alphaOp, tevStage.alphaBias, tevStage.alphaScale), 0 if tevStage.alphaClamp else -4, 1 if tevStage.alphaClamp else 4))
                if i == mat.tevStageNum-1 and tevStage.alphaRegId != Register.PREV:
                    fout.writeLine("colorPrev.a = {}.a;".format(tev_output_table[tevStage.alphaRegId]))
        
        if mat.alphaComp is not None:
            # reduce the number of cases to handle by eliminating impossibilities
            if mat.alphaComp.comp0 == CompareType.LEQUAL and mat.alphaComp.ref0 == 255: mat.alphaComp.comp0 = CompareType.ALWAYS
            if mat.alphaComp.comp1 == CompareType.LEQUAL and mat.alphaComp.ref1 == 255: mat.alphaComp.comp1 = CompareType.ALWAYS
            if mat.alphaComp.comp0 == CompareType.GEQUAL and mat.alphaComp.ref0 == 0: mat.alphaComp.comp0 = CompareType.ALWAYS
            if mat.alphaComp.comp1 == CompareType.GEQUAL and mat.alphaComp.ref1 == 0: mat.alphaComp.comp1 = CompareType.ALWAYS
            if mat.alphaComp.comp0 == CompareType.LESS and mat.alphaComp.ref0 == 0: mat.alphaComp.comp0 = CompareType.NEVER
            if mat.alphaComp.comp1 == CompareType.LESS and mat.alphaComp.ref1 == 0: mat.alphaComp.comp1 = CompareType.NEVER
            if mat.alphaComp.comp0 == CompareType.GREATER and mat.alphaComp.ref0 == 255: mat.alphaComp.comp0 = CompareType.NEVER
            if mat.alphaComp.comp1 == CompareType.GREATER and mat.alphaComp.ref1 == 255: mat.alphaComp.comp1 = CompareType.NEVER
            # optimizations
            if CompareType.ALWAYS in (mat.alphaComp.comp0, mat.alphaComp.comp1) and mat.alphaComp.op == AlphaOp.OR:
                pass
            elif CompareType.NEVER in (mat.alphaComp.comp0, mat.alphaComp.comp1) and mat.alphaComp.op == AlphaOp.AND:
                fout.writeLine("discard;")
            elif (mat.alphaComp.comp0 == CompareType.ALWAYS and mat.alphaComp.op == AlphaOp.AND) or (mat.alphaComp.comp0 == CompareType.NEVER and mat.alphaComp.op == AlphaOp.OR):
                fout.writeLine(self.makeSimpleComp(mat.alphaComp.comp1, mat.alphaComp.ref1))
            elif (mat.alphaComp.comp1 == CompareType.ALWAYS and mat.alphaComp.op == AlphaOp.AND) or (mat.alphaComp.comp1 == CompareType.NEVER and mat.alphaComp.op == AlphaOp.OR):
                fout.writeLine(self.makeSimpleComp(mat.alphaComp.comp0, mat.alphaComp.ref0))
            elif mat.alphaComp.op == AlphaOp.OR:
                fout.writeLine(self.makeSimpleComp(mat.alphaComp.comp0, mat.alphaComp.ref0))
                fout.writeLine(self.makeSimpleComp(mat.alphaComp.comp1, mat.alphaComp.ref1))
            else:
                # fallback/general case
                fout.writeLine("if (!(({}) {} ({}))) discard;".format(self.makeComp(mat.alphaComp.comp0, mat.alphaComp.ref0), ["&&", "||", "!=", "=="][mat.alphaComp.op.value], self.makeComp(mat.alphaComp.comp1, mat.alphaComp.ref1)))

    def sampleTexture(self, texSlot, texture, coord):
        if texture.mipmapCount > 1:
            # the texture's factor is in texture import settings
            s = "tex2Dbias(_Tex{}, float4({}, 0, sceneTextureLODBias))".format(texSlot, coord)
        else:
            s = "tex2D(_Tex{}, {})".format(texSlot, coord)
        if not texture.usePalette and texture.format in (TexFmt.I4, TexFmt.I8): suffix = "rrrr"
        elif not texture.usePalette and texture.format in (TexFmt.IA4, TexFmt.IA8): suffix = "rrrg"
        elif texture.usePalette and texture.paletteFormat == TlutFmt.IA8: suffix = "rrrg"
        else: suffix = "rgba"
        if True or texture.transparency:
            if suffix != "rgba":
                s += "."+suffix
        else:
            s = "fixed4({}.{}, 1)".format(s, suffix[:3])
        return s

    def makeComp(self, comp, ref):
        if comp == CompareType.ALWAYS: return "1"
        elif comp == CompareType.NEVER: return "0"
        else: return "colorPrev.a {} {}/255.0".format(["", "<", "==", "<=", ">", "!=", ">="][comp.value], ref)

    def makeSimpleComp(self, comp, ref):
        if comp in (CompareType.LESS, CompareType.LEQUAL, CompareType.GREATER, CompareType.GEQUAL):
            if comp == CompareType.LEQUAL:
                ref += 1
                comp = CompareType.LESS
            elif comp == CompareType.GEQUAL:
                ref -= 1
                comp = CompareType.GREATER
            if comp == CompareType.GREATER:
                return "clip(colorPrev.a - {}/255.0);".format(ref)
            elif comp == CompareType.LESS:
                return "clip({}/255.0 - colorPrev.a);".format(ref)
        else:
            return "if (!({})) discard;".format(self.makeComp(comp, ref))

def usesTexGenInput(mat, src):
    return any(
        texGen is not None and \
        texGen.source == src
        for texGen in mat.texCoords
    )

def usesBump(mat):
    return any(
        texGen is not None and \
        texGen.type >= TexGenType.BUMP0 and \
        texGen.type <= TexGenType.BUMP7
        for texGen in mat.texCoords
    )

def usesNormal(mat):
    return any(
        colorChan is not None and \
        colorChan.lightingEnabled and \
        colorChan.litMask != 0 and \
        (colorChan.diffuseFunction != DiffuseFunction.NONE or colorChan.attenuationFunction == 0)
        for colorChan in mat.colorChans
    )

def usesColorChannel(chan: ColorChanInfo):
    return chan is not None and (chan.matColorSource == ColorSrc.VTX or chan.ambColorSource == ColorSrc.VTX)

class UnityShaderGen(DXShaderGen):
    def genv2f(self, mat, fout):
        for i, texGen in enumerate(mat.texCoords[:mat.texGenNum]):
            fout.writeLine("{0} texcoord{1} : TEXCOORD{1};".format("float2" if texGen.type in (TexGenType.MTX2x4, TexGenType.SRTG) else "float3", i))
        for i in range(mat.colorChanNum):
            fout.writeLine("fixed4 color{0} : COLOR{0};".format(i))
    
    def genUniforms(self, mat, indirect, fout):
        for i, color in enumerate(mat.matColors):
            if color is not None: fout.writeLine("fixed4 _MatColor{};".format(i))
        for i, color in enumerate(mat.ambColors):
            # use unity_AmbientSky for ambColor 0
            if i != 0 and color is not None: fout.writeLine("const fixed4 _AmbColor{0} = {{{1[0]}/255.0, {1[1]}/255.0, {1[2]}/255.0, {1[3]}/255.0}};".format(i, color))
        for i in range(3):
            fout.writeLine("half4 _TevColor{};".format(i))
        for i, color in enumerate(mat.tevKColors):
            if color is not None: fout.writeLine("fixed4 _TevKColor{};".format(i))
        for i, texIdx in enumerate(mat.texNos):
            if texIdx is not None: fout.writeLine("sampler2D _Tex{};".format(i))
        for i, texMtx in enumerate(mat.texMtxs):
            if texMtx is not None:
                fout.writeLine("float4 _Tex{}_ST;".format(i))
                fout.writeLine("float4 _Tex{}_CR;".format(i))
                fout.writeLine("const float4x4 _EffectMtx{} = {{{}}};".format(i, ", ".join(map(str, texMtx.effectMatrix))))
        for i, texMtx in enumerate(mat.postTexMtxs):
            if texMtx is not None: fout.writeLine("const float4x4 _PostTexMtx{} = {{{}}};".format(i, ", ".join(map(str, texMtx.calcMtx()))))
        for i, texMtx in enumerate(indirect.indTexMtx):
            if texMtx is not None: fout.writeLine("const float4x4 _IndTexMtx{} = {{{}}};".format(i, ", ".join(map(str, texMtx.m+([0]*8)))))
    
    def genAttributes(self, mat, fout):
        if usesTexGenInput(mat, TexGenSrc.TANGENT) or usesBump(mat): fout.writeLine("float3 tangent : TANGENT;")
        if usesNormal(mat) or usesTexGenInput(mat, TexGenSrc.NRM): fout.writeLine("float3 normal : NORMAL;")
        for i in range(8):
            if usesTexGenInput(mat, TexGenSrc.TEX0+i): fout.writeLine("float2 texcoord{0} : TEXCOORD{0};".format(i))
        for i in range(2):
            if i*2+1 >= len(mat.colorChans) or mat.colorChans[i*2+1] is None: continue
            if usesColorChannel(mat.colorChans[i*2]) or usesColorChannel(mat.colorChans[i*2+1]): fout.writeLine("fixed4 color{0} : COLOR{0};".format(i))
    
    def gen(self, mat, indirect, textures, fout, useColor1, doMeta):
        fout.writeLine("Shader \"J3D/{}\"".format(mat.name))
        with fout:
            fout.writeLine("Properties")
            with fout:
                # Unity converts colors from sRGB *if* they are marked as "Color"
                # in the ShaderLab properties. "Vector" types are not converted.
                for i, color in enumerate(mat.matColors):
                    if color is not None: fout.writeLine("_MatColor{0} (\"Material color {0}\", Vector) = (0, 0, 0, 1)".format(i))
                # amb color is never animated
                #for i, color in enumerate(mat.ambColors):
                #    if color is not None: fout.writeLine("_AmbColor{0} (\"Ambient color {0}\", Vector) = (0, 0, 0, 1)".format(i))
                for i, color in enumerate(mat.tevColors):
                    # (the [HDR] tag doesn't do anything because it's not a color, but it seems harmless)
                    if color is not None: fout.writeLine("[HDR] _TevColor{0} (\"TEV color {0}\", Vector) = (0, 0, 0, 1)".format(i))
                for i, color in enumerate(mat.tevKColors):
                    if color is not None: fout.writeLine("_TevKColor{0} (\"TEV constant color {0}\", Vector) = (0, 0, 0, 1)".format(i))
                for i in range(8):
                    # note: texMtx and texNo do not necessarily correspond
                    texMtx = mat.texMtxs[i] if i < len(mat.texMtxs) else None
                    texIdx = mat.texNos[i] if i < len(mat.texNos) else None
                    if texMtx is None and texIdx is None: continue
                    if texMtx is None: tags = "[NoScaleOffset] "
                    else: tags = ""
                    desc = ""
                    if texIdx is not None:
                        desc += "Texture slot {}".format(i)
                        if texMtx is not None: desc += "/"
                    if texMtx is not None: desc += "Texture matrix {} ST".format(i)
                    fout.writeLine("{}_Tex{} (\"{}\", 2D) = \"black\" {{}}".format(tags, i, desc))
                # still need texmtx center, rotation
                for i, texMtx in enumerate(mat.texMtxs):
                    if texMtx is not None: fout.writeLine("_Tex{0}_CR (\"Texture matrix {0} CR\", Vector) = (0.5, 0.5, 0, 0)".format(i))
                # postTexMtx is never animated
            
            if all(colorChan is None or not colorChan.lightingEnabled or colorChan.litMask == 0 for colorChan in mat.colorChans): fout.writeLine("CustomEditor \"EmissiveShaderGUI\"")
            
            fout.writeLine("CGINCLUDE")
            fout.indent += 1
            
            # TODO: I don't know if target/multi_compile features affect CGINCLUDE blocks
            
            fout.writeLine("#include \"UnityCG.cginc\"")
            
            fout.writeLine("struct appdata_t")
            with fout:
                fout.writeLine("float3 vertex : POSITION;")
                self.genAttributes(mat, fout)
                fout.writeLine("UNITY_VERTEX_INPUT_INSTANCE_ID")
            fout.writeLine(";")
            
            self.genUniforms(mat, indirect, fout)
            
            fout.writeLine("void texGen(appdata_t v, fixed4 colorChannel0, fixed4 colorChannel1{})".format("".join(", out {} outTexCoord{}".format("float2" if texGen.type in (TexGenType.MTX2x4, TexGenType.SRTG) else "float3", i) for i, texGen in enumerate(mat.texCoords[:mat.texGenNum]))))
            with fout:
                self.genTexGen(mat, fout)
            callTexGen = "texGen(v, colorChannel0, colorChannel1{});".format("".join(", o.texcoord{}".format(i) for i in range(mat.texGenNum)))

            fout.writeLine("half TevPack16(half2 a) { return dot(a, half2(1.0, 256.0)); }")
            fout.writeLine("half TevPack24(half3 a) { return dot(a, half3(1.0, 256.0, 256.0 * 256.0)); }")
            
            fout.indent -= 1
            fout.writeLine("ENDCG")

            fout.writeLine("SubShader")
            with fout:
                fout.writeLine('Tags')
                with fout:
                    if mat.materialMode == 4: # XLU
                        fout.writeLine('"Queue" = "Transparent"')
                        fout.writeLine('"RenderType" = "Transparent"')
                        fout.writeLine('"IgnoreProjector" = "True"')
                    else:
                        if mat.zCompLoc is not None:
                            if mat.zCompLoc:
                                fout.writeLine('"Queue" = "Geometry"')
                                fout.writeLine('"RenderType" = "Opaque"')
                            else:
                                fout.writeLine('"Queue" = "AlphaTest"')
                                fout.writeLine('"RenderType" = "TransparentCutout"')
                                fout.writeLine('"IgnoreProjector" = "True"')
                
                #fout.writeLine("LOD 100")
                if mat.blend is not None:
                    if mat.blend.blendMode == BlendMode.NONE:
                        fout.writeLine("Blend Off")
                    else:
                        factors = ['Zero', 'One', 'SrcColor', 'OneMinusSrcColor', 'SrcAlpha', 'OneMinusSrcAlpha', 'DstAlpha', 'OneMinusDstAlpha']
                        fout.writeLine("Blend {} {}".format(factors[mat.blend.srcFactor.value], factors[mat.blend.dstFactor.value]))
                        if mat.blend.blendMode == BlendMode.BLEND:
                            fout.writeLine("BlendOp Add")
                        elif mat.blend.blendMode == BlendMode.LOGIC:
                            fout.writeLine("BlendOp Logical {}".format(['Clear', 'And', 'AndReverse', 'Copy', 'AndInverted', 'Noop', 'Xor', 'Or', 'Nor', 'Equiv', 'Invert', 'OrReverse', 'CopyInverted', 'OrInverted', 'Nand', 'Set'][mat.blend.logicOp.value]))
                        elif mat.blend.blendMode == BlendMode.SUBTRACT:
                            fout.writeLine("BlendOp Sub")
                if mat.cullMode is not None:
                    if mat.cullMode == CullMode.ALL:
                        fout.writeLine("ColorMask 0")
                    else:
                        fout.writeLine("Cull {}".format(['Off', 'Front', 'Back'][mat.cullMode.value]))
                if mat.zMode is not None:
                    if mat.zMode.enable and mat.zMode.func == CompareType.NEVER:
                        fout.writeLine("ColorMask 0")
                    else:
                        fout.writeLine("ZTest {}".format(['Never', 'Less', 'Equal', 'LEqual', 'Greater', 'NotEqual', 'GEqual', 'Always'][mat.zMode.func.value] if mat.zMode.enable else "Always"))
                    fout.writeLine("ZWrite {}".format(['Off', 'On'][mat.zMode.writeZ]))
                
                fout.writeLine("Pass")
                with fout:
                    #fout.writeLine("LOD 100")
                    
                    fout.writeLine("Tags")
                    with fout:
                        if any(colorChan is not None and colorChan.lightingEnabled and colorChan.litMask != 0 for colorChan in mat.colorChans):
                            fout.writeLine('"LightMode" = "Vertex"')
                        else:
                            fout.writeLine('"LightMode" = "Always"')
                    
                    fout.writeLine("CGPROGRAM")
                    fout.indent += 1
                    
                    fout.writeLine("#pragma vertex vert")
                    fout.writeLine("#pragma fragment frag")
                    fout.writeLine("#pragma target 2.0")
                    if mat.fog is not None: fout.writeLine("#pragma multi_compile_fog")
                    if not doMeta: fout.writeLine("#pragma multi_compile_instancing")
                    
                    fout.writeLine("struct v2f")
                    with fout:
                        fout.writeLine("float4 position : SV_POSITION;")
                        self.genv2f(mat, fout)
                        if mat.fog is not None: fout.writeLine("UNITY_FOG_COORDS({})".format(mat.texGenNum))
                        fout.writeLine("UNITY_VERTEX_INPUT_INSTANCE_ID")
                        fout.writeLine("UNITY_VERTEX_OUTPUT_STEREO")
                    fout.writeLine(";")
                    
                    fout.writeLine("v2f vert(appdata_t v)")
                    with fout:
                        fout.writeLine("UNITY_SETUP_INSTANCE_ID(v);")
                        fout.writeLine("v2f o;")
                        fout.writeLine("UNITY_INITIALIZE_VERTEX_OUTPUT_STEREO(o);")
                        fout.writeLine("float3 viewpos = UnityObjectToViewPos(v.vertex);")
                        if usesNormal(mat): fout.writeLine("float3 viewN = normalize (mul((float3x3)UNITY_MATRIX_IT_MV, v.normal));")
                        fout.writeLine("o.position = UnityViewToClipPos(viewpos);")
                        self.genVertLighting(mat, fout, useColor1)
                        fout.writeLine(callTexGen)
                        if mat.fog is not None: fout.writeLine("UNITY_TRANSFER_FOG(o,o.position);")
                        fout.writeLine("return o;")
                    
                    fout.writeLine("half4 frag(v2f i) : SV_Target")
                    with fout:
                        self.genFrag(mat, indirect, textures, fout)
                        fout.writeLine("#ifdef UNITY_COLORSPACE_GAMMA")
                        fout.writeLine("    half4 ret = colorPrev;")
                        fout.writeLine("#else")
                        fout.writeLine("    half4 ret = half4(GammaToLinearSpace(colorPrev.rgb), colorPrev.a);")
                        fout.writeLine("#endif")
                        fout.writeLine("UNITY_APPLY_FOG(i.fogCoord, ret);")
                        fout.writeLine("return ret;")
            
                    fout.indent -= 1
                    fout.writeLine("ENDCG")
                
                if mat.materialMode != 4:
                    fout.writeLine("Pass")
                    with fout:
                        fout.writeLine("Tags { \"LightMode\" = \"ShadowCaster\" }")
                        fout.writeLine("CGPROGRAM")
                        fout.indent += 1
                        
                        fout.writeLine("#pragma vertex vertShadow")
                        fout.writeLine("#pragma fragment fragShadow")
                        fout.writeLine("#pragma target 2.0")
                        fout.writeLine("#pragma multi_compile_shadowcaster")
                        if not doMeta: fout.writeLine("#pragma multi_compile_instancing")
                        fout.writeLine("struct v2fShadow")
                        with fout:
                            fout.writeLine("V2F_SHADOW_CASTER;")
                            if not mat.zCompLoc: self.genv2f(mat, fout)
                            fout.writeLine("UNITY_VERTEX_INPUT_INSTANCE_ID")
                            fout.writeLine("UNITY_VERTEX_OUTPUT_STEREO")
                        fout.writeLine(";")

                        fout.writeLine("v2fShadow vertShadow({} v)".format("appdata_base" if mat.zCompLoc else "appdata_t"))
                        with fout:
                            fout.writeLine("UNITY_SETUP_INSTANCE_ID(v);")
                            fout.writeLine("v2fShadow o;")
                            fout.writeLine("UNITY_INITIALIZE_VERTEX_OUTPUT_STEREO(o);")
                            if mat.zCompLoc or usesNormal(mat): fout.writeLine("TRANSFER_SHADOW_CASTER_NORMALOFFSET(o)")
                            else: fout.writeLine("TRANSFER_SHADOW_CASTER(o)")
                            if not mat.zCompLoc:
                                #self.genVertLighting(mat, fout, useColor1, alphaOnly=True)
                                fout.writeLine("fixed4 colorChannel0 = {0, 0, 0, 1};")
                                fout.writeLine("fixed4 colorChannel1 = {0, 0, 0, 1};")
                                for i in range(mat.colorChanNum):
                                    fout.writeLine("o.color{0} = colorChannel{0};".format(i))
                                fout.writeLine(callTexGen)
                            fout.writeLine("return o;")

                        fout.writeLine("float4 fragShadow(v2fShadow i) : SV_Target")
                        with fout:
                            if not mat.zCompLoc: self.genFrag(mat, indirect, textures, fout)
                            fout.writeLine("SHADOW_CASTER_FRAGMENT(i)")
                        
                        fout.indent -= 1
                        fout.writeLine("ENDCG")
                
                if doMeta and mat.materialMode != 4:
                    fout.writeLine("Pass")
                    with fout:
                        fout.writeLine("Tags { \"LightMode\" = \"Meta\" }")
                        fout.writeLine("Cull Off")
                        fout.writeLine("CGPROGRAM")
                        fout.indent += 1
                        
                        fout.writeLine("#pragma vertex vert_meta")
                        fout.writeLine("#pragma fragment frag_meta")
                        fout.writeLine("#pragma shader_feature EDITOR_VISUALIZATION")
                        fout.writeLine("#include \"UnityMetaPass.cginc\"")
 
                        fout.writeLine("struct appdata_lightmapped_t")
                        with fout:
                            fout.writeLine("float4 vertex : POSITION;")
                            self.genAttributes(mat, fout)
                            fout.writeLine("float2 lightMapUV : TEXCOORD1;")
                            fout.writeLine("float2 dynLightMapUV : TEXCOORD2;")
                        fout.writeLine(";")
                        
                        fout.writeLine("struct v2f_meta")
                        with fout:
                            fout.writeLine("float4 position : SV_POSITION;")
                            self.genv2f(mat, fout)
                            fout.writeLine("#ifdef EDITOR_VISUALIZATION")
                            fout.writeLine("    float2 vizUV : TEXCOORD{};".format(mat.texGenNum))
                            fout.writeLine("    float4 lightCoord : TEXCOORD{};".format(mat.texGenNum+1))
                            fout.writeLine("#endif")
                        fout.writeLine(";")
                        
                        fout.writeLine("v2f_meta vert_meta(appdata_lightmapped_t v)")
                        with fout:
                            fout.writeLine("v2f_meta o;")
                            fout.writeLine("o.position = UnityMetaVertexPosition(v.vertex, v.lightMapUV, v.dynLightMapUV, unity_LightmapST, unity_DynamicLightmapST);")
                            self.genVertLighting(mat, fout, useColor1, lightShaderEnabled=False)
                            for i, texGen in enumerate(mat.texCoords[:mat.texGenNum]):
                                fout.writeLine("{} outTexCoord{} = 0;".format("float2" if texGen.type in (TexGenType.MTX2x4, TexGenType.SRTG) else "float3", i))
                            self.genTexGen(mat, fout)
                            for i in range(mat.texGenNum):
                                fout.writeLine("o.texcoord{0} = outTexCoord{0};".format(i))
                            fout.writeLine("#ifdef EDITOR_VISUALIZATION")
                            with fout:
                                fout.writeLine("o.vizUV = 0;")
                                fout.writeLine("o.lightCoord = 0;")
                                fout.writeLine("if (unity_VisualizationMode == EDITORVIZ_TEXTURE)")
                                with fout:
                                    fout.writeLine("o.vizUV = UnityMetaVizUV(unity_EditorViz_UVIndex, {}, v.lightMapUV, v.dynLightMapUV, unity_EditorViz_Texture_ST);".format("v.texcoord0" if usesTexGenInput(mat, TexGenSrc.TEX0) else "float2(0,0)"))
                                fout.writeLine("else if (unity_VisualizationMode == EDITORVIZ_SHOWLIGHTMASK)")
                                with fout:
                                    fout.writeLine("o.vizUV = v.lightMapUV * unity_LightmapST.xy + unity_LightmapST.zw;")
                                    fout.writeLine("o.lightCoord = mul(unity_EditorViz_WorldToLight, mul(unity_ObjectToWorld, float4(v.vertex.xyz, 1)));")
                            fout.writeLine("#endif")
                            fout.writeLine("return o;")
                        
                        fout.writeLine("float4 frag_meta (v2f_meta i) : SV_Target")
                        with fout:
                            self.genFrag(mat, indirect, textures, fout)
                            # only support unlit materials as emissive
                            fout.writeLine("#ifdef EDITOR_VISUALIZATION")
                            with fout:
                                fout.writeLine("UnityMetaInput o;")
                                fout.writeLine("UNITY_INITIALIZE_OUTPUT(UnityMetaInput, o);")
                                fout.writeLine("o.VizUV = i.vizUV;")
                                fout.writeLine("o.LightCoord = i.lightCoord;")
                                fout.writeLine("o.Emission = GammaToLinearSpace(colorPrev.rgb);")
                                fout.writeLine("return UnityMetaFragment(o);")
                            fout.writeLine("#else")
                            with fout:
                                fout.writeLine("half4 res = {0, 0, 0, 1};")
                                fout.writeLine("if (unity_MetaFragmentControl.y)")
                                with fout: fout.writeLine("res.rgb = GammaToLinearSpace(colorPrev.rgb);")
                                fout.writeLine("return res;")
                            fout.writeLine("#endif")
                        
                        fout.indent -= 1
                        fout.writeLine("ENDCG")

