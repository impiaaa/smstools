from bmd import *

# FIXME: hardcoded to sunshine
CosAtt = {1<<0: (1, 0, 0), 1<<2: (0, 0, 1)}
DistAtt = {1<<0: (1, 0, 0), 1<<2: (25, 0, -24)}
# Copied from Dolphin
class DXShaderGen:
    def genLightShader(self, fout, colorChannel, suffix):
        if colorChannel.attenuationFunction == 0:
            # Spec
            fout.write("ldir = unity_LightPosition[0].xyz - viewpos * unity_LightPosition[0].w;\n")
            #fout.write("float3 spotDir = unity_SpotDirection[0].w ? unity_SpotDirection[0].xyz : ldir.xyz;\n")
            fout.write("ldir = normalize(ldir);\n")
            #fout.write("attn = (dot(viewN, ldir) >= 0.0) ? max(0.0, dot(viewN, spotDir)) : 0.0;\n")
            fout.write("attn = max(0.0, dot(viewN, ldir));\n")
            fout.write("cosAttn = float3{};\n".format(CosAtt[colorChannel.litMask&5]))
            fout.write("distAttn = {}(float3{});\n".format("normalize" if (colorChannel.diffuseFunction == DiffuseFunction.NONE) else "", DistAtt[colorChannel.litMask&5]))
            fout.write("attn = max(0.0f, dot(cosAttn, float3(1.0, attn, attn*attn))) / dot(distAttn, float3(1.0, attn, attn*attn));\n")
        elif colorChannel.attenuationFunction == 1:
            # Spot
            fout.write("ldir = unity_LightPosition[0].xyz - viewpos * unity_LightPosition[0].w;\n")
            #fout.write("float3 spotDir = unity_SpotDirection[0].w ? unity_SpotDirection[0].xyz : ldir.xyz;\n")
            fout.write("dist2 = dot(ldir, ldir);\n")
            fout.write("dist = sqrt(dist2);\n")
            fout.write("ldir = ldir / dist;\n")
            #fout.write("attn = max(0.0, dot(ldir, spotDir));\n")
            fout.write("attn = 1.0;\n")
            # attn*attn may overflow
            cosAtt = CosAtt[colorChannel.litMask&5]
            fout.write("attn = max(0.0, {} + {}*attn + {}*attn*attn) / dot(float3{}, float3(1.0,dist,dist2));\n".format(cosAtt[0], cosAtt[1], cosAtt[2], DistAtt[colorChannel.litMask&5]))
        else:
            # None/dir
            fout.write("ldir = normalize(unity_LightPosition[0].xyz - viewpos);\n")
            fout.write("attn = 1.0;\n")
            fout.write("if (length(ldir) == 0.0)\n    ldir = viewN;\n")
        
        if colorChannel.diffuseFunction == DiffuseFunction.NONE:
            fout.write("lacc{0} += attn * unity_LightColor[0]{0};\n".format(suffix))
        else:
            fout.write("lacc{0} += attn * {1}dot(ldir, viewN)) * unity_LightColor[0]{0};\n".format(suffix, "max(0.0," if colorChannel.diffuseFunction == DiffuseFunction.CLAMP else "("))
    
    def genVertLighting(self, mat, fout, useColor1):
        # numColorChans controls the number of color channels available to TEV, but
        # we still need to generate all channels here, as it can be used in texgen.
        fout.write("float4 vertex_color_0, vertex_color_1;\n")
        
        # To use color 1, the vertex descriptor must have color 0 and 1.
        # If color 1 is present but not color 0, it is used for lighting channel 0.
        for i in range(2):
            if i*2+1 >= len(mat.colorChans) or mat.colorChans[i*2+1] is None: continue
            if mat.colorChans[i*2].matColorSource == ColorSrc.VTX or mat.colorChans[i*2].ambColorSource == ColorSrc.VTX or mat.colorChans[i*2+1].matColorSource == ColorSrc.VTX or mat.colorChans[i*2+1].ambColorSource == ColorSrc.VTX:
                if i == 0 or useColor1:
                    # Use color0 for channel 0, and color1 for channel 1 if both colors 0 and 1 are present.
                    fout.write("vertex_color_{0} = v.color{0};\n".format(i))
                elif i == 0:
                    # Use color1 for channel 0 if color0 is not present.
                    fout.write("vertex_color_0 = v.color1;\n")
                #else:
                #    fout.write("vertex_color_{0} = missing_color_value;\n".format(i))
        
        fout.write("half4 lacc;\n"
            "float3 ldir, h, cosAttn, distAttn;\n"
            "float dist, dist2, attn;\n")
        for i in range(2):
            if i*2+1 >= len(mat.colorChans) or mat.colorChans[i*2+1] is None: continue
            fout.write("fixed4 colorChannel{};\n".format(i))
            fout.write("{\n")
            colorChannel = mat.colorChans[i*2]
            if colorChannel.matColorSource == ColorSrc.VTX:
                fout.write("fixed4 mat = vertex_color_{};\n".format(i))
            else:
                fout.write("fixed4 mat = _MatColor{};\n".format(i))
            
            if colorChannel.lightingEnabled:
                if colorChannel.ambColorSource == ColorSrc.VTX:
                    fout.write("lacc = vertex_color_{};\n".format(i))
                else:
                    if i == 0:
                        fout.write("lacc = fixed4(LinearToGammaSpace(UNITY_LIGHTMODEL_AMBIENT.xyz), UNITY_LIGHTMODEL_AMBIENT.w);\n")
                    else:
                        fout.write("lacc = _AmbColor{};\n".format(i))
            else:
                fout.write("lacc = half4(1,1,1,1);\n")
            
            alphaChannel = mat.colorChans[i*2+1]
            if alphaChannel.matColorSource != colorChannel.matColorSource:
                if alphaChannel.matColorSource == ColorSrc.VTX:
                    fout.write("mat.w = vertex_color_{}.w;\n".format(i))
                else:
                    fout.write("mat.w = _MatColor{}.w;\n".format(i))
            
            if alphaChannel.lightingEnabled != colorChannel.lightingEnabled or alphaChannel.ambColorSource != colorChannel.ambColorSource:
                if alphaChannel.lightingEnabled:
                    if alphaChannel.ambColorSource == ColorSrc.VTX:
                        fout.write("lacc.w = vertex_color_{}.w;\n".format(i))
                    else:
                        if i == 0:
                            fout.write("lacc.w = UNITY_LIGHTMODEL_AMBIENT.w;\n")
                        else:
                            fout.write("lacc.w = _AmbColor{}.w;\n".format(i))
                else:
                    fout.write("lacc.w = half(1);\n")
            
            # on GX, need to have different light for diffuse/specular, so
            # just assume 1 light and use it for all calcs
            if colorChannel.lightingEnabled == alphaChannel.lightingEnabled and colorChannel.litMask == alphaChannel.litMask and colorChannel.diffuseFunction == alphaChannel.diffuseFunction and colorChannel.attenuationFunction == alphaChannel.attenuationFunction:
                if colorChannel.lightingEnabled and colorChannel.litMask != 0:
                    self.genLightShader(fout, colorChannel, "")
            else:
                if colorChannel.lightingEnabled and colorChannel.litMask != 0:
                    self.genLightShader(fout, colorChannel, ".xyz")
                if alphaChannel.lightingEnabled and alphaChannel.litMask != 0:
                    self.genLightShader(fout, alphaChannel, ".w")
            
            fout.write("lacc = saturate(lacc);\n")
            fout.write("colorChannel{} = mat * lacc;\n".format(i))
            if i < mat.colorChanNum: fout.write("o.color{0} = colorChannel{0};\n".format(i))
            fout.write("}\n")
        
    def genTexGen(self, mat, fout):
        for i in range(mat.texGenNum):
            texInfo = mat.texCoords[i]
            fout.write("{\n")
            fout.write("float4 src = float4(0.0, 0.0, 1.0, 1.0);\n")
            if texInfo.source == TexGenSrc.POS:
                fout.write("src.xyz = v.vertex;\n")
            elif texInfo.source == TexGenSrc.NRM:
                fout.write("src.xyz = v.normal;\n")
            elif texInfo.source == TexGenSrc.BINRM:
                fout.write("src.xyz = cross(v.normal, v.tangent);\n")
            elif texInfo.source == TexGenSrc.TANGENT:
                fout.write("src.xyz = v.tangent;\n")
            elif texInfo.source >= TexGenSrc.TEX0 and texInfo.source <= TexGenSrc.TEX7:
                fout.write("src.xy = v.texcoord{}.xy;\n".format(texInfo.source-TexGenSrc.TEX0))
            elif texInfo.source >= TexGenSrc.TEXCOORD0 and texInfo.source <= TexGenSrc.TEXCOORD6:
                prevIdx = texInfo.source-TexGenSrc.TEXCOORD0
                prevTexGen = mat.texCoords[prevIdx]
                suffix = "xy" if texGen.type == TexGenType.MTX2x4 or texGen.type == TexGenType.SRTG else "xyz"
                fout.write("src.{} = o.texcoord{};\n".format(suffix, prevIdx))
            else:
                fout.write("src = colorChannel{};\n".format(texInfo.source-TexGenSrc.COLOR0))
            
            if texInfo.type in (TexGenType.MTX3x4, TexGenType.MTX2x4):
                if texInfo.type == TexGenType.MTX3x4:
                    fout.write("float3 texcoord;\n")
                    suffix = ".xyz"
                else:
                    fout.write("float2 texcoord;\n")
                    suffix = ".xy"
                if texInfo.matrix >= TexGenMatrix.PNMTX0 and texInfo.matrix <= TexGenMatrix.PNMTX9:
                    fout.write("texcoord = UnityObjectToViewPos(src){};\n".format(suffix))
                elif texInfo.matrix >= TexGenMatrix.TEXMTX0 and texInfo.matrix <= TexGenMatrix.TEXMTX9:
                    texMtxIdx = (texInfo.matrix-TexGenMatrix.TEXMTX0)//3
                    fout.write("float cosR = cos(_Tex{}_CR.z);\n".format(texMtxIdx))
                    fout.write("float sinR = sin(_Tex{}_CR.z);\n".format(texMtxIdx))
                    fout.write("""texcoord = (
    float3(
        dot(float4(cosR, -sinR, 0, dot(float2(-cosR,  sinR), _Tex{0}_CR.xy)), src),
        dot(float4(sinR,  cosR, 0, dot(float2(-sinR, -cosR), _Tex{0}_CR.xy)), src),
        src.z
    ) * float3(_Tex{0}_ST.xy, 1.0) + float3(_Tex{0}_ST.zw, 0.0) + _Tex{0}_CR.xyz
){1};
""".format(texMtxIdx, suffix))
                elif texInfo.matrix == TexGenMatrix.IDENTITY:
                    fout.write("texcoord = src{};\n".format(suffix))
                else:
                    raise ValueError()
            elif texInfo.type == TexGenType.SRTG:
                fout.write("float3 texcoord = src.xyz;\n")
            else:
                raise ValueError()
            
            if i >= len(mat.postTexGens) or mat.postTexGens[i] is None or mat.postTexGens[i].matrix == TexGenMatrix.DTTIDENTITY:
                fout.write("o.texcoord{} = texcoord;\n".format(i))
            else:
                texMtxIdx = (mat.postTexGens[i].matrix-TexGenMatrix.DTTMTX0)//3
                fout.write("o.texcoord{} = mul(_PostTexMtx{}, texcoord);\n".format(i, texMtxIdx))
            fout.write("}\n")

    def genFrag(self, mat, fout):
        fout.write('    fixed4 col = {1,1,1,1};\n')
        if len(mat.texNos) > 0 and mat.texNos[0] is not None and len(mat.texMtxs) > 0 and mat.texMtxs[0] is not None: fout.write('    col *= tex2D(_Tex0, i.texcoord0);\n')
        if mat.colorChanNum > 0 and usesColorChannel(mat.colorChans[0]): fout.write('    col *= i.color0;\n')
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
                pass#fout.write("    clip(1);\n")
            elif CompareType.NEVER in (mat.alphaComp.comp0, mat.alphaComp.comp1) and mat.alphaComp.op == AlphaOp.AND:
                fout.write("    clip(-1);\n")
            elif (mat.alphaComp.comp0 == CompareType.ALWAYS and mat.alphaComp.op == AlphaOp.AND) or (mat.alphaComp.comp0 == CompareType.NEVER and mat.alphaComp.op == AlphaOp.OR):
                fout.write(makeSimpleComp(mat.alphaComp.comp1, mat.alphaComp.ref1))
            elif (mat.alphaComp.comp1 == CompareType.ALWAYS and mat.alphaComp.op == AlphaOp.AND) or (mat.alphaComp.comp1 == CompareType.NEVER and mat.alphaComp.op == AlphaOp.OR):
                fout.write(makeSimpleComp(mat.alphaComp.comp0, mat.alphaComp.ref0))
            else:
                # fallback/general case
                fout.write("    clip(((%s) %s (%s))?%s);\n"%(makeComp(mat.alphaComp.comp0, mat.alphaComp.ref0), ["&&", "||", "^", "^"][mat.alphaComp.op.value], makeComp(mat.alphaComp.comp1, mat.alphaComp.ref1), ("-1:1" if (mat.alphaComp.op == AlphaOp.XNOR) else "1:-1")))

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

def makeComp(comp, ref):
    if comp == CompareType.ALWAYS: return "1"
    elif comp == CompareType.NEVER: return "0"
    else: return "col.w %s %f"%(["", "<", "==", "<=", ">", "!=", ">="][comp.value], ref/255)

def makeSimpleComp(comp, ref):
    if comp in (CompareType.LESS, CompareType.LEQUAL, CompareType.GREATER, CompareType.GEQUAL):
        if comp == CompareType.LEQUAL:
            ref += 1
            comp = CompareType.LESS
        elif comp == CompareType.GEQUAL:
            ref -= 1
            comp = CompareType.GREATER
        if comp == CompareType.GREATER:
            return "    clip(col.w - %f);\n"%(ref/255)
        else:
            return "    clip(%f - col.w);\n"%(ref/255)
    else:
        return "    clip((%s)?1:-1);\n"%makeComp(comp, ref)

class UnityShaderGen(DXShaderGen):
    def genv2f(self, mat, fout):
        for i, texGen in enumerate(mat.texCoords[:mat.texGenNum]):
            if texGen.type == TexGenType.MTX2x4 or texGen.type == TexGenType.SRTG:
                fout.write('float2')
            else:
                fout.write('float3')
            fout.write(' texcoord%d : TEXCOORD%d;\n'%(i,i))
        for i in range(mat.colorChanNum): fout.write('fixed4 color%d : COLOR%d;\n'%(i,i))
    
    def genUniforms(self, mat, fout):
        for i, color in enumerate(mat.matColors):
            if color is not None: fout.write('fixed4 _MatColor%d;\n'%i)
        for i, color in enumerate(mat.ambColors):
            # use unity_AmbientSky for ambColor 0
            if i != 0 and color is not None: fout.write('fixed4 _AmbColor%d = {%d/255, %d/255, %d/255, %d/255};\n'%((i,)+color))
        for i, color in enumerate(mat.tevColors):
            if color is not None: fout.write('half4 _TevColor%d;\n'%i)
        for i, color in enumerate(mat.tevKColors):
            if color is not None: fout.write('fixed4 _TevKColor%d;\n'%i)
        for i, texIdx in enumerate(mat.texNos):
            if texIdx is not None: fout.write('sampler2D _Tex%d;\n'%i)
        for i, texMtx in enumerate(mat.texMtxs):
            if texMtx is not None: fout.write('float4 _Tex%d_ST;\n'%i)
            if texMtx is not None: fout.write('float4 _Tex%d_CR;\n'%i)
        for i, texMtx in enumerate(mat.postTexMtxs):
            if texMtx is not None: fout.write('float4x4 _PostTexMtx%d = {%s};\n'%(i, ", ".join(map(str, texMtx.effectMatrix))))
    
    def genVertPrefix(self, mat, fout):
        fout.write("float3 viewpos = UnityObjectToViewPos(v.vertex);\n")
        if usesNormal(mat): fout.write("float3 viewN = normalize (mul ((float3x3)UNITY_MATRIX_IT_MV, v.normal));\n")
        fout.write("o.vertex = UnityViewToClipPos(viewpos);\n")
    
    def gen(self, mat, fout, useColor1):
        fout.write('Shader "J3D/%s" {\n'%mat.name)
        
        fout.write('Properties {\n')
        # Note: Unity converts colors from sRGB *if* they are marked as "Color"
        # in the ShaderLab properties. "Vector" types are not converted.
        for i, color in enumerate(mat.matColors):
            if color is not None: fout.write('_MatColor%d ("Material color %d", Vector) = (0, 0, 0, 1)\n'%(i,i))
        # amb color is never animated. also use unity_AmbientSky for ambColor 0
        #for i, color in enumerate(mat.ambColors):
        #    if color is not None: fout.write('_AmbColor%d ("Ambient color %d", Vector) = (0, 0, 0, 1)\n'%(i,i))
        for i, color in enumerate(mat.tevColors):
            if color is not None: fout.write('[HDR] _TevColor%d ("TEV color %d", Vector) = (0, 0, 0, 1)\n'%(i,i))
        for i, color in enumerate(mat.tevKColors):
            if color is not None: fout.write('_TevKColor%d ("TEV constant color %d", Vector) = (0, 0, 0, 1)\n'%(i,i))
        for i in range(8):
            # note: texMtx and texNo do not necessarily correspond
            texMtx = mat.texMtxs[i] if i < len(mat.texMtxs) else None
            texIdx = mat.texNos[i] if i < len(mat.texNos) else None
            if texMtx is None and texIdx is None: continue
            if texMtx is None: fout.write('[NoScaleOffset] ')
            fout.write('_Tex%d ("Texture '%i)
            if texIdx is not None:
                fout.write('slot')
                if texMtx is not None: fout.write('/')
            if texMtx is not None: fout.write('matrixST')
            fout.write(' %d", 2D) = "black" {}\n'%i)
        # still need texmtx center, rotation
        for i, texMtx in enumerate(mat.texMtxs):
            if texMtx is not None: fout.write('_Tex%d_CR ("Texture matrixCR %d", Vector) = (0, 0, 0, 0)\n'%(i,i))
        fout.write('}\n') # Properties
        
        fout.write('CGINCLUDE\n')
        fout.write('#include "UnityCG.cginc"\n')
        
        fout.write('struct appdata_t {\n')
        fout.write('float3 vertex : POSITION;\n')
        if usesTexGenInput(mat, TexGenSrc.TANGENT) or usesBump(mat): fout.write('float3 tangent : TANGENT;\n')
        if usesNormal(mat) or usesTexGenInput(mat, TexGenSrc.NRM): fout.write('float3 normal : NORMAL;\n')
        for i in range(8):
            if usesTexGenInput(mat, TexGenSrc.TEX0+i): fout.write('float2 texcoord%d : TEXCOORD%d;\n'%(i,i))
        for i in range(2):
            if i*2+1 >= len(mat.colorChans) or mat.colorChans[i*2+1] is None: continue
            if usesColorChannel(mat.colorChans[i*2]) or usesColorChannel(mat.colorChans[i*2+1]): fout.write('fixed4 color%d : COLOR%d;\n'%(i,i))
        fout.write('UNITY_VERTEX_INPUT_INSTANCE_ID\n')
        fout.write('};\n') # struct appdata_t
        
        self.genUniforms(mat, fout)
        fout.write('ENDCG\n')

        fout.write('SubShader {\n')
        
        fout.write('Tags { ')
        if mat.materialMode == 4: # XLU
            fout.write('"Queue" = "Transparent" ')
            fout.write('"RenderType" = "Transparent" ')
            fout.write('"IgnoreProjector"="True" ')
        else:
            if mat.zCompLoc is not None:
                if mat.zCompLoc:
                    fout.write('"Queue" = "Geometry" ')
                    fout.write('"RenderType" = "Opaque" ')
                else:
                    fout.write('"Queue" = "AlphaTest" ')
                    fout.write('"RenderType" = "TransparentCutout" ')
                    fout.write('"IgnoreProjector"="True" ')
        fout.write('}\n') # Tags
        
        fout.write('LOD 100\n')
        if mat.blend is not None:
            fout.write('Blend ')
            if mat.blend.blendMode == BlendMode.NONE:
                fout.write('Off\n')
            else:
                fout.write(['Zero', 'One', 'SrcColor', 'OneMinusSrcColor', 'SrcAlpha', 'OneMinusSrcAlpha', 'DstAlpha', 'OneMinusDstAlpha'][mat.blend.srcFactor.value])
                fout.write(' ')
                fout.write(['Zero', 'One', 'SrcColor', 'OneMinusSrcColor', 'SrcAlpha', 'OneMinusSrcAlpha', 'DstAlpha', 'OneMinusDstAlpha'][mat.blend.dstFactor.value])
                fout.write('\n')
                fout.write('BlendOp ')
                if mat.blend.blendMode == BlendMode.BLEND:
                    fout.write('Add\n')
                elif mat.blend.blendMode == BlendMode.LOGIC:
                    fout.write('Logical')
                    fout.write(['Clear', 'And', 'AndReverse', 'Copy', 'AndInverted', 'Noop', 'Xor', 'Or', 'Nor', 'Equiv', 'Invert', 'OrReverse', 'CopyInverted', 'OrInverted', 'Nand', 'Set'][mat.blend.logicOp.value])
                    fout.write('\n')
                elif mat.blend.blendMode == BlendMode.SUBTRACT:
                    fout.write('Sub\n')
        if mat.cullMode is not None:
            if mat.cullMode == CullMode.ALL:
                fout.write('ColorMask 0\n')
            else:
                fout.write('Cull ')
                fout.write(['Off', 'Front', 'Back'][mat.cullMode.value])
                fout.write('\n')
        if mat.zMode is not None:
            if mat.zMode.enable and mat.zMode.func == CompareType.NEVER:
                fout.write('ColorMask 0\n')
            else:
                fout.write('ZTest ')
                if mat.zMode.enable:
                    fout.write(['Never', 'Less', 'Equal', 'LEqual', 'Greater', 'NotEqual', 'GEqual', 'Always'][mat.zMode.func.value])
                else:
                    fout.write('Always')
                fout.write('\n')
            fout.write('ZWrite ')
            fout.write(['Off', 'On'][mat.zMode.writeZ])
            fout.write('\n')
        
        fout.write('Pass {\n')
        fout.write('LOD 100\n')
        
        fout.write('Tags { ')
        if any(colorChan is not None and colorChan.lightingEnabled for colorChan in mat.colorChans):
            fout.write('"LightMode" = "Vertex" ')
        else:
            fout.write('"LightMode" = "Always" ')
        fout.write('}\n') # Tags
        
        fout.write('CGPROGRAM\n')
        fout.write('#pragma vertex vert\n')
        fout.write('#pragma fragment frag\n')
        fout.write('#pragma target 2.0\n')
        if mat.fog is not None: fout.write('#pragma multi_compile_fog\n')
        
        fout.write('struct v2f {\n')
        fout.write('float4 vertex : SV_POSITION;\n')
        self.genv2f(mat, fout)
        if mat.fog is not None: fout.write('UNITY_FOG_COORDS(%d)\n'%mat.texGenNum)
        fout.write('UNITY_VERTEX_OUTPUT_STEREO\n')
        fout.write('};\n') # struct v2f
        
        fout.write("""v2f vert (appdata_t v)
{
    v2f o;
    UNITY_SETUP_INSTANCE_ID(v);
    UNITY_INITIALIZE_VERTEX_OUTPUT_STEREO(o);
""")
        self.genVertPrefix(mat, fout)
        self.genVertLighting(mat, fout, useColor1)
        self.genTexGen(mat, fout)
        if mat.fog is not None: fout.write('UNITY_TRANSFER_FOG(o,o.vertex);\n')
        fout.write("""    return o;
}

half4 frag (v2f i) : SV_Target
{
""")
        self.genFrag(mat, fout)
        fout.write("""    #ifdef UNITY_COLORSPACE_GAMMA
    half4 ret = col;
    #else
    half4 ret = half4(GammaToLinearSpace(col.xyz), col.w);
    #endif
    UNITY_APPLY_FOG(i.fogCoord, ret);
    return ret;
}
""")
        fout.write('ENDCG\n')
        
        fout.write('}\n') # Pass
        
        if mat.materialMode != 4:
            fout.write("""Pass
{
    Tags { "LightMode" = "ShadowCaster" }
    LOD 80
    CGPROGRAM
    #pragma vertex vertShadow
    #pragma fragment fragShadow
    #pragma target 2.0
    #pragma multi_compile_shadowcaster
    struct v2fShadow {
        V2F_SHADOW_CASTER;
""")
            if not mat.zCompLoc: self.genv2f(mat, fout)
            fout.write("""        UNITY_VERTEX_OUTPUT_STEREO
    };

    v2fShadow vertShadow("""+("appdata_base" if mat.zCompLoc else "appdata_t")+""" v)
    {
        v2fShadow o;
        UNITY_SETUP_INSTANCE_ID(v);
        UNITY_INITIALIZE_VERTEX_OUTPUT_STEREO(o);
""")
            if mat.zCompLoc or usesNormal(mat): fout.write('        TRANSFER_SHADOW_CASTER_NORMALOFFSET(o)\n')
            else: fout.write('        TRANSFER_SHADOW_CASTER(o)\n')
            if not mat.zCompLoc:
                self.genTexGen(mat, fout)
            fout.write("""        return o;
    }

    float4 fragShadow(v2fShadow i) : SV_Target
    {
""")
            if not mat.zCompLoc: self.genFrag(mat, fout)
            fout.write("""        SHADOW_CASTER_FRAGMENT(i)
    }
    ENDCG
}
""")
        
        fout.write('}\n') # SubShader
        fout.write('}\n') # Shader

