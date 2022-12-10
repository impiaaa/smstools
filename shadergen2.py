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

# FIXME: hardcoded to sunshine
CosAtt = {1<<0: (1, 0, 0), 1<<2: (0, 0, 1)}
DistAtt = {1<<0: (1, 0, 0), 1<<2: (25, 0, -24)}
# Copied from Dolphin
class DXShaderGen:
    def genLightShader(self, fout, colorChannel, suffix):
        if colorChannel.attenuationFunction == 0:
            # Spec
            fout.writeLine("ldir = unity_LightPosition[0].xyz - viewpos * unity_LightPosition[0].w;")
            #fout.writeLine("float3 spotDir = unity_SpotDirection[0].w ? unity_SpotDirection[0].xyz : ldir.xyz;")
            fout.writeLine("ldir = normalize(ldir);")
            #fout.writeLine("attn = (dot(viewN, ldir) >= 0.0) ? max(0.0, dot(viewN, spotDir)) : 0.0;")
            fout.writeLine("attn = max(0.0, dot(viewN, ldir));")
            fout.writeLine("cosAttn = float3{};".format(CosAtt[colorChannel.litMask&5]))
            fout.writeLine("distAttn = {}(float3{});".format("normalize" if (colorChannel.diffuseFunction == DiffuseFunction.NONE) else "", DistAtt[colorChannel.litMask&5]))
            fout.writeLine("attn = max(0.0f, dot(cosAttn, float3(1.0, attn, attn*attn))) / dot(distAttn, float3(1.0, attn, attn*attn));")
        elif colorChannel.attenuationFunction == 1:
            # Spot
            fout.writeLine("ldir = unity_LightPosition[0].xyz - viewpos * unity_LightPosition[0].w;")
            #fout.writeLine("float3 spotDir = unity_SpotDirection[0].w ? unity_SpotDirection[0].xyz : ldir.xyz;")
            fout.writeLine("dist2 = dot(ldir, ldir);")
            fout.writeLine("dist = sqrt(dist2);")
            fout.writeLine("ldir = ldir / dist;")
            #fout.writeLine("attn = max(0.0, dot(ldir, spotDir));")
            fout.writeLine("attn = 1.0;")
            # attn*attn may overflow
            cosAtt = CosAtt[colorChannel.litMask&5]
            fout.writeLine("attn = max(0.0, {} + {}*attn + {}*attn*attn) / dot(float3{}, float3(1.0,dist,dist2));".format(cosAtt[0], cosAtt[1], cosAtt[2], DistAtt[colorChannel.litMask&5]))
        else:
            # None/dir
            fout.writeLine("ldir = normalize(unity_LightPosition[0].xyz - viewpos * unity_LightPosition[0].w);")
            fout.writeLine("attn = 1.0;")
            fout.writeLine("if (length(ldir) == 0.0)\n    ldir = viewN;")
        
        if colorChannel.diffuseFunction == DiffuseFunction.NONE:
            fout.writeLine("lacc{0} += attn * unity_LightColor[0]{0};".format(suffix))
        else:
            fout.writeLine("lacc{0} += attn * {1}dot(ldir, viewN)) * unity_LightColor[0]{0};".format(suffix, "max(0.0," if colorChannel.diffuseFunction == DiffuseFunction.CLAMP else "("))
    
    def genVertLighting(self, mat, fout, useColor1, lightingEnabled=True, alphaOnly=False):
        # numColorChans controls the number of color channels available to TEV, but
        # we still need to generate all channels here, as it can be used in texgen.
        fout.writeLine("float4 vertex_color_0, vertex_color_1;")
        
        # To use color 1, the vertex descriptor must have color 0 and 1.
        # If color 1 is present but not color 0, it is used for lighting channel 0.
        for i in range(2):
            if i*2+1 >= len(mat.colorChans) or mat.colorChans[i*2+1] is None: continue
            if mat.colorChans[i*2].matColorSource == ColorSrc.VTX or mat.colorChans[i*2].ambColorSource == ColorSrc.VTX or mat.colorChans[i*2+1].matColorSource == ColorSrc.VTX or mat.colorChans[i*2+1].ambColorSource == ColorSrc.VTX:
                if i == 0 or useColor1:
                    # Use color0 for channel 0, and color1 for channel 1 if both colors 0 and 1 are present.
                    fout.writeLine("vertex_color_{0} = v.color{0};".format(i))
                elif i == 0:
                    # Use color1 for channel 0 if color0 is not present.
                    fout.writeLine("vertex_color_0 = v.color1;")
                #else:
                #    fout.writeLine("vertex_color_{0} = missing_color_value;".format(i))
        
        fout.writeLine("half4 lacc;")
        fout.writeLine("float3 ldir, h, cosAttn, distAttn;")
        fout.writeLine("float dist, dist2, attn;")
        for i in range(2):
            if i*2+1 >= len(mat.colorChans) or mat.colorChans[i*2+1] is None: continue
            fout.writeLine("fixed4 colorChannel{};".format(i))
            with fout:
                colorChannel = mat.colorChans[i*2]
                if colorChannel.matColorSource == ColorSrc.VTX:
                    fout.writeLine("fixed4 mat = vertex_color_{};".format(i))
                else:
                    fout.writeLine("fixed4 mat = _MatColor{};".format(i))
                
                if colorChannel.lightingEnabled and lightingEnabled:
                    if colorChannel.ambColorSource == ColorSrc.VTX:
                        fout.writeLine("lacc = vertex_color_{};".format(i))
                    else:
                        if i == 0:
                            fout.writeLine("lacc = fixed4(LinearToGammaSpace(UNITY_LIGHTMODEL_AMBIENT.xyz), UNITY_LIGHTMODEL_AMBIENT.w);")
                        else:
                            fout.writeLine("lacc = _AmbColor{};".format(i))
                else:
                    fout.writeLine("lacc = half4(1,1,1,1);")
                
                alphaChannel = mat.colorChans[i*2+1]
                if alphaChannel.matColorSource != colorChannel.matColorSource:
                    if alphaChannel.matColorSource == ColorSrc.VTX:
                        fout.writeLine("mat.w = vertex_color_{}.w;".format(i))
                    else:
                        fout.writeLine("mat.w = _MatColor{}.w;".format(i))
                
                if alphaChannel.lightingEnabled != colorChannel.lightingEnabled or alphaChannel.ambColorSource != colorChannel.ambColorSource:
                    if alphaChannel.lightingEnabled and lightingEnabled:
                        if alphaChannel.ambColorSource == ColorSrc.VTX:
                            fout.writeLine("lacc.w = vertex_color_{}.w;".format(i))
                        else:
                            if i == 0:
                                fout.writeLine("lacc.w = UNITY_LIGHTMODEL_AMBIENT.w;")
                            else:
                                fout.writeLine("lacc.w = _AmbColor{}.w;".format(i))
                    else:
                        fout.writeLine("lacc.w = half(1);")
                
                # on GX, need to have different light for diffuse/specular, so
                # just assume 1 light and use it for all calcs
                if not alphaOnly and colorChannel.lightingEnabled == alphaChannel.lightingEnabled and colorChannel.litMask == alphaChannel.litMask and colorChannel.diffuseFunction == alphaChannel.diffuseFunction and colorChannel.attenuationFunction == alphaChannel.attenuationFunction:
                    if colorChannel.lightingEnabled and colorChannel.litMask != 0 and lightingEnabled:
                        self.genLightShader(fout, colorChannel, "")
                else:
                    if colorChannel.lightingEnabled and colorChannel.litMask != 0 and lightingEnabled and not alphaOnly:
                        self.genLightShader(fout, colorChannel, ".xyz")
                    if alphaChannel.lightingEnabled and alphaChannel.litMask != 0 and lightingEnabled:
                        self.genLightShader(fout, alphaChannel, ".w")
                
                fout.writeLine("lacc = saturate(lacc);")
                fout.writeLine("colorChannel{} = mat * lacc;".format(i))
                if i < mat.colorChanNum: fout.writeLine("o.color{0} = colorChannel{0};".format(i))
        
    def genTexGen(self, mat, fout):
        for i in range(mat.texGenNum):
            texInfo = mat.texCoords[i]
            with fout:
                fout.writeLine("float4 src = float4(0.0, 0.0, 1.0, 1.0);")
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
                    fout.writeLine("src.{} = o.texcoord{};".format(suffix, prevIdx))
                else:
                    fout.writeLine("src = colorChannel{};".format(texInfo.source-TexGenSrc.COLOR0))
                
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
                        fout.writeLine("float cosR = cos(_Tex{}_CR.z);".format(texMtxIdx))
                        fout.writeLine("float sinR = sin(_Tex{}_CR.z);".format(texMtxIdx))
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
                        raise ValueError()
                elif texInfo.type == TexGenType.SRTG:
                    fout.writeLine("float3 texcoord = src.xyz;")
                else:
                    raise ValueError()
                
                if i >= len(mat.postTexGens) or mat.postTexGens[i] is None or mat.postTexGens[i].matrix == TexGenMatrix.DTTIDENTITY:
                    fout.writeLine("o.texcoord{} = texcoord;".format(i))
                else:
                    texMtxIdx = (mat.postTexGens[i].matrix-TexGenMatrix.DTTMTX0)//3
                    fout.writeLine("o.texcoord{} = mul(_PostTexMtx{}, texcoord);".format(i, texMtxIdx))

    def genFrag(self, mat, fout):
        fout.writeLine("fixed4 col = {1,1,1,1};")
        if len(mat.texNos) > 0 and mat.texNos[0] is not None and len(mat.texMtxs) > 0 and mat.texMtxs[0] is not None: fout.writeLine("col *= tex2D(_Tex0, i.texcoord0);")
        if mat.colorChanNum > 0 and usesColorChannel(mat.colorChans[0]): fout.writeLine("col *= i.color0;")
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
                pass#fout.writeLine("clip(1);")
            elif CompareType.NEVER in (mat.alphaComp.comp0, mat.alphaComp.comp1) and mat.alphaComp.op == AlphaOp.AND:
                fout.writeLine("clip(-1);")
            elif (mat.alphaComp.comp0 == CompareType.ALWAYS and mat.alphaComp.op == AlphaOp.AND) or (mat.alphaComp.comp0 == CompareType.NEVER and mat.alphaComp.op == AlphaOp.OR):
                fout.writeLine(makeSimpleComp(mat.alphaComp.comp1, mat.alphaComp.ref1))
            elif (mat.alphaComp.comp1 == CompareType.ALWAYS and mat.alphaComp.op == AlphaOp.AND) or (mat.alphaComp.comp1 == CompareType.NEVER and mat.alphaComp.op == AlphaOp.OR):
                fout.writeLine(makeSimpleComp(mat.alphaComp.comp0, mat.alphaComp.ref0))
            else:
                # fallback/general case
                fout.writeLine("clip((({}) {} ({}))?{});".format(makeComp(mat.alphaComp.comp0, mat.alphaComp.ref0), ["&&", "||", "^", "^"][mat.alphaComp.op.value], makeComp(mat.alphaComp.comp1, mat.alphaComp.ref1), ("-1:1" if (mat.alphaComp.op == AlphaOp.XNOR) else "1:-1")))

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
    else: return "col.w {} {}".format(["", "<", "==", "<=", ">", "!=", ">="][comp.value], ref/255)

def makeSimpleComp(comp, ref):
    if comp in (CompareType.LESS, CompareType.LEQUAL, CompareType.GREATER, CompareType.GEQUAL):
        if comp == CompareType.LEQUAL:
            ref += 1
            comp = CompareType.LESS
        elif comp == CompareType.GEQUAL:
            ref -= 1
            comp = CompareType.GREATER
        if comp == CompareType.GREATER:
            return "clip(col.w - {});".format(ref/255)
        else:
            return "clip({} - col.w);".format(ref/255)
    else:
        return "clip(({})?1:-1);".format(makeComp(comp, ref))

class UnityShaderGen(DXShaderGen):
    def genv2f(self, mat, fout):
        for i, texGen in enumerate(mat.texCoords[:mat.texGenNum]):
            fout.writeLine("{0} texcoord{1} : TEXCOORD{1};".format("float2" if texGen.type in (TexGenType.MTX2x4, TexGenType.SRTG) else "float3", i))
        for i in range(mat.colorChanNum): fout.writeLine("fixed4 color{0} : COLOR{0};".format(i))
    
    def genUniforms(self, mat, fout):
        for i, color in enumerate(mat.matColors):
            if color is not None: fout.writeLine("fixed4 _MatColor{};".format(i))
        for i, color in enumerate(mat.ambColors):
            # use unity_AmbientSky for ambColor 0
            if i != 0 and color is not None: fout.writeLine("const fixed4 _AmbColor{0} = {{{1[0]}/255, {1[1]}/255, {1[2]}/255, {1[3]}/255}};".format(i, color))
        for i, color in enumerate(mat.tevColors):
            if color is not None: fout.writeLine("half4 _TevColor{};".format(i))
        for i, color in enumerate(mat.tevKColors):
            if color is not None: fout.writeLine("fixed4 _TevKColor{};".format(i))
        for i, texIdx in enumerate(mat.texNos):
            if texIdx is not None: fout.writeLine("sampler2D _Tex{};".format(i))
        for i, texMtx in enumerate(mat.texMtxs):
            if texMtx is not None: fout.writeLine("float4 _Tex{}_ST;".format(i))
            if texMtx is not None: fout.writeLine("float4 _Tex{}_CR;".format(i))
        for i, texMtx in enumerate(mat.postTexMtxs):
            if texMtx is not None: fout.writeLine("const float4x4 _PostTexMtx{} = {{{}}};".format(i, ", ".join(map(str, texMtx.effectMatrix))))
    
    def genAttributes(self, mat, fout):
        if usesTexGenInput(mat, TexGenSrc.TANGENT) or usesBump(mat): fout.writeLine("float3 tangent : TANGENT;")
        if usesNormal(mat) or usesTexGenInput(mat, TexGenSrc.NRM): fout.writeLine("float3 normal : NORMAL;")
        for i in range(8):
            if usesTexGenInput(mat, TexGenSrc.TEX0+i): fout.writeLine("float2 texcoord{0} : TEXCOORD{0};".format(i))
        for i in range(2):
            if i*2+1 >= len(mat.colorChans) or mat.colorChans[i*2+1] is None: continue
            if usesColorChannel(mat.colorChans[i*2]) or usesColorChannel(mat.colorChans[i*2+1]): fout.writeLine("fixed4 color{0} : COLOR{0};".format(i))
    
    def gen(self, mat, fout, useColor1):
        fout.writeLine("Shader \"J3D/{}\"".format(mat.name))
        with fout:
            fout.writeLine("Properties")
            with fout:
                # Note: Unity converts colors from sRGB *if* they are marked as "Color"
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
                    if texMtx is not None: fout.writeLine("_Tex{0}_CR (\"Texture matrix {0} CR\", Vector) = (0, 0, 0, 0)".format(i))
                # postTexMtx is never animated
            
            if all(colorChan is None or not colorChan.lightingEnabled or colorChan.litMask == 0 for colorChan in mat.colorChans): fout.writeLine("CustomEditor \"EmissiveShaderGUI\"")
            
            fout.writeLine("CGINCLUDE")
            fout.indent += 1
            
            fout.writeLine("#include \"UnityCG.cginc\"")
            
            fout.writeLine("struct appdata_t")
            with fout:
                fout.writeLine("float3 vertex : POSITION;")
                self.genAttributes(mat, fout)
                fout.writeLine("UNITY_VERTEX_INPUT_INSTANCE_ID")
            fout.writeLine(";")
            
            self.genUniforms(mat, fout)
            
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
                
                fout.writeLine("LOD 100")
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
                    fout.writeLine("LOD 100")
                    
                    fout.writeLine("Tags")
                    with fout:
                        if any(colorChan is not None and colorChan.lightingEnabled for colorChan in mat.colorChans):
                            fout.writeLine('"LightMode" = "Vertex"')
                        else:
                            fout.writeLine('"LightMode" = "Always"')
                    
                    fout.writeLine("CGPROGRAM")
                    fout.indent += 1
                    
                    fout.writeLine("#pragma vertex vert")
                    fout.writeLine("#pragma fragment frag")
                    fout.writeLine("#pragma target 2.0")
                    if mat.fog is not None: fout.writeLine("#pragma multi_compile_fog")
                    
                    fout.writeLine("struct v2f")
                    with fout:
                        fout.writeLine("float4 position : SV_POSITION;")
                        self.genv2f(mat, fout)
                        if mat.fog is not None: fout.writeLine("UNITY_FOG_COORDS({})".format(mat.texGenNum))
                        fout.writeLine("UNITY_VERTEX_OUTPUT_STEREO")
                    fout.writeLine(";")
                    
                    fout.writeLine("v2f vert(appdata_t v)")
                    with fout:
                        fout.writeLine("v2f o;")
                        fout.writeLine("UNITY_SETUP_INSTANCE_ID(v);")
                        fout.writeLine("UNITY_INITIALIZE_VERTEX_OUTPUT_STEREO(o);")
                        fout.writeLine("float3 viewpos = UnityObjectToViewPos(v.vertex);")
                        if usesNormal(mat): fout.writeLine("float3 viewN = normalize (mul((float3x3)UNITY_MATRIX_IT_MV, v.normal));")
                        fout.writeLine("o.position = UnityViewToClipPos(viewpos);")
                        self.genVertLighting(mat, fout, useColor1)
                        self.genTexGen(mat, fout)
                        if mat.fog is not None: fout.writeLine("UNITY_TRANSFER_FOG(o,o.position);")
                        fout.writeLine("return o;")

                    fout.writeLine("half4 frag(v2f i) : SV_Target")
                    with fout:
                        self.genFrag(mat, fout)
                        fout.writeLine("#ifdef UNITY_COLORSPACE_GAMMA")
                        fout.writeLine("    half4 ret = col;")
                        fout.writeLine("#else")
                        fout.writeLine("    half4 ret = half4(GammaToLinearSpace(col.xyz), col.w);")
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
                        fout.writeLine("struct v2fShadow")
                        with fout:
                            fout.writeLine("V2F_SHADOW_CASTER;")
                            if not mat.zCompLoc: self.genv2f(mat, fout)
                            fout.writeLine("UNITY_VERTEX_OUTPUT_STEREO")
                        fout.writeLine(";")

                        fout.writeLine("v2fShadow vertShadow({} v)".format("appdata_base" if mat.zCompLoc else "appdata_t"))
                        with fout:
                            fout.writeLine("v2fShadow o;")
                            fout.writeLine("UNITY_SETUP_INSTANCE_ID(v);")
                            fout.writeLine("UNITY_INITIALIZE_VERTEX_OUTPUT_STEREO(o);")
                            if mat.zCompLoc or usesNormal(mat): fout.writeLine("TRANSFER_SHADOW_CASTER_NORMALOFFSET(o)")
                            else: fout.writeLine("TRANSFER_SHADOW_CASTER(o)")
                            if not mat.zCompLoc:
                                self.genVertLighting(mat, fout, useColor1, lightingEnabled=False, alphaOnly=True)
                                self.genTexGen(mat, fout)
                            fout.writeLine("return o;")

                        fout.writeLine("float4 fragShadow(v2fShadow i) : SV_Target")
                        with fout:
                            if not mat.zCompLoc: self.genFrag(mat, fout)
                            fout.writeLine("SHADOW_CASTER_FRAGMENT(i)")
                        
                        fout.indent -= 1
                        fout.writeLine("ENDCG")
                
                # only do meta pass for unlit materials.
                if all(colorChan is None or not colorChan.lightingEnabled or colorChan.litMask == 0 for colorChan in mat.colorChans):
                    fout.writeLine("Pass")
                    with fout:
                        fout.writeLine("Tags { \"LightMode\" = \"Meta\" }")
                        fout.writeLine("Cull Off")
                        fout.writeLine("CGPROGRAM")
                        fout.indent += 1
                        
                        fout.writeLine("#pragma vertex vert_meta")
                        fout.writeLine("#pragma fragment frag_meta")
                        fout.writeLine("#include \"UnityMetaPass.cginc\"")
 
                        fout.writeLine("struct appdata_lightmapped_t")
                        with fout:
                            fout.writeLine("float4 vertex : POSITION;")
                            self.genAttributes(mat, fout)
                            fout.writeLine("float2 lightMapUV : TEXCOORD{};".format(min(i for i in range(8) if not usesTexGenInput(mat, TexGenSrc.TEX0+i))))
                        fout.writeLine(";")
                        
                        fout.writeLine("struct v2f_meta")
                        with fout:
                            fout.writeLine("float4 position : SV_POSITION;")
                            self.genv2f(mat, fout)
                        fout.writeLine(";")
                        
                        fout.writeLine("v2f_meta vert_meta(appdata_lightmapped_t v)")
                        with fout:
                            fout.writeLine("v2f_meta o;")
                            fout.writeLine("o.position = UnityMetaVertexPosition(v.vertex, {}, {}, unity_LightmapST, unity_DynamicLightmapST);".format("v.texcoord1" if usesTexGenInput(mat, TexGenSrc.TEX1) else "v.lightMapUV", "v.texcoord2" if usesTexGenInput(mat, TexGenSrc.TEX2) else "v.lightMapUV"))
                            # it shouldn't generate any actual light shaders, but we need it to get mat/vtx colors
                            self.genVertLighting(mat, fout, useColor1)
                            self.genTexGen(mat, fout)
                            fout.writeLine("return o;")
                        
                        fout.writeLine("float4 frag_meta (v2f_meta i) : SV_Target")
                        with fout:
                            self.genFrag(mat, fout)
                            fout.writeLine("half4 res = {0, 0, 0, 1};")
                            # only support unlit materials as emissive
                            fout.writeLine("if (unity_MetaFragmentControl.y)")
                            with fout: fout.writeLine("res.xyz = GammaToLinearSpace(col.xyz);")
                            fout.writeLine("return res;")
                        
                        fout.indent -= 1
                        fout.writeLine("ENDCG")

