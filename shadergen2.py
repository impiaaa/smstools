from bmd import *

class GenericShaderGen: pass

class DXShaderGen(GenericShaderGen): pass

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
    else: return "col.a %s %f"%(["", "<", "==", "<=", ">", "!=", ">="][comp.value], ref/255)

class UnityShaderGen(DXShaderGen):
    def genv2f(self, mat, fout):
        for i, texGen in enumerate(mat.texCoords[:mat.texGenNum]):
            if texGen.type == TexGenType.MTX2x4 or texGen.type == TexGenType.SRTG:
                fout.write('float2')
            else:
                fout.write('float3')
            fout.write(' texcoord%d : TEXCOORD%d;\n'%(i,i))
        for i in range(mat.colorChanNum): fout.write('fixed4 color%d : COLOR%d;\n'%(i,i))
    
    def genVert(self, mat, fout):
        for i in range(min(mat.texGenNum, len(mat.texNos), len(mat.texMtxs))):
            if mat.texNos[i] is not None and mat.texMtxs[i] is not None and usesTexGenInput(mat, TexGenSrc.TEX0+i): fout.write('    o.texcoord%d = TRANSFORM_TEX(v.texcoord%d, _Tex%d);\n'%(i,i,i))
        for i in range(mat.colorChanNum):
            if usesColorChannel(mat.colorChans[i*2]) or usesColorChannel(mat.colorChans[i*2+1]): fout.write('    o.color%d = v.color%d;\n'%(i,i))
        if mat.fog is not None: fout.write('    UNITY_TRANSFER_FOG(o,o.vertex);\n')
    
    def genFrag(self, mat, fout):
        fout.write('    fixed4 col = {1,1,1,1};\n')
        if len(mat.texNos) > 0 and mat.texNos[0] is not None and len(mat.texMtxs) > 0 and mat.texMtxs[0] is not None: fout.write('    col *= tex2D(_Tex0, i.texcoord0);\n')
        if mat.colorChanNum > 0 and usesColorChannel(mat.colorChans[0]): fout.write('    col *= i.color0;\n')
        if mat.alphaComp is not None:
            fout.write("    clip(((%s) %s (%s))?%s);\n"%(makeComp(mat.alphaComp.comp0, mat.alphaComp.ref0), ["&&", "||", "^", "^"][mat.alphaComp.op.value], makeComp(mat.alphaComp.comp1, mat.alphaComp.ref1), ("-1:1" if (mat.alphaComp.op == AlphaOp.XNOR) else "1:-1")))
    
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
    
    def gen(self, mat, fout):
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
        for i in range(mat.colorChanNum):
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
            fout.write('"LightMode" = "ForwardBase" ')
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
    o.vertex = UnityObjectToClipPos(v.vertex);
""")
        self.genVert(mat, fout)
        fout.write("""    return o;
}

half4 frag (v2f i) : SV_Target
{
""")
        self.genFrag(mat, fout)
        fout.write("""    #ifdef UNITY_COLORSPACE_GAMMA
    half4 ret = col;
    #else
    half4 ret = half4(GammaToLinearSpace(col), col.a);
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
            else: fout.write('    TRANSFER_SHADOW_CASTER(o)\n')
            if not mat.zCompLoc: self.genVert(mat, fout)
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

