from warnings import warn
import sys
from common import *
assert sys.version_info[0] >= 3

class Bck(Section):
    def read(self, fin):
        signature, fileLength, chunkCount, svr = unpack('>8sLL4s12x', fin.read(0x20))
        for chunkno in range(chunkCount):
            start = fin.tell()
            try: chunk, size = unpack('>4sL', fin.read(8))
            except StructError:
                warn("File too small for chunk count of "+str(chunkCount))
                continue
            if chunk == b"ANK1":
                self.ank1 = Ank1()
                self.ank1.read(fin, start, size)
            else:
                warn("Unsupported section %r" % chunk)
            fin.seek(start+size)

def convRotation(rots, scale):
    for r in rots:
        r.value *= scale
        r.tangent *= scale

class Ank1(Section):
    header = Struct('>BBHHHHHIIII')
    def read(self, fin, start, size):
        self.loopFlags, angleMultiplier, self.animationLength, \
        numJoints, scaleCount, rotCount, transCount, \
        offsetToJoints, offsetToScales, offsetToRots, offsetToTrans = self.header.unpack(fin.read(28))
        
        scales = array('f')
        fin.seek(start+offsetToScales)
        scales.fromfile(fin, scaleCount)
        if sys.byteorder == 'little': scales.byteswap()
        
        rotations = array('h')
        fin.seek(start+offsetToRots)
        rotations.fromfile(fin, rotCount)
        if sys.byteorder == 'little': rotations.byteswap()

        translations = array('f')
        fin.seek(start+offsetToTrans)
        translations.fromfile(fin, transCount)
        if sys.byteorder == 'little': translations.byteswap()
        
        rotScale = float(1<<angleMultiplier)*math.pi/32768.0
        fin.seek(start+offsetToJoints)
        self.anims = [None]*numJoints
        for i in range(numJoints):
            joint = AnimatedJoint()
            joint.read(fin)
            
            anim = Animation()
            
            anim.scalesX = readComp(scales, joint.x.s)
            anim.scalesY = readComp(scales, joint.y.s)
            anim.scalesZ = readComp(scales, joint.z.s)

            anim.rotationsX = readComp(rotations, joint.x.r)
            convRotation(anim.rotationsX, rotScale)
            anim.rotationsY = readComp(rotations, joint.y.r)
            convRotation(anim.rotationsY, rotScale)
            anim.rotationsZ = readComp(rotations, joint.z.r)
            convRotation(anim.rotationsZ, rotScale)

            anim.translationsX = readComp(translations, joint.x.t)
            anim.translationsY = readComp(translations, joint.y.t)
            anim.translationsZ = readComp(translations, joint.z.t)
            
            self.anims[i] = anim

class AnimatedJoint(Readable):
    def read(self, f):
        self.x = AnimComponent(f)
        self.y = AnimComponent(f)
        self.z = AnimComponent(f)

class AnimComponent(Readable):
    def read(self, f):
        self.s = AnimIndex(f)
        self.r = AnimIndex(f)
        self.t = AnimIndex(f)

class AnimIndex(Readable):
    header = Struct('>HHH')
    def read(self, f):
        self.count, self.index, self.zero = self.header.unpack(f.read(6))

class Key(object): pass
class Animation(object): pass

# ImportHelper is a helper class, defines filename and
# invoke() function which calls the file selector.
from bpy_extras.io_utils import ImportHelper
from bpy.props import StringProperty, BoolProperty, EnumProperty
from bpy.types import Operator
import bpy
import os
from mathutils import *
from bisect import bisect
import mathutils.geometry

def readComp(src, index):
    dst = [None]*index.count
    #violated by biawatermill01.bck
    if index.zero != 0:
        warn("bck: zero field %d instead of zero" % index.zero)
    #TODO: biawatermill01.bck doesn't work, so the "zero"
    #value is obviously something important

    if index.count <= 0:
        warn("bck1: readComp(): count is <= 0")
        return
    elif index.count == 1:
        k = Key()
        k.time = 0
        k.value = src[index.index]
        k.tangent = 0
        dst[0] = k
    else:
        for j in range(index.count):
            k = Key()
            k.time = src[index.index + 3*j]
            k.value = src[index.index + 3*j + 1]
            k.tangent = src[index.index + 3*j + 2]
            dst[j] = k
        dst.sort(key=lambda a: a.time)
    
    return dst

def doCurve(action, data_path, loopFlags, data):
    for i, subData in enumerate(data):
        curve = action.fcurves.new(data_path=data_path, index=i)
        if loopFlags == 2:
            mod = curve.modifiers.new("CYCLES")
        curve.keyframe_points.add(len(subData))
        lastKey = lastKeyPoint = None
        for key_point, key in zip(curve.keyframe_points, subData):
            key_point.co = Vector((key.time, key.value))
            key_point.interpolation = "LINEAR"#"BEZIER"
            
            deltaTime = 0.0 if lastKey is None else key.time-lastKey.time
            key_point.handle_left = Vector((-1.0, -key.tangent))*deltaTime+key_point.co
            
            key_point.handle_left_type = "ALIGNED"

            if lastKeyPoint is not None:
                lastKeyPoint.handle_right = Vector((1.0, lastKey.tangent))*deltaTime+lastKeyPoint.co
                lastKeyPoint.handle_right_type = "ALIGNED"
            
            lastKeyPoint = key_point
            lastKey = key
        
        lastKeyPoint.handle_right = lastKeyPoint.co
        lastKeyPoint.handle_right_type = "ALIGNED"

def animateSingle(time, keyList):
    timeList = [key.time for key in keyList]
    i = bisect(timeList, time)
    if i <= 0:
        # the time is before any keys
        # TODO: does the tangent affect out-of-bounds values?
        return keyList[0].value
    elif i >= len(keyList):
        # the time is after all keys
        return keyList[-1].value
    else:
        keyBefore = keyList[i-1]
        keyAfter = keyList[i]
        # TODO TESTING
        return keyBefore.value+(keyAfter.value-keyBefore.value)*(time-keyBefore.time)/(keyAfter.time-keyBefore.time)

def animate(time, keyListSet):
    return (animateSingle(time, keyList) for keyList in keyListSet)

def importFile(filepath, context):
    fin = open(filepath, 'rb')
    print("Reading", filepath)
    bck = Bck()
    bck.name = os.path.splitext(os.path.split(filepath)[-1])[0]
    bck.read(fin)
    fin.close()

    armObj = context.active_object
    assert armObj is not None
    assert armObj.type == "ARMATURE"
    if len(armObj.data.bones) != len(bck.ank1.anims):
        context.window_manager.popup_menu(lambda self, context: self.layout.label("%d bones required (given %d)"%(len(bck.ank1.anims), len(armObj.data.bones))),
            title="Incompatible armature", icon='ERROR')
        return

    print("Importing", filepath)
    for b in armObj.pose.bones:
        b.rotation_mode = "XYZ"
    arm = armObj.data
    
    armObj.animation_data_create()
    action = bpy.data.actions.new(name=bck.name)
    armObj.animation_data.action = action
    
    for i, anim in enumerate(bck.ank1.anims):
        bone = arm.bones[i]

        rest = bone.matrix_local
        if "_bmd_rest_scale" in bone:
            s = Matrix()
            scale = tuple(map(float, bone["_bmd_rest_scale"].split(',')))
            s[0][0] = scale[0]
            s[1][1] = scale[1]
            s[2][2] = scale[2]
            rest = rest*s
        if bone.parent:
            rest = bone.parent.matrix_local.inverted()*rest
        #rest = Matrix(eval(bone["_bmd_rest"]))
        
        animList = (anim.scalesX, anim.scalesY, anim.scalesZ,
                    anim.rotationsX, anim.rotationsY, anim.rotationsZ,
                    anim.translationsX, anim.translationsY, anim.translationsZ)
        newAnim = tuple([None]*len(animData) for animData in animList)

        for animDataIndex, (animData, newAnimData) in enumerate(zip(animList, newAnim)):
            lastRot = None
            axisIndex = animDataIndex%3
            for animDataSubIndex, key in enumerate(animData):
                #scale = animate(key.time, animList[0:3])
                #rotation = animate(key.time, animList[3:6])
                #translation = animate(key.time, animList[6:9])
                
                #t = Matrix.Translation(translation).to_4x4()
                #r = Euler(rotation).to_matrix().to_4x4()
                #s = Matrix()
                #scale = tuple(scale)
                #s[0][0] = scale[0]
                #s[1][1] = scale[1]
                #s[2][2] = scale[2]
                #mat = t*r*s
                if animDataIndex < 3:
                    mat = Matrix()
                    mat[axisIndex][axisIndex] = key.value
                    #print("XYZ"[axisIndex], "scale =", key.value)
                    #print("Animated scale", tuple(animate(key.time, animList[0:3])))
                    #scale = animate(key.time, animList[0:3])
                    #mat = Matrix()
                    #scale = tuple(scale)
                    #mat[0][0] = scale[0]
                    #mat[1][1] = scale[1]
                    #mat[2][2] = scale[2]
                elif animDataIndex < 6:
                    #e = Euler()
                    #e[axisIndex] = key.value
                    #mat = e.to_matrix().to_4x4()
                    #print("XYZ"[axisIndex], "rotation =", key.value)
                    #print("Animated rotation", tuple(animate(key.time, animList[3:6])))
                    rotation = animate(key.time, animList[3:6])
                    mat = Euler(rotation).to_matrix().to_4x4()
                else:
                    v = Vector()
                    v[axisIndex] = key.value
                    mat = Matrix.Translation(v).to_4x4()
                    #print("XYZ"[axisIndex], "translation =", key.value)
                    #print("Animated translation", tuple(animate(key.time, animList[6:9])))
                    #translation = animate(key.time, animList[6:9])
                    #mat = Matrix.Translation(translation).to_4x4()
                
                mat = rest.inverted()*mat
                
                newLoc, newRot, newScale = mat.decompose()
                newRot = newRot.to_euler("XYZ") if lastRot is None else newRot.to_euler("XYZ", lastRot)
                lastRot = newRot
                newData = newScale[:]+newRot[:]+newLoc[:]
                
                newKey = Key()
                newAnimData[animDataSubIndex] = newKey
                newKey.time = key.time
                newKey.value = newData[animDataIndex]
                newKey.tangent = key.tangent if key.value == 0 else key.tangent*newKey.value/key.value # TODO not sure about this

        bone_path = 'pose.bones["%s"]' % bone.name
        
        doCurve(action, bone_path+".scale", bck.ank1.loopFlags, newAnim[0:3])
        doCurve(action, bone_path+".rotation_euler", bck.ank1.loopFlags, newAnim[3:6])
        doCurve(action, bone_path+".location", bck.ank1.loopFlags, newAnim[6:9])
    
    context.scene.frame_start = 0.0
    context.scene.frame_end = bck.ank1.animationLength
    context.scene.render.fps = 60
    context.scene.render.fps_base = 1.0

class ImportBCK(Operator, ImportHelper):
    bl_idname = "import_anim.bck"  # important since its how bpy.ops.import_test.some_data is constructed
    bl_label = "Import BCK"

    # ImportHelper mixin class uses this
    filename_ext = ".bck"

    filter_glob = StringProperty(
            default="*.bck",
            options={'HIDDEN'},
            )

    def execute(self, context):
        if context.active_object.type != "ARMATURE":
            context.window_manager.popup_menu(lambda self, context: None,
                title="Select an armature to animate!", icon='ERROR')
            return {'CANCELED'}
        importFile(self.filepath, context)
        return {'FINISHED'}

# Only needed if you want to add into a dynamic menu
def menu_func_import(self, context):
    self.layout.operator(ImportBCK.bl_idname, text="Import BCK")


def register():
    bpy.utils.register_class(ImportBCK)
    bpy.types.INFO_MT_file_import.append(menu_func_import)


def unregister():
    bpy.utils.unregister_class(ImportBCK)
    bpy.types.INFO_MT_file_import.remove(menu_func_import)


if __name__ == "__main__":
    #register()

    # test call
    #bpy.ops.import_anim.bck('INVOKE_DEFAULT')
    
    importFile('/Volumes/ExtraData/sms/scene/bianco0/butterfly/butterfly_fly.bck', bpy.context)
