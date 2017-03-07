# THIS IS A MESS
# rewrite it pls

from struct import unpack
import sys
from warnings import warn
try:
    import bpy
    blender = True
    console = False
except ImportError:
    blender = False
    console = True
vmf = False
from math import radians

def readstring(fin):
    length, = unpack('>H', fin.read(2))
    return fin.read(length).decode("shift-jis")

def bmd2vmfcoords(x, y, z, rx, ry, rz):
    return -x, z, y, -rx, rz, ry

def bmd2blendcoords(x, y, z, rx, ry, rz):
    return (z, x, y), (radians(rz), radians(rx), radians(ry))

def getmesh(name):
    try:
        return bpy.data.meshes[name]
    except KeyError:
        try:
            return bpy.data.meshes[name.lower()]
        except KeyError:
            return bpy.data.meshes.new(name)

def stylecolor(r,g,b):
    if r == g == b and r != 0 and r != 0xff:
        colorcode = int((r+2312)/10)
    else:
        colorcode = 16 + (36 * r/51) + (6 * g/51) + b/51
    if (r*r + g*g + b*b) > 48768:
        stylecode = 48
    else:
        stylecode = 38
    return "\x1b[%d;5;%dm#%02X%02X%02X\x1b[0m"%(stylecode, colorcode, r, g, b)

def readsection(fin, indent=0, vmfout=None):
    start = fin.tell()
    x = fin.read(6)
    if len(x) != 6: return -1
    sectionlength, op = unpack('>xxHH', x)
    enname = readstring(fin)
    id, = unpack('>H', fin.read(2)) # Not always unique, but pretty random.
    jpname = readstring(fin)
    endinfo = fin.tell()
    if console: print("%s%x@%x+%x: type=%s (0x%x) name=%s" % ('  '*indent, id, endinfo, start+sectionlength-endinfo, enname, op, jpname))
    if op == 0xe529:
        # AmbColor
        r, g, b = unpack('>BBBx', fin.read(4))
        if console: print("%s%s"%('  '*indent, stylecolor(r, g, b)))
    elif op == 0x286a:
        # Light
        x, y, z, r, g, b = unpack('>fffBBBx4x', fin.read(20))
        if console: print("%s%r %r %r %s"%('  '*indent, x, y, z, stylecolor(r, g, b)))
        if 0:#r > 0 or g > 0 or b > 0:
            if blender:
                lamp = bpy.data.lamps.new(jpname, "POINT")
                obj = bpy.data.objects.new(enname, lamp)
                bpy.context.scene.objects.link(obj)
                obj.location, obj.rotation_euler = bmd2blendcoords(x, y, z, rx, ry, rz)
                lamp.color = (r/255.0, g/255.0, b/255.0)
                lamp.energy = 0.1
                lamp.falloff_type = "CONSTANT"
            if vmf:
                x, y, z, rx, ry, rz = bmd2vmfcoords(x, y, z, rx, ry, rz)
                vmfout.write("""entity
{
	"id" "%d"
	"classname" "light"
	"_light" "%d %d %d 200"
	"_lightHDR" "-1 -1 -1 1"
	"_lightscaleHDR" "1"
	"_constant_attn" "1"
	"origin" "%r %r %r"
}
"""%(id, r,g,b, x,y,z))
    elif op in (0xc5d,0xfebc,0xf3d9,0x2639,0x372c):
        # MapStaticObj, MapObjBase, MapObjGeneral, Fence, WindmillRoof
        x, y, z, rx, ry, rz, sx, sy, sz = unpack('>fffffffff', fin.read(36))
        name1 = readstring(fin)
        fin.seek(4, 1)
        name2 = readstring(fin)
        if blender:
            mesh = getmesh(name2)
            obj = bpy.data.objects.new(jpname, mesh)
            bpy.context.scene.objects.link(obj)
            obj.location, obj.rotation_euler = bmd2blendcoords(x, y, z, rx, ry, rz)
            obj.scale = (sx, sy, sz)
        if vmf:
            x, y, z, rx, ry, rz = bmd2vmfcoords(x, y, z, rx, ry, rz)
            vmfout.write("""entity
{
	"id" "%d"
	"classname" "prop_static" // %s
	"origin" "%r %r %r"
	"angles" "%r %r %r"
	"model" "models/bianco2/%s.mdl"
}
"""%(id, enname, x,y,z, rx,ry,rz, name2))
    elif op in (0xd8a,0xde07,0x74e8,0xfba0,0x4a81,0xf591,0x31ae,0xd73c):
        # Palm, BananaTree, RiccoLog, BigWindmill, BiaBell, BiaWatermill, LeafBoat, BiaTurnBridge
        x, y, z, rx, ry, rz, sx, sy, sz = unpack('>fffffffff', fin.read(36))
        name1 = readstring(fin)
        fin.seek(4, 1)
        name2 = readstring(fin)
        if blender:
            mesh = getmesh(name2)
            obj = bpy.data.objects.new(jpname, mesh)
            bpy.context.scene.objects.link(obj)
            obj.location, obj.rotation_euler = bmd2blendcoords(x, y, z, rx, ry, rz)
            obj.scale = (sx, sy, sz)
        if vmf:
            x, y, z, rx, ry, rz = bmd2vmfcoords(x, y, z, rx, ry, rz)
            vmfout.write("""entity
{
	"id" "%d"
	"classname" "prop_physics_multiplayer" // %s
	"origin" "%r %r %r"
	"angles" "%r %r %r"
	"model" "models/bianco2/%s.mdl"
}
"""%(id, enname, x,y,z, rx,ry,rz, name2))
    elif op == 0x9913:
        # MapObjSoundGroup
        name1 = readstring(fin)
        if 0:#vmf:
            vmfout.write("""entity
{
	"id" "%d"
	"classname" "env_soundscape"
	"origin" "0 0 0"
	"angles" "0 0 0"
	"soundscape" "%s"
	"radius" "-1"
}
"""%(id, name1))
    elif op in (0xc662, 0x99b5, 0x66, 0x8c51):
        # ItemManager, MapObjBaseManager, MapObjManager, PoolManager
        readstring(fin)
        u, v = unpack('>4xff', fin.read(12))
    elif op in (0x41b8, 0x6e9e, 0x4746, 0xabc3, 0x62c9, 0xffb3, \
                0xc315, 0x35bc, 0x9481, \
                0x220f, 0x586d, 0x3d5d, \
                0x83e9, 0xb980):
        # GroupObj, AmbAry, LightAry, Strategy, NameRefGrp, CameraMapToolTable,
        # CubeGeneralInfoTable, StreamGeneralInfoTable, StageEnemyInfoHeader,
        # ScenarioArchiveNamesInStage, ScenarioArchiveNameTable, ReplayLink,
        # PositionHolder, EventTable
        count, = unpack('>L', fin.read(4))
        for i in range(count): readsection(fin, indent+1, vmfout)
    elif op in (0x3c2e, 0x2682):
        # MarScene, IdxGroup
        groupid, count = unpack('>LL', fin.read(8))
        for i in range(count): readsection(fin, indent+1, vmfout)
    #elif sectionlength-(endinfo-start) > 36 and sectionlength < 0xff: print
    elif op in (0x31, 0xbd21, 0x43e0):
        # ScenarioArchiveName, SmplChara, ObjChara
        fileName = readstring(fin)
        if console:
            print(('  '*(indent+1))+fileName)
    elif op == 0x13bf:
        # PerformList
        while fin.tell() < start+sectionlength:
            s = readstring(fin)
            n, = unpack('>I', fin.read(4))
            if console: print(('  '*(indent+1))+hex(n)+' '+s)
    elif op == 0x7af4:
        # StageEnemyInfo
        s = readstring(fin)
        n1, n2 = unpack('>II', fin.read(8))
        if console:
            print(('  '*(indent+1))+s+' '+hex(n1)+' '+hex(n2))
    elif op == 0xbeaa:
        # StageEventInfo
        n1, = unpack('>I', fin.read(4))
        if console: print '  '*indent, hex(n1),
        while fin.tell() < start+sectionlength-4:
            s = readstring(fin)
            if console: print s,
        n2, = unpack('>I', fin.read(4))
        if console: print hex(n2)
    elif op == 0x54e9:
        # CubeGeneralInfo
        x, y, z, rx, ry, rz, sx, sy, sz = unpack('>fffffffff', fin.read(36))
        n = unpack('>III', fin.read(12))
        if n[2] != 0xFFFFFFFF:
            s = readstring(fin)
            if console: print('  '*indent+str(n)+s)
        else:
            if console: print('  '*indent+str(n))
    elif op == 0xd6a:
        # Link
        n1, n2, n3 = unpack('>xHxHxH', fin.read(9))
        if console: print('  '*indent+hex(n1)+' '+hex(n2)+' '+hex(n3))
    elif op == 0x574e:
        # MarioPositionObj
        while fin.tell() < start+sectionlength:
            s = readstring(fin)
            x, y, z, rx, ry, rz, sx, sy, sz = unpack('>fffffffff', fin.read(36))
            if console: print("  %s%r %r %r, %s" % ('  '*indent, x, y, z, s))
            if vmf:
                x, y, z, rx, ry, rz = bmd2vmfcoords(x, y, z, rx, ry, rz)
                vmfout.write("""entity
{
	"id" "%d"
	"classname" "info_player_start"
	"angles" "%r %r %r"
	"origin" "%r %r %r"
}
"""%(id, rx,ry,rz, x,y,z))
    else:
        if start+sectionlength-endinfo >= 36:
            x, y, z, rx, ry, rz, sx, sy, sz = unpack('>fffffffff', fin.read(36))
            #if (abs(x) < 0.001 or abs(x) > 1000000) and (abs(y) < 0.001 or abs(y) > 1000000) and (abs(z) < 0.001 or abs(z) > 1000000):
            #    fin.seek(start+sectionlength)
            #    return
            left = start-endinfo+sectionlength-36
            if console: print("%s%r %r %r, 0x%x left" % ('  '*indent, x, y, z, left))
            if 0:#left > 1:
                try:
                    name1 = readstring(fin)
                    print('  '*indent+name1)
                    fin.seek(4, 1)
                    if left-len(name1) > 1:
                        try:
                            name2 = readstring(fin)
                            print('  '*indent+name2)
                        except UnicodeDecodeError:
                            print('  '*indent+"no second name")
                except UnicodeDecodeError:
                    print('  '*indent+"no first name")
            if blender:
                mesh = getmesh(enname)
                obj = bpy.data.objects.new(jpname, mesh)
                bpy.context.scene.objects.link(obj)
                obj.location, obj.rotation_euler = bmd2blendcoords(x, y, z, rx, ry, rz)
                obj.scale = (sx, sy, sz)
            if vmf:
                x, y, z, rx, ry, rz = bmd2vmfcoords(x, y, z, rx, ry, rz)
                if op == 0xa3d9:
                    # SunModel --> env_sun
                    vmfout.write("""entity
{
	"id" "%d"
	"classname" "env_sun"
	"angles" "%r %r %r"
	"HDRColorScale" "1.0"
	"material" "sprites/light_glow02_add_noz"
	"overlaycolor" "0 0 0"
	"overlaymaterial" "sprites/light_glow02_add_noz"
	"overlaysize" "-1"
	"rendercolor" "100 80 80"
	"size" "16"
	"origin" "%r %r %r"
}
"""%(id, rx,ry,rz, x,y,z))
                elif op == 0x2844:
                    # Mario -> info_player_start
                    vmfout.write("""entity
{
	"id" "%d"
	"classname" "info_player_start"
	"angles" "%r %r %r"
	"origin" "%r %r %r"
	"spawnflags" "1" // Master
}
"""%(id, rx,ry,rz, x,y,z))
                elif op in ():#(0xcad9, 0xee83):
                    # AnimalBird, AnimalMew -> npc_seagull
                    vmfout.write("""entity
{
	"id" "%d"
	"classname" "npc_seagull"
	"angles" "%r %r %r"
	"physdamagescale" "1.0"
	"renderamt" "255"
	"rendercolor" "255 255 255"
	"spawnflags" "516"
	"origin" "%r %r %r"
}
"""%(id, rx,ry,rz, x,y,z))
                elif op in ():#== 0x5cf:
                    # EffectFire -> env_fire
                    vmfout.write("""entity
{
	"id" "%d"
	"classname" "env_fire"
	"angles" "%r %r %r"
	"origin" "%r %r %r"
}
"""%(id, rx,ry,rz, x,y,z))
                elif op in (0x1c09, 0x2fe8, 0x9d75):
                    # CameraMapInfo, CameraCubeInfo, StagePositionInfo (tables.bin) -> info_observer_point
                    vmfout.write("""entity
{
	"id" "%d"
	"classname" "info_observer_point"
	"angles" "%r %r %r"
	"origin" "%r %r %r"
}
"""%(id, rx,ry,rz, x,y,z))
                elif op == 0x6133:
                    # MapObjChangeStage -> trigger_changelevel
                    # assume a unit cube
                    ax, ay, az = sx/2, sy/2, sz/2
                    bx, by, bz = -sx/2, -sy/2, -sz/2
                    #import transformations, numpy
                    #Ma = transformations.compose_matrix(angles=(rx, ry, rz), translate=(ax, ay, az))
                    #Ma = numpy.dot(Ma, transformations.compose_matrix(translate=(x,y,z)))
                    #Mb = transformations.compose_matrix(angles=(rx, ry, rz), translate=(bx, by, bz))
                    #Mb = numpy.dot(Mb, transformations.compose_matrix(translate=(x,y,z)))
                    #ax, ay, az = transformations.translation_from_matrix(Ma)
                    #bx, by, bz = transformations.translation_from_matrix(Mb)
                    vmfout.write("""entity
{
	"id" "%d"
	"classname" "trigger_changelevel"
	"spawnflags" "0"
	"StartDisabled" "0"
	"angles" "%r %r %r"
	"origin" "%r %r %r"
	solid
	{
		"id" "%d"
		side
		{
			"id" "%d"
			"plane" "(%r %r %r) (%r %r %r) (%r %r %r)"
			"material" "TOOLS/TOOLSTRIGGER"
			"uaxis" "[1 0 0 0] 0.25"
			"vaxis" "[0 -1 0 0] 0.25"
			"rotation" "0"
			"lightmapscale" "16"
			"smoothing_groups" "0"
		}
		side
		{
			"id" "%d"
			"plane" "(%r %r %r) (%r %r %r) (%r %r %r)"
			"material" "TOOLS/TOOLSTRIGGER"
			"uaxis" "[1 0 0 0] 0.25"
			"vaxis" "[0 -1 0 0] 0.25"
			"rotation" "0"
			"lightmapscale" "16"
			"smoothing_groups" "0"
		}
		side
		{
			"id" "%d"
			"plane" "(%r %r %r) (%r %r %r) (%r %r %r)"
			"material" "TOOLS/TOOLSTRIGGER"
			"uaxis" "[0 1 0 0] 0.25"
			"vaxis" "[0 0 -1 0] 0.25"
			"rotation" "0"
			"lightmapscale" "16"
			"smoothing_groups" "0"
		}
		side
		{
			"id" "%d"
			"plane" "(%r %r %r) (%r %r %r) (%r %r %r)"
			"material" "TOOLS/TOOLSTRIGGER"
			"uaxis" "[0 1 0 0] 0.25"
			"vaxis" "[0 0 -1 0] 0.25"
			"rotation" "0"
			"lightmapscale" "16"
			"smoothing_groups" "0"
		}
		side
		{
			"id" "%d"
			"plane" "(%r %r %r) (%r %r %r) (%r %r %r)"
			"material" "TOOLS/TOOLSTRIGGER"
			"uaxis" "[1 0 0 0] 0.25"
			"vaxis" "[0 0 -1 0] 0.25"
			"rotation" "0"
			"lightmapscale" "16"
			"smoothing_groups" "0"
		}
		side
		{
			"id" "%d"
			"plane" "(%r %r %r) (%r %r %r) (%r %r %r)"
			"material" "TOOLS/TOOLSTRIGGER"
			"uaxis" "[1 0 0 0] 0.25"
			"vaxis" "[0 0 -1 0] 0.25"
			"rotation" "0"
			"lightmapscale" "16"
			"smoothing_groups" "0"
		}
	}
}
"""%(id, rx,ry,rz, x,y,z, id+1, id+2,bx,ay,az,ax,ay,az,ax,by,az, id+3,bx,by,bz,ax,by,bz,ax,ay,bz, id+4,bx,ay,az,bx,by,az,bx,by,bz, id+5,ax,ay,bz,ax,by,bz,ax,by,az, id+6,ax,ay,az,bx,ay,az,bx,ay,bz, id+7,ax,by,bz,bx,by,bz,bx,by,az))
                elif op in (0xf58f, 0xc6c0, 0x3887):
                    # MiniWindmill, BellWatermill, BiaWatermillVertical
                    name1 = readstring(fin)
                    fin.seek(4, 1)
                    name2 = readstring(fin)
                    if blender:
                        mesh = getmesh(name2)
                        obj = bpy.data.objects.new(jpname, mesh)
                        bpy.context.scene.objects.link(obj)
                        obj.location, obj.rotation_euler = bmd2blendcoords(x, y, z, rx, ry, rz)
                        obj.scale = (sx, sy, sz)
                    if vmf:
                        x, y, z, rx, ry, rz = bmd2vmfcoords(x, y, z, rx, ry, rz)
                        vmfout.write("""entity
{
	"id" "%d"
	"classname" "prop_physics_multiplayer" // %s
	"origin" "%r %r %r"
	"angles" "%r %r %r"
	"model" "models/bianco2/%s.mdl"
}
"""%(id, enname, x,y,z, rx,ry,rz, name2))
                elif op == 0x6db4:
                    # FlowerCoin
                    name1 = readstring(fin)
                    fin.seek(4, 1)
                    name2 = readstring(fin)
                    if blender:
                        mesh = getmesh(name2)
                        obj = bpy.data.objects.new(jpname, mesh)
                        bpy.context.scene.objects.link(obj)
                        obj.location, obj.rotation_euler = bmd2blendcoords(x, y, z, rx, ry, rz)
                        obj.scale = (sx, sy, sz)
                    if vmf:
                        x, y, z, rx, ry, rz = bmd2vmfcoords(x, y, z, rx, ry, rz)
                        vmfout.write("""entity
{
	"id" "%d"
	"classname" "prop_detail" // %s
	"origin" "%r %r %r"
	"angles" "%r %r %r"
	"model" "models/bianco2/%s.mdl"
}
"""%(id, enname, x,y,z, rx,ry,rz, name2))
                else:
                    vmfout.write("""entity
{
	"id" "%d"
	"classname" "info_null"
	"angles" "%r %r %r"
	"origin" "%r %r %r"
	//"scale" "%r %r %r"
	"comments" "%s"
}
"""%(id, rx,ry,rz, x,y,z, sx,sy,sz, enname))
        extradata = fin.read((start+sectionlength)-fin.tell())
        if console and len(extradata) < 1920 and len(extradata) > 0: print(''.join(['%02X' % ord(c) for c in extradata]))
    assert fin.tell() == start+sectionlength, (fin.tell(), start, sectionlength)

if blender: fin = open("E:\sms\scene\dolpic0\map\scene.bin", 'rb')
else: fin = open(sys.argv[1], 'rb')
if vmf:
    vmfout = open(sys.argv[1][:sys.argv[1].rfind('.')]+".vmf", 'w')
    vmfout.write("""versioninfo
    {
    	"editorversion" "400"
    	"editorbuild" "5439"
    	"mapversion" "1"
    	"formatversion" "100"
    	"prefab" "0"
    }
    visgroups
    {
    }
    viewsettings
    {
    	"bSnapToGrid" "1"
    	"bShowGrid" "1"
    	"bShowLogicalGrid" "0"
    	"nGridSpacing" "64"
    	"bShow3DGrid" "0"
    }
    world
    {
    	"id" "1"
    	"mapversion" "1"
    	"classname" "worldspawn"
    	"skyname" "sky_day01_01"
    	"maxpropscreenwidth" "-1"
    	"detailvbsp" "detail.vbsp"
    	"detailmaterial" "detail/detailsprites"
    }
    """)
else: vmfout = None
readsection(fin, vmfout=vmfout)
if vmf:
    vmfout.write("""cameras
    {
    	"activecamera" "0"
    	camera
    	{
    		"position" "[126.401 356.961 598.126]"
    		"look" "[-88.097 -1817.03 -831.39]"
    	}
    }
    """)
fin.close()
