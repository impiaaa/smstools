from scenebin import *
import sys, pathlib

def bmd2vmfcoords(x, y, z, rx, ry, rz):
    return -x, z, y, -rx, rz, ry

argpath = pathlib.Path(sys.argv[1])
if argpath.is_dir():
    if argpath.name == "map":
        scenedirpath = argpath.parent
        scenebinpath = argpath / "scene.bin"
    else:
        scenedirpath = argpath
        scenebinpath = scenedirpath / "map" / "scene.bin"
else:
    scenedirpath = argpath.parents[1]
    scenebinpath = argpath

scenename = scenedirpath.name

scene = readsection(open(scenebinpath, 'rb'))

for o in scene.objects:
    if o.namehash == 0x3c2e: # MarScene
        marScene = o
        break

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

for o in marScene.objects:
    if o.namehash == 0x4746: # LightAry
        for o2 in o.objects:
            assert o2.namehash == 0x286a # Light
            x, y, z, rx, ry, rz = bmd2vmfcoords(o2.x, o2.y, o2.z, 0, 0, 0)
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
"""%(o2.deschash, o2.r,o2.g,o2.b, x,y,z))
    if o.namehash == 0xabc3: # Strategy
        strategy = o

for group in strategy.objects:
    assert group.namehash == 0x2682
    for o in group.objects:
        if o.namehash in {0xc5d,0xfebc,0xf3d9,0x2639,0x372c}:
            # MapStaticObj, MapObjBase, MapObjGeneral, Fence, WindmillRoof
            x, y, z, rx, ry, rz = bmd2vmfcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
            vmfout.write("""entity
{
	"id" "%d"
	"classname" "prop_static" // %s
	"origin" "%r %r %r"
	"angles" "%r %r %r"
	"model" "models/bianco2/%s.mdl"
}
"""%(o.deschash, o.name, x,y,z, rx,ry,rz, o.model))
        elif o.namehash in {0xd8a,0x74e8,0xfba0,0x4a81,0xf591,0x31ae,0xd73c,0xf58f,0xc6c0,0x3887}:
            # Palm, BananaTree, RiccoLog, BigWindmill, BiaBell, BiaWatermill, LeafBoat, BiaTurnBridge, MiniWindmill, BellWatermill, BiaWatermillVertical
            x, y, z, rx, ry, rz = bmd2vmfcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
            vmfout.write("""entity
{
	"id" "%d"
	"classname" "prop_physics_multiplayer" // %s
	"origin" "%r %r %r"
	"angles" "%r %r %r"
	"model" "models/bianco2/%s.mdl"
}
"""%(o.deschash, o.name, x,y,z, rx,ry,rz, o.model))
        elif o.namehash == 0x574e:
            # MarioPositionObj
            for spawn in o.spawns:
                x, y, z, rx, ry, rz = bmd2vmfcoords(spawn.x, spawn.y, spawn.z, spawn.rx, spawn.ry, spawn.rz)
                vmfout.write("""entity
{
	"id" "%d"
	"classname" "info_player_start"
	"angles" "%r %r %r"
	"origin" "%r %r %r"
}
"""%(o.deschash, rx,ry,rz, x,y,z))
        elif o.namehash == 0x6db4:
            # FlowerCoin
            x, y, z, rx, ry, rz = bmd2vmfcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
            vmfout.write("""entity
{
	"id" "%d"
	"classname" "prop_detail" // %s
	"origin" "%r %r %r"
	"angles" "%r %r %r"
	"model" "models/bianco2/%s.mdl"
}
"""%(o.deschash, o.name, x,y,z, rx,ry,rz, o.model))
        elif o.namehash == 0xa3d9:
            # SunModel --> env_sun
            x, y, z, rx, ry, rz = bmd2vmfcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
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
"""%(o.deschash, rx,ry,rz, x,y,z))
        elif o.namehash == 0x2844:
            # Mario -> info_player_start
            x, y, z, rx, ry, rz = bmd2vmfcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
            vmfout.write("""entity
{
	"id" "%d"
	"classname" "info_player_start"
	"angles" "%r %r %r"
	"origin" "%r %r %r"
	"spawnflags" "1" // Master
}
"""%(o.deschash, rx,ry,rz, x,y,z))
        elif o.namehash in ():#(0xcad9, 0xee83):
            # AnimalBird, AnimalMew -> npc_seagull
            x, y, z, rx, ry, rz = bmd2vmfcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
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
"""%(o.deschash, rx,ry,rz, x,y,z))
        elif o.namehash in ():#== 0x5cf:
            # EffectFire -> env_fire
            x, y, z, rx, ry, rz = bmd2vmfcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
            vmfout.write("""entity
{
	"id" "%d"
	"classname" "env_fire"
	"angles" "%r %r %r"
	"origin" "%r %r %r"
}
"""%(o.deschash, rx,ry,rz, x,y,z))
        elif o.namehash == 0x6133:
            x, y, z, rx, ry, rz = bmd2vmfcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
            # MapObjChangeStage -> trigger_changelevel
            # assume a unit cube
            ax, ay, az = o.sx/2, o.sy/2, o.sz/2
            bx, by, bz = -o.sx/2, -o.sy/2, -o.sz/2
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
"""%(o.deschash, rx,ry,rz, x,y,z, o.deschash+1, o.deschash+2,bx,ay,az,ax,ay,az,ax,by,az, o.deschash+3,bx,by,bz,ax,by,bz,ax,ay,bz, o.deschash+4,bx,ay,az,bx,by,az,bx,by,bz, o.deschash+5,ax,ay,bz,ax,by,bz,ax,by,az, o.deschash+6,ax,ay,az,bx,ay,az,bx,ay,bz, o.deschash+7,ax,by,bz,bx,by,bz,bx,by,az))
        elif hasattr(o, "rx"):
            x, y, z, rx, ry, rz = bmd2vmfcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
            vmfout.write("""entity
{
	"id" "%d"
	"classname" "info_null"
	"angles" "%r %r %r"
	"origin" "%r %r %r"
	//"scale" "%r %r %r"
	"comments" "%s"
}
"""%(o.deschash, rx,ry,rz, x,y,z, o.sx,o.sy,o.sz, o.name))

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
vmfout.close()

