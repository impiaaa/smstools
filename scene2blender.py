from scenebin import *
import sys, pathlib
from warnings import warn
import bpy
from math import radians

def bmd2blendcoords(x, y, z, rx, ry, rz):
    return (z, x, y), (radians(rz+90), radians(rx), radians(ry+90))

def getmesh(name):
    try:
        return bpy.data.meshes[name]
    except KeyError:
        try:
            return bpy.data.meshes[name.lower()]
        except KeyError:
            return bpy.data.meshes.new(name)

argpath = pathlib.Path("")
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

for o in marScene.objects:
    if o.namehash == 0x4746: # LightAry
        for o2 in o.objects:
            assert o2.namehash == 0x286a # Light
            lamp = bpy.data.lights.new(o2.description, "POINT")
            obj = bpy.data.objects.new(o2.description, lamp)
            bpy.context.scene.collection.objects.link(obj)
            obj.location, obj.rotation_euler = bmd2blendcoords(o2.x, o2.y, o2.z, 0, 0, 0)
            lamp.color = (o2.r/255.0, o2.g/255.0, o2.b/255.0)
    if o.namehash == 0xabc3: # Strategy
        strategy = o

for group in strategy.objects:
    assert group.namehash == 0x2682
    for o in group.objects:
        if o.namehash == 0xa3d9:
            lamp = bpy.data.lights.new(o.description, "SUN")
            obj = bpy.data.objects.new(o.description, lamp)
            bpy.context.scene.collection.objects.link(obj)
            obj.location, obj.rotation_euler = bmd2blendcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
        elif hasattr(o, "model"):
            mesh = getmesh(o.model.lower())
            obj = bpy.data.objects.new(o.description, mesh)
            bpy.context.scene.collection.objects.link(obj)
            obj.location, obj.rotation_euler = bmd2blendcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
            obj.scale = (o.sx, o.sy, o.sz)
        elif hasattr(o, "sx"):
            obj = bpy.data.objects.new(o.description, None)
            bpy.context.scene.collection.objects.link(obj)
            obj.location, obj.rotation_euler = bmd2blendcoords(o.x, o.y, o.z, o.rx, o.ry, o.rz)
            obj.scale = (o.sx, o.sy, o.sz)

