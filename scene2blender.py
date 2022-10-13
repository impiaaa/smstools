from scenebin import *
import sys, pathlib
from warnings import warn
import bpy
from math import radians

def bmd2blendcoords(pos, rot):
    x, y, z = pos
    rx, ry, rz = rot
    return (z, x, y), (radians(rz+90), radians(rx), radians(ry+90))

def getmesh(name):
    try:
        return bpy.data.meshes[name]
    except KeyError:
        try:
            return bpy.data.meshes[name.lower()]
        except KeyError:
            return bpy.data.meshes.new(name)

argpath = pathlib.Path("/media/spencer/ExtraData/Game extracts/sms/scene/pinnaBoss1")
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
            obj.location, obj.rotation_euler = bmd2blendcoords(o2.pos, (0, 0, 0))
            lamp.color = [c/255.0 for c in o2.color][:3]
    if o.namehash == 0xabc3: # Strategy
        strategy = o

for group in strategy.objects:
    assert group.namehash == 0x2682
    for o in group.objects:
        if not hasattr(o, "pos"): continue
        if o.namehash == 0xa3d9:
            data = bpy.data.lights.new(o.description, "SUN")
        elif hasattr(o, "model"):
            data = getmesh(o.model.lower())
        else:
            data = None
        obj = bpy.data.objects.new(o.description, data)
        bpy.context.scene.collection.objects.link(obj)
        if hasattr(o, "rot"):
            obj.location, obj.rotation_euler = bmd2blendcoords(o.pos, o.rot)
        else:
            obj.location, obj.rotation_euler = bmd2blendcoords(o.pos, (0,0,0))
        if hasattr(o, "scale"):
            obj.scale = o.scale
