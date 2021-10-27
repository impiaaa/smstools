import bpy, struct, os, bmesh
from col import ColReader

bl_info = {
    "name": "Import COL",
    "author": "Spencer Alves",
    "version": (1,0,0),
    "blender": (2, 80, 0),
    "location": "Import",
    "description": "Import J3D COL collision data",
    "warning": "",
    "wiki_url": "",
    "tracker_url": "",
    "category": "Import-Export"}

# ImportHelper is a helper class, defines filename and
# invoke() function which calls the file selector.
from bpy_extras.io_utils import ImportHelper
from bpy.props import StringProperty, BoolProperty, EnumProperty
from bpy.types import Operator

def importFile(fname):
    print("Reading", fname)
    fin = open(fname, 'rb')
    col = ColReader()
    col.read(fin)
    fin.close()

    for groupidx, group in enumerate(col.groups):
        bm = bmesh.new()
        for x, y, z in zip(col.vertexBuffer[0::3], col.vertexBuffer[1::3], col.vertexBuffer[2::3]):
            bm.verts.new((z, x, y))
        bm.verts.ensure_lookup_table()

        m = bpy.data.meshes.new(os.path.splitext(os.path.split(fname)[-1])[0])
        if 1:
            mat = bpy.data.materials.new(str(groupidx))
            m.materials.append(mat)
            for triIndices in zip(group.indexBuffer[0::3], group.indexBuffer[1::3], group.indexBuffer[2::3]):
                try: face = bm.faces.new([bm.verts[vIdx] for vIdx in triIndices])
                except ValueError: pass # duplicate faces for some reason?
                #face.material_index = groupidx
        o = bpy.data.objects.new(m.name, m)
        bm.to_mesh(m)
        bm.free()
        bpy.context.scene.collection.objects.link(o)

class ImportCOL(Operator, ImportHelper):
    bl_idname = "import_scene.col"  # important since its how bpy.ops.import_test.some_data is constructed
    bl_label = "Import COL"

    # ImportHelper mixin class uses this
    filename_ext = ".col"

    filter_glob: StringProperty(
            default="*.col",
            options={'HIDDEN'},
            )

    def execute(self, context):
        importFile(self.filepath)
        return {'FINISHED'}

# Only needed if you want to add into a dynamic menu
def menu_func_import(self, context):
    self.layout.operator(ImportCOL.bl_idname, text="Import J3D COL collision data (*.col)")


def register():
    bpy.utils.register_class(ImportCOL)
    bpy.types.TOPBAR_MT_file_import.append(menu_func_import)


def unregister():
    bpy.utils.unregister_class(ImportCOL)
    bpy.types.TOPBAR_MT_file_import.remove(menu_func_import)


if __name__ == "__main__":
    register()

    # test call
    #bpy.ops.import_scene.bmd('INVOKE_DEFAULT')
