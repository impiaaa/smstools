import uuid, yaml, os.path, unityparser

def writeMeta(name, importer, outputFolderLocation):
    guid = str(uuid.uuid4()).replace('-', '')
    meta = {
        "fileFormatVersion": 2,
        "guid": guid
    }
    meta.update(importer)
    yaml.dump(meta, open(os.path.join(outputFolderLocation, name+".meta"), 'w'))
    return guid

def writeNativeMeta(name, mainObjectFileID, outputFolderLocation):
    return writeMeta(name, {
        "NativeFormatImporter": {
            "mainObjectFileID": mainObjectFileID
        }
    }, outputFolderLocation)

def fixUnityParserFloats():
    import re
    # for whatever reason, unityparser adds explicit type markers to floats with no
    # fraction. this restores pyyaml's default behavior
    unityparser.resolver.Resolver.add_implicit_resolver(
            'tag:yaml.org,2002:float',
            re.compile(r'''^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?
                        |\.[0-9_]+(?:[eE][-+][0-9]+)?
                        |[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*
                        |[-+]?\.(?:inf|Inf|INF)
                        |\.(?:nan|NaN|NAN))$''', re.X),
            list('-+0123456789.'))

