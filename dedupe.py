from zlib import crc32
import pathlib, os.path
import unityparser, uuid, yaml

def toTuple(d):
    if isinstance(d, dict):
        return tuple((k, toTuple(v)) for k, v in d.items())
    elif isinstance(d, list):
        return tuple(toTuple(v) for v in d)
    else:
        return d

def toDict(d):
    if isinstance(d, dict):
        return {k: toDict(v) for k, v in d.items()}
    else:
        return d

toCheck = set(pathlib.Path.cwd().rglob("*.*"))
while len(toCheck) > 0:
    files = {}
    for path in toCheck:
        if path.is_dir(): continue
        if path.suffix == ".meta": continue
        data = path.read_bytes()
        if path.suffix == ".shader": data = data[data.find(b'\n'):] # skip shader name
        h = crc32(data)
        if h in files: files[h].add(path)
        else: files[h] = {path}
    
    toCheck = set()
    
    for dupes in files.values():
        if len(dupes) == 1: continue
        metas = [unityparser.UnityDocument.load_yaml(f.with_suffix(f.suffix+".meta")).entry for f in dupes]
        guids = {m['guid'] for m in metas}
        for m in metas: del m['guid']
        origMeta = toDict(metas[0])
        metas = {toTuple(m) for m in metas}
        if len(metas) != 1: continue
        
        name = (','.join({f.stem for f in dupes}))[:50]+(','.join({f.suffix for f in dupes}))
        dir = pathlib.Path(os.path.commonpath(dupes))
        newPath = dir / name
        
        print("Moving", dupes, "to", newPath)
        dupes.pop().rename(newPath)
        for d in dupes: d.unlink()
        for d in dupes: d.with_suffix(d.suffix+".meta").unlink()
        
        newGuid = str(uuid.uuid4()).replace('-', '')
        origMeta['guid'] = newGuid
        yaml.dump(origMeta, open(newPath.with_suffix(newPath.suffix+".meta"), 'w'))
        
        newGuid = newGuid.encode()
        guids = {guid.encode() for guid in guids}
        for f in pathlib.Path.cwd().rglob("*.*"):
            if path.is_dir(): continue
            if path.suffix == ".meta": continue
            txt = f.read_bytes()
            repl = txt
            for guid in guids:
                repl = repl.replace(guid, newGuid)
            if repl != txt:
                print("Updating", f)
                f.write_bytes(repl)
                toCheck.add(f)

