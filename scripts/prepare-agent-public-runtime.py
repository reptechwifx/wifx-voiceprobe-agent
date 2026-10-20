#!/usr/bin/env python3
"""Prépare le SDK public hors cible : NumPy utilise les runtimes Fortran du système."""
import argparse,base64,csv,email,gzip,hashlib,io,json,os,re,shutil,subprocess,tarfile,tempfile,zipfile
from pathlib import Path
from agent_build_container import run_container

def sha(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def prepare(args):
    docker=['docker','--host','unix:///var/run/docker.sock']
    if json.loads(subprocess.check_output(docker+['info','--format','{{json .}}']))['Name']!='docker-desktop':raise ValueError('Construction locale Docker Desktop requise.')
    if args.output.exists():raise ValueError('Destination immuable déjà présente.')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='public-runtime-',dir=args.output.parent) as folder:
        stage=Path(folder)
        with tarfile.open(args.input) as a:
            members=a.getmembers()
            if sum(m.size for m in members)>256*1024*1024:raise ValueError('SDK trop volumineux.')
            for m in members:
                p=Path(m.name)
                if p.is_absolute() or '..' in p.parts or not (m.isfile() or m.isdir()):raise ValueError('Entrée SDK non sûre.')
                target=stage/p
                if m.isdir():target.mkdir(parents=True,exist_ok=True)
                else:target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(a.extractfile(m).read())
        sdk=stage/'pjsip';meta=json.loads((sdk/'binary.json').read_text())
        if meta['pjsip_version']!='2.16' or meta['source_sha256']!='3af2e481d51aaa095897820fa2ee26c30e530590c6ca56d23e4133bbdad369eb':raise ValueError('Provenance PJSIP non qualifiée.')
        arm64=meta['platform']=='debian-13-arm64-cp313'
        version='2.2.6' if arm64 else '1.26.4'
        arch='aarch64' if arm64 else 'x86_64'
        system_dependencies=['libgfortran5'] if arm64 else ['libgfortran5','libquadmath0']
        wheels=sdk/'wheels';originals=list(wheels.glob('numpy-*.whl'))
        if len(originals)!=1:raise ValueError('Wheel NumPy absent ou ambigu.')
        original=originals[0];original_sha=sha(original);root=stage/'numpy';root.mkdir()
        with zipfile.ZipFile(original) as z:
            for info in z.infolist():
                p=Path(info.filename)
                if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] not in ('numpy','numpy.libs','numpy-'+version+'.dist-info'):raise ValueError('Contenu NumPy non qualifié.')
                if not info.is_dir():target=root/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(info))
        removed=[]
        for p in (root/'numpy.libs').iterdir():
            if p.name.startswith(('libgfortran-','libquadmath-')):removed.append(p.name);p.unlink()
        if len(removed)!=(1 if arm64 else 2):raise ValueError('Runtimes NumPy inattendus ; aucune transformation implicite.')
        program="""from pathlib import Path
import subprocess,json
changes=[]
for p in Path('/work').rglob('*'):
 if p.is_file() and p.read_bytes()[:4]==b'\\x7fELF':
  old=subprocess.check_output(['patchelf','--print-needed',str(p)],text=True).splitlines()
  for name in old:
   new='libgfortran.so.5' if name.startswith('libgfortran-') else 'libquadmath.so.0' if name.startswith('libquadmath-') else None
   if new:subprocess.run(['patchelf','--replace-needed',name,new,str(p)],check=True);changes.append({'file':str(p.relative_to('/work')),'before':name,'after':new})
assert changes
Path('/work/elf-changes.json').write_text(json.dumps(changes,indent=2))
"""
        run_container(docker,['--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--user',str(os.getuid())+':'+str(os.getgid()),'--mount','type=bind,src='+str(root)+',dst=/work',args.elf_tools_image,'python3','-c',program])
        changes=json.loads((root/'elf-changes.json').read_text());(root/'elf-changes.json').unlink()
        info=root/('numpy-'+version+'.dist-info');(info/'WIFX-PROVENANCE.json').write_text(json.dumps({'upstream_wheel_sha256':original_sha,'transformation':'External Fortran runtime; BSD OpenBLAS DT_NEEDED patched; no NumPy or SIP algorithm changed','removed_vendored_libraries':removed,'system_dependencies':system_dependencies,'elf_changes':changes},indent=2)+'\n')
        py='cp'+meta['python'].replace('.','');tag=py+'-'+py+'-linux_'+arch;(info/'WHEEL').write_text('Wheel-Version: 1.0\nGenerator: WIFX public runtime packager\nRoot-Is-Purelib: false\nTag: '+tag+'\n')
        (info/'RECORD').unlink();records=[]
        for p in sorted(root.rglob('*')):
            if p.is_file():b=p.read_bytes();records.append([str(p.relative_to(root)),'sha256='+base64.urlsafe_b64encode(hashlib.sha256(b).digest()).decode().rstrip('='),len(b)])
        records.append(['numpy-'+version+'.dist-info/RECORD','',''])
        with (info/'RECORD').open('w',newline='') as f:csv.writer(f,lineterminator='\n').writerows(records)
        public=wheels/('numpy-'+version+'-'+tag+'.whl')
        with zipfile.ZipFile(public,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
            for p in sorted(root.rglob('*')):
                if p.is_file():item=zipfile.ZipInfo(str(p.relative_to(root)),date_time=(2026,1,1,0,0,0));item.external_attr=0o644<<16;z.writestr(item,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED)
        original.unlink()
        lock=[];receipt=[]
        for p in sorted(wheels.glob('*.whl')):
            with zipfile.ZipFile(p) as z:metadata=email.message_from_bytes(z.read(next(n for n in z.namelist() if n.endswith('.dist-info/METADATA'))))
            digest=sha(p);lock.append(metadata['Name']+'=='+metadata['Version']+' --hash=sha256:'+digest);receipt.append({'name':p.name,'sha256':digest,'bytes':p.stat().st_size})
        (sdk/'requirements.lock').write_text('\n'.join(lock)+'\n');(sdk/'wheels.json').write_text(json.dumps(receipt,indent=2)+'\n')
        shutil.copytree(args.notices,sdk/'licenses',dirs_exist_ok=True)
        meta['numpy_system_runtime']={'version':version,'upstream_wheel_sha256':original_sha,'wheel_sha256':sha(public),'dependencies':system_dependencies};meta['sdk_input_sha256']=sha(args.input);(sdk/'binary.json').write_text(json.dumps(meta,indent=2)+'\n')
        with args.output.open('wb') as raw,gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as gz,tarfile.open(fileobj=gz,mode='w') as a:
            for p in sorted(sdk.rglob('*')):
                ti=a.gettarinfo(str(p),'pjsip/'+str(p.relative_to(sdk)));ti.mtime=0;ti.uid=ti.gid=0;ti.uname=ti.gname='';ti.mode=0o755 if p.is_dir() else 0o644
                if p.is_file():
                    with p.open('rb') as f:a.addfile(ti,f)
                else:a.addfile(ti)
        print(json.dumps({'platform':meta['platform'],'output':str(args.output),'sha256':sha(args.output),'numpy_wheel_sha256':meta['numpy_system_runtime']['wheel_sha256']}))

if __name__=='__main__':
    from storage_maintenance import guard
    guard(1)
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--notices',type=Path,required=True);p.add_argument('--elf-tools-image',default='voiceprobe-agent-public-elf-tools:20261015');prepare(p.parse_args())
