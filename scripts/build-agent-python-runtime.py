#!/usr/bin/env python3
"""Assemble un SDK PJSUA2 déjà construit et des wheels exclusivement binaires sur Marc-Home."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

PINS=['requests==2.33.0','websockets==15.0.1','numpy==1.26.4']

def build(args):
    docker=['docker','--host','unix:///var/run/docker.sock']
    info=json.loads(subprocess.check_output(docker+['info','--format','{{json .}}']))
    if info['Name']!='docker-desktop':raise ValueError('Construction réservée à Marc-Home Docker Desktop.')
    if args.output.exists():raise ValueError('Archive existante ; aucun écrasement.')
    sdk=args.sdk_dir.resolve();metadata=json.loads((sdk/'binary.json').read_text())
    if metadata['platform']!=args.platform or metadata['pjsip_version']!='2.16':raise ValueError('SDK incompatible.')
    wheels=sdk/'wheels';wheels.mkdir(exist_ok=True)
    lock=sdk/'requirements.lock'
    if not lock.exists():
        qualified=Path(__file__).resolve().parents[1]/'agent/installer/requirements'/(args.platform+'.lock')
        if not qualified.is_file():raise ValueError('Lock de dépendances qualifié absent.')
        lock.write_bytes(qualified.read_bytes())
    code='''import hashlib,json,os,pathlib,subprocess,sys,zipfile,email
root=pathlib.Path('/out');wheels=root/'wheels'
args=[sys.executable,'-m','pip','--isolated','download','--index-url','https://pypi.org/simple','--only-binary',':all:','--dest',str(wheels)]
if (root/'requirements.lock').exists():args+=['--require-hashes','-r',str(root/'requirements.lock')]
else:args+=json.loads(sys.argv[1])
subprocess.run(args,check=True)
lines=[];receipt=[]
for wheel in sorted(wheels.iterdir()):
 if wheel.suffix!='.whl':raise ValueError('Source archive forbidden')
 with zipfile.ZipFile(wheel) as z:
  names=[n for n in z.namelist() if n.endswith('.dist-info/METADATA')];assert len(names)==1
  m=email.message_from_bytes(z.read(names[0]))
 digest=hashlib.file_digest(wheel.open('rb'),'sha256').hexdigest()
 lines.append(m['Name']+'=='+m['Version']+' --hash=sha256:'+digest)
 receipt.append({'name':wheel.name,'sha256':digest,'bytes':wheel.stat().st_size})
(root/'requirements.lock').write_text('\\n'.join(lines)+'\\n')
(root/'wheels.json').write_text(json.dumps(receipt,indent=2)+'\\n')
for p in root.rglob('*'):
 os.chown(p,int(sys.argv[2]),int(sys.argv[3]));p.chmod(0o755 if p.is_dir() else 0o644)
'''
    subprocess.run(docker+['run','--rm','--pull=never','--mount','type=bind,src='+str(sdk)+',dst=/out',args.builder_image,'/opt/voiceprobe/venv/bin/python','-c',code,json.dumps(PINS),str(os.getuid()),str(os.getgid())],check=True)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('wb') as raw,gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as zipped,tarfile.open(fileobj=zipped,mode='w') as archive:
        for path in sorted(sdk.rglob('*')):
            if path.is_symlink():raise ValueError('Lien interdit dans le SDK.')
            item=archive.gettarinfo(str(path),'pjsip/'+str(path.relative_to(sdk)));item.mtime=0;item.uid=item.gid=0;item.uname=item.gname='';item.mode=0o755 if item.isdir() else 0o644
            if path.is_file():
                with path.open('rb') as source:archive.addfile(item,source)
            else:archive.addfile(item)
    print(json.dumps({'platform':args.platform,'output':str(args.output),'sha256':hashlib.file_digest(args.output.open('rb'),'sha256').hexdigest()}))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--platform',required=True,choices=['ubuntu-24.04-amd64-cp312','debian-12-amd64-cp311']);p.add_argument('--sdk-dir',required=True,type=Path);p.add_argument('--builder-image',required=True);p.add_argument('--output',required=True,type=Path)
    build(p.parse_args())
