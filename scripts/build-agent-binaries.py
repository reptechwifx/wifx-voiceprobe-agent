#!/usr/bin/env python3
"""Construit PJSUA2 2.16 uniquement sur Marc-Home ; aucun upload, aucun build client."""
if __name__ == '__main__':
    from storage_maintenance import guard
    guard(10)

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
TARGETS={'ubuntu-24.04-amd64-cp312':('ubuntu:24.04','3.12'),'debian-12-amd64-cp311':('debian:bookworm-slim','3.11')}
DOCKERFILE='''ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-dev python3-venv python3-setuptools build-essential swig curl ca-certificates libssl-dev libasound2-dev libopus-dev && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv --system-site-packages /opt/voiceprobe/venv
COPY build-pjsip.sh instrument-pjsip.py rtp-observer.h rtcp-safe.h /
RUN VOICEPROBE_CONTROLLED_BUILD=marc-home /bin/bash /build-pjsip.sh
'''
EXPORT='''import pjsua2 as p,sys,sysconfig,platform,json,subprocess,shutil,pathlib,os
root=pathlib.Path('/out');module=pathlib.Path(p.__file__);extension=next(module.parent.glob('_pjsua2*.so'))
e=p.Endpoint();e.libCreate();c=p.EpConfig();c.logConfig.level=0;c.logConfig.consoleLevel=0;e.libInit(c);e.libStart();e.audDevManager().setNullDev()
assert e.libVersion().full=='2.16'
assert hasattr(p.Call,'getVoiceProbeStats')
assert all(any(x.codecId.startswith(k) for x in e.codecEnum2()) for k in ('G722/','PCMA/','PCMU/'));e.libDestroy()
for path in (module,extension):shutil.copy2(path,root/path.name)
subprocess.run(['strip','--strip-unneeded',str(root/extension.name)],check=True)
shared=subprocess.check_output(['ldd',str(root/extension.name)],text=True);assert 'not found' not in shared
metadata={'platform':sys.argv[1],'pjsip_version':'2.16','python':'.'.join(map(str,sys.version_info[:2])),'soabi':sysconfig.get_config_var('SOABI'),'glibc':platform.libc_ver()[1],'shared_libraries':shared,'source_sha256':'3af2e481d51aaa095897820fa2ee26c30e530590c6ca56d23e4133bbdad369eb','calls':128,'accounts':32,'codecs':['G722','PCMA','PCMU'],'cpu_baseline':'x86-64 generic','builder_image_id':sys.argv[4],'rtcp_patch_sha256':pathlib.Path('/var/tmp/voiceprobe-pjsip-build/pjproject-2.16/voiceprobe-rtcp-patch.sha256').read_text().strip(),'rtcp_arithmetic':'vp-rtcp-safe-v1','rtcp_arithmetic_sha256':pathlib.Path('/var/tmp/voiceprobe-pjsip-build/pjproject-2.16/voiceprobe-rtcp-safe.sha256').read_text().strip(),'rtp_observer_protocol':1,'rtp_playout_distribution_protocol':2,'observer_sha256':pathlib.Path('/var/tmp/voiceprobe-pjsip-build/pjproject-2.16/voiceprobe-observer.sha256').read_text().strip()}
(root/'binary.json').write_text(json.dumps(metadata,indent=2)+'\\n');shutil.copy2('/var/tmp/voiceprobe-pjsip-build/pjproject-2.16/COPYING',root/'COPYING')
for path in root.iterdir():os.chown(path,int(sys.argv[2]),int(sys.argv[3]));path.chmod(0o644)
'''
def main(args):
    docker=['docker','--host','unix:///var/run/docker.sock']
    if json.loads(subprocess.check_output(docker+['info','--format','{{json .}}']))['Name']!='docker-desktop':raise ValueError('Docker Desktop Marc-Home requis.')
    if args.output.exists():raise ValueError('Destination existante refusée ; conserver les paquets immuables.')
    args.output.mkdir(parents=True,mode=0o700);sdk=args.output/args.platform;sdk.mkdir(mode=0o755)
    default,python=TARGETS[args.platform];base=args.base or default
    baseinfo=json.loads(subprocess.check_output(docker+['image','inspect',base]))[0]
    if baseinfo['Architecture']!='amd64' or baseinfo['Os']!='linux':raise ValueError('Base Linux AMD64 requise.')
    base_reference=(baseinfo.get('RepoDigests') or [base])[0]
    image='voiceprobe-agent-sdk:'+args.platform+'-'+os.urandom(6).hex()
    with tempfile.TemporaryDirectory(prefix='builder-',dir=os.environ.get('VP_STORAGE_SCRATCH', str(args.output))) as tmp:
        context=Path(tmp);(context/'Dockerfile').write_text(DOCKERFILE);shutil.copy2(ROOT/'scripts/build-pjsip.sh',context/'build-pjsip.sh');shutil.copy2(ROOT/'scripts/instrument-pjsip.py',context/'instrument-pjsip.py');shutil.copy2(ROOT/'agent/installer/rtp-observer.h',context/'rtp-observer.h');shutil.copy2(ROOT/'agent/installer/rtcp-safe.h',context/'rtcp-safe.h')
        with (args.output/'build-private.log').open('wb') as log:subprocess.run(docker+['build','--pull=false','--platform','linux/amd64','--build-arg','BASE_IMAGE='+base_reference,'-t',image,str(context)],check=True,stdout=log,stderr=subprocess.STDOUT)
    image_id=json.loads(subprocess.check_output(docker+['image','inspect',image]))[0]['Id']
    subprocess.run(docker+['run','--rm','--pull=never','--mount','type=bind,src='+str(sdk.resolve())+',dst=/out',image,'/opt/voiceprobe/venv/bin/python','-c',EXPORT,args.platform,str(os.getuid()),str(os.getgid()),image_id],check=True)
    metadata=json.loads((sdk/'binary.json').read_text())
    if metadata['python']!=python:raise ValueError('Version Python produite incompatible.')
    (args.output/'provenance.json').write_text(json.dumps({'base_image':baseinfo['Id'],'builder_image':image_id,'platform':args.platform},indent=2))
    subprocess.run(['python3',str(ROOT/'scripts/build-agent-python-runtime.py'),'--platform',args.platform,'--sdk-dir',str(sdk),'--builder-image',image,'--output',str(args.output/(args.platform+'-offline.tar.gz'))],check=True)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--platform',required=True,choices=TARGETS);p.add_argument('--output',required=True,type=Path);p.add_argument('--base');main(p.parse_args())
