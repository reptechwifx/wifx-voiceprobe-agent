#!/usr/bin/env python3
"""Construction locale Agent uniquement ; manifeste signé, aucun upload implicite."""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tarfile
import time
import tempfile
import urllib.parse

ROOT=Path(__file__).resolve().parents[1]
PJSIP_SOURCE_SHA256='3af2e481d51aaa095897820fa2ee26c30e530590c6ca56d23e4133bbdad369eb'


def run(args,**kwargs):return subprocess.check_output(args,**kwargs)
def sha(path):return hashlib.file_digest(Path(path).open('rb'),'sha256').hexdigest()
def artifact(path):return {'name':path.name,'bytes':path.stat().st_size,'sha256':sha(path)}
def sign(key,source,destination):run(['openssl','dgst','-sha256','-sign',str(key),'-out',str(destination),str(source)])


def pack(args):
    if args.runtime_public_key and not args.runtime_release:raise ValueError('Clé de base sans release de référence.')
    source=urllib.parse.urlsplit(args.source)
    if source.scheme!='https' or not source.hostname or source.username or source.password or source.query or source.fragment:raise ValueError('Source HTTPS canonique sans identifiants requise.')
    if args.output.exists():raise ValueError('Destination existante refusée.')
    dirty=bool(run(['git','status','--porcelain'],cwd=ROOT))
    if dirty and not args.lab_development:raise ValueError('Sources commitées et propres requises pour une distribution finale.')
    development=dirty or args.lab_development
    revision=run(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if dirty:
        h=hashlib.sha256()
        for folder in ['agent/src','agent/web','agent/installer']:
            for p in sorted((ROOT/folder).rglob('*')):
                if p.is_file() and '__pycache__' not in p.parts:h.update(str(p.relative_to(ROOT)).encode()+p.read_bytes())
        for name in ['VERSION','agent/VERSION','scripts/configure-agent.py','scripts/package-agent-release.py','infrastructure/agent/container-entrypoint.py','docs/installation/agent-public-template.md']:
            h.update(name.encode()+(ROOT/name).read_bytes())
        revision=h.hexdigest()[:40]
    version=(ROOT/'agent/VERSION').read_text().strip();release_id=version+'-'+revision[:12]
    out=args.output;out.mkdir(parents=True,mode=0o700);context=out/'agent-only-build';context.mkdir()
    for part in ['src','web']:shutil.copytree(ROOT/'agent'/part,context/'agent'/part,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    (context/'agent/src/gateway.py').unlink(missing_ok=True)
    license_file=ROOT/'agent/LICENSE'
    if license_file.is_file():
        shutil.copy2(license_file,context/'agent/LICENSE');shutil.copy2(license_file,context/'LICENSE')
    if (ROOT/'agent/NOTICE.md').is_file():shutil.copy2(ROOT/'agent/NOTICE.md',context/'agent/NOTICE.md')
    if args.notices:shutil.copytree(args.notices,context/'THIRD_PARTY_LICENSES')
    shutil.copy2(ROOT/'docs/installation/agent-public-template.md',context/'README.md')
    (context/'agent/VERSION').write_text(version+'\n');(context/'agent/BUILD_ID').write_text(revision+'\n')
    (context/'VERSION').write_text(version+'\n');(context/'scripts').mkdir();(context/'installer').mkdir()
    for filename in ['configure-agent.py']:shutil.copy2(ROOT/'scripts'/filename,context/'scripts'/filename)
    shutil.copy2(ROOT/'infrastructure/agent/container-entrypoint.py',context/'scripts/container-entrypoint.py')
    shutil.copy2(ROOT/'agent/installer/manage.py',context/'installer/manage.py')
    shutil.copy2(ROOT/'agent/installer/healthcheck.py',context/'installer/healthcheck.py')
    app=out/('voiceprobe-agent-'+release_id+'.tar.gz')
    with app.open('wb') as raw,gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as zipped,tarfile.open(fileobj=zipped,mode='w') as archive:
        for name in ['agent','VERSION','scripts','README.md']+(["LICENSE"] if (context/'LICENSE').exists() else [])+(["THIRD_PARTY_LICENSES"] if (context/'THIRD_PARTY_LICENSES').exists() else []):
            root=context/name
            for path in [root,*sorted(root.rglob('*'))] if root.is_dir() else [root]:
                item=archive.gettarinfo(str(path),str(path.relative_to(context)));item.mtime=0;item.uid=item.gid=0;item.uname=item.gname=''
                item.mode=0o755 if path.is_dir() or path.stat().st_mode&0o111 else 0o644
                if path.is_file():
                    with path.open('rb') as source_file:archive.addfile(item,source_file)
                else:archive.addfile(item)
    runtimes={}
    for platform_key in ['ubuntu-24.04-amd64-cp312','debian-12-amd64-cp311', *args.additional_platform]:
        binary=args.binaries/(platform_key+'-offline.tar.gz')
        with tarfile.open(binary) as archive:
            info=json.load(archive.extractfile('pjsip/binary.json'))
            if info['platform']!=platform_key or info['pjsip_version']!='2.16' or info['source_sha256']!=PJSIP_SOURCE_SHA256:raise ValueError('Provenance binaire PJSIP incompatible.')
            if info.get('rtp_observer_protocol') != 1 or info.get('rtp_playout_distribution_protocol') != 2 or info.get('observer_sha256') != sha(ROOT/'agent/installer/rtp-observer.h'):raise ValueError('Observer RTP absent ou non conforme au code livré.')
            if info.get('rtcp_patch_sha256') != sha(ROOT/'scripts/instrument-pjsip.py') or info.get('rtcp_arithmetic') != 'vp-rtcp-safe-v1' or info.get('rtcp_arithmetic_sha256') != sha(ROOT/'agent/installer/rtcp-safe.h'):raise ValueError('Correctif arithmétique RTCP absent ou non conforme.')
            if platform_key=='debian-12-amd64-cp311':
                target=context/'pjsip';target.mkdir()
                for member in archive:
                    relative=Path(member.name).relative_to('pjsip')
                    if not member.isfile():continue
                    if relative.is_absolute() or '..' in relative.parts:raise ValueError('Chemin binaire interdit.')
                    destination=target/relative;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(archive.extractfile(member).read())
        binary_name=platform_key+'-'+sha(binary)[:12]+'.tar.gz'
        shutil.copy2(binary,out/binary_name)
        dependencies=['python3','python3-venv','ca-certificates','openssl','iproute2','traceroute','libcap2-bin','libopus0','libstdc++6','libgcc-s1','libgfortran5']
        if platform_key!='debian-13-arm64-cp313':dependencies+=['libquadmath0']
        dependencies+=['libssl3t64','libasound2t64'] if platform_key.startswith('ubuntu') or platform_key=='debian-13-arm64-cp313' else ['libssl3','libasound2']
        runtimes[platform_key]={**artifact(out/binary_name),'python':info['python'],'soabi':info['soabi'],'glibc':info['glibc'],'dependencies':dependencies,'rtp_observer_protocol':1,'rtp_playout_distribution_protocol':2,'observer_sha256':info['observer_sha256'],'rtcp_patch_sha256':info['rtcp_patch_sha256'],'rtcp_arithmetic':info['rtcp_arithmetic'],'rtcp_arithmetic_sha256':info['rtcp_arithmetic_sha256']}
    dockerfile='''ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates openssl libssl3 libopus0 libasound2 libgfortran5 libquadmath0 iproute2 traceroute libcap2-bin && rm -rf /var/lib/apt/lists/* && setcap cap_net_raw=ep /usr/bin/traceroute.db && useradd -u 1000 -m probe
ARG SOURCE_REVISION
ARG AGENT_VERSION
LABEL net.wifx.project=voiceprobe-agent org.opencontainers.image.revision=$SOURCE_REVISION org.opencontainers.image.version=$AGENT_VERSION
COPY . /opt/voiceprobe/
RUN python3 -m venv /opt/voiceprobe/venv && /opt/voiceprobe/venv/bin/pip --isolated install --no-index --only-binary :all: --require-hashes --find-links /opt/voiceprobe/pjsip/wheels -r /opt/voiceprobe/pjsip/requirements.lock && rm -rf /opt/voiceprobe/pjsip/wheels /root/.cache
WORKDIR /opt/voiceprobe
ENV PATH=/opt/voiceprobe/venv/bin:$PATH PYTHONPATH=/opt/voiceprobe/agent/src:/opt/voiceprobe/pjsip PYTHONUNBUFFERED=1
RUN mkdir -p /var/lib/voiceprobe && chown 1000:1000 /var/lib/voiceprobe && chmod 0700 /var/lib/voiceprobe
VOLUME ["/var/lib/voiceprobe"]
USER 1000:1000
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=4 CMD ["python3","/opt/voiceprobe/installer/healthcheck.py"]
ENTRYPOINT ["python3","/opt/voiceprobe/scripts/container-entrypoint.py"]
CMD ["python3","agent/src/main.py"]
'''
    if args.runtime_release:
        previous=json.loads(args.runtime_release.read_text())
        public=args.runtime_public_key.read_bytes() if args.runtime_public_key else run(['openssl','pkey','-in',str(args.signing_key),'-pubout'])
        if args.runtime_public_key and public!=args.runtime_release.with_name('signing-public.pem').read_bytes():raise ValueError('Clé publique de la release de base incohérente.')
        with tempfile.TemporaryDirectory(prefix='voiceprobe-runtime-root-') as tmp:
            pub=Path(tmp)/'public.pem';pub.write_bytes(public)
            subprocess.run(['openssl','dgst','-sha256','-verify',str(pub),'-signature',str(args.runtime_release.with_suffix('.sig')),str(args.runtime_release)],check=True,stdout=subprocess.DEVNULL)
        base_ref=previous['docker']['reference']
        base=json.loads(run(['docker','image','inspect',base_ref]))[0]
        if base['Id'] not in previous['docker']['image_ids'] or base['RootFS']['Layers']!=previous['docker']['rootfs_diff_ids'] or base['Architecture']!='amd64' or base['Config']['Labels'].get('net.wifx.project')!='voiceprobe-agent':raise ValueError('Image Agent de référence non qualifiée.')
        dockerfile='FROM '+base_ref+'\nARG SOURCE_REVISION\nARG AGENT_VERSION\nLABEL net.wifx.project=voiceprobe-agent org.opencontainers.image.revision=$SOURCE_REVISION org.opencontainers.image.version=$AGENT_VERSION\nUSER root\nRUN test -x /usr/bin/traceroute.db && command -v setcap && setcap cap_net_raw=ep /usr/bin/traceroute.db\nCOPY . /opt/voiceprobe/\nRUN rm -rf /opt/voiceprobe/pjsip/wheels\nUSER 1000:1000\n'
    (context/'Dockerfile').write_text(dockerfile)
    docker=['docker','--host','unix:///var/run/docker.sock']
    if json.loads(run(docker+['info','--format','{{json .}}']))['Name']!='docker-desktop':raise ValueError('Construction exclusivement Docker Desktop Marc-Home.')
    ref='voiceprobe-agent-runtime:'+release_id
    if subprocess.run(docker+['image','inspect',ref],capture_output=True).returncode==0:raise ValueError('Tag Agent immuable déjà présent ; aucune reconstruction implicite.')
    with (out/'build-private.log').open('wb') as log:
        subprocess.run(docker+['build','--pull=false','--platform','linux/amd64','--build-arg','BASE_IMAGE='+args.debian_base,'--build-arg','SOURCE_REVISION='+revision,'--build-arg','AGENT_VERSION='+version,'-t',ref,str(context)],check=True,stdout=log,stderr=subprocess.STDOUT)
    image=json.loads(run(docker+['image','inspect',ref]))[0]
    if args.runtime_release and image['RootFS']['Layers'][:len(base['RootFS']['Layers'])] != base['RootFS']['Layers']:raise ValueError('Le runtime 017 signé n’est pas la base de la nouvelle image.')
    tar=out/'agent-image.tar';run(docker+['image','save','-o',str(tar),ref])
    with tarfile.open(tar) as archive:
        entries=json.load(archive.extractfile('manifest.json'));entry=entries[0];config=archive.extractfile(entry['Config']).read();config_id='sha256:'+hashlib.sha256(config).hexdigest()
        if len(entries)!=1 or entry.get('RepoTags')!=[ref]:raise ValueError('Archive Agent contenant une image inattendue.')
    docker_archive=out/('voiceprobe-agent-image-'+release_id+'.tar.gz')
    with tar.open('rb') as src,docker_archive.open('wb') as dst:
        with gzip.GzipFile(filename='',mode='wb',fileobj=dst,mtime=0) as zipped:shutil.copyfileobj(src,zipped)
    tar.unlink()
    compatibility=json.loads((ROOT/'agent/installer/compatibility.json').read_text())
    manager_name='agent-manager-'+sha(ROOT/'agent/installer/manage.py')[:12]+'.py'
    manifest={'schema':1,'installer_protocol':1,'installer_version':'1.0.2','sequence':args.sequence,'expires':int(time.time())+90*86400,
       'version':version,'release_id':release_id,'source_revision':revision,'development':development,'data_schema':1,'rollback_compatible':True,
       'compatible_from':list(dict.fromkeys(['0.9-003','0.9-004','0.9-007','0.9-008','0.9-009','0.9-012','0.9-013','0.9-017','0.9-019','0.9-020','0.9-021','0.9-024','0.9-025',version])),'legacy_main_sha256':compatibility['legacy_native_main_sha256'],
       'manager':{**artifact(ROOT/'agent/installer/manage.py'),'name':manager_name},'agent':artifact(app),'runtimes':runtimes,'docker':{**artifact(docker_archive),'reference':ref,'image_ids':list(dict.fromkeys([image['Id'],config_id])),
       'rootfs_diff_ids':image['RootFS']['Layers']}}
    if args.artifact_source:
        spec=importlib.util.spec_from_file_location('agent_manager',ROOT/'agent/installer/manage.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        if not module.github_channel(args.source) or not module.github_release(args.artifact_source):raise ValueError('Canal/Release GitHub hors périmètre.')
        manifest['artifact_source']=args.artifact_source
    if args.corresponding_sources:
        manifest['corresponding_sources']=[]
        for path in args.corresponding_sources:
            shutil.copy2(path,out/path.name);manifest['corresponding_sources'].append(artifact(out/path.name))
    (out/'release.json').write_text(json.dumps(manifest,indent=2)+'\n');sign(args.signing_key,out/'release.json',out/'release.sig')
    public=run(['openssl','pkey','-in',str(args.signing_key),'-pubout']).decode().strip();(out/'signing-public.pem').write_text(public+'\n')
    manager=out/manager_name;shutil.copy2(ROOT/'agent/installer/manage.py',manager)
    manager_spec=importlib.util.spec_from_file_location('manager_package',ROOT/'scripts/package-agent-manager.py')
    manager_package=importlib.util.module_from_spec(manager_spec);manager_spec.loader.exec_module(manager_package)
    manager_package.write_catalog(out,manager,revision,args.sequence,manifest['expires'],args.artifact_source,args.signing_key)
    bootstrap_manifest='schema=1\nexpires='+str(manifest['expires'])+'\ndocker_id1='+image['Id']+'\ndocker_id2='+config_id+'\nmanager='+manager.name+'\nmanager_sha256='+sha(manager)+'\ndocker='+docker_archive.name+'\ndocker_sha256='+sha(docker_archive)+'\ndocker_reference='+ref+'\n'
    if args.artifact_source:bootstrap_manifest+='artifact_source='+args.artifact_source+'\n'
    (out/'bootstrap.manifest').write_text(bootstrap_manifest);sign(args.signing_key,out/'bootstrap.manifest',out/'bootstrap.sig')
    bootstrap=(ROOT/'agent/installer/bootstrap.sh.in').read_text().replace('@SOURCE_SHELL@',shlex.quote(args.source.rstrip('/'))).replace('@PUBLIC_KEY@',public)
    (out/'install.sh').write_text(bootstrap)
    files=[p for p in out.iterdir() if p.is_file() and not p.name.endswith('.log')]
    (out/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in sorted(files)))
    print(json.dumps({'release_id':release_id,'source_revision':revision,'development':development,'output':str(out),'image':ref,'sha256':sha(out/'release.json')}))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);p.add_argument('--binaries',required=True,type=Path);p.add_argument('--source',required=True);p.add_argument('--signing-key',required=True,type=Path);p.add_argument('--sequence',type=int,required=True);p.add_argument('--debian-base',default='debian:bookworm-slim');p.add_argument('--additional-platform',action='append',default=[],choices=['debian-13-arm64-cp313']);p.add_argument('--artifact-source');p.add_argument('--notices',type=Path);p.add_argument('--corresponding-sources',type=Path,nargs='*');p.add_argument('--runtime-release',type=Path);p.add_argument('--runtime-public-key',type=Path);p.add_argument('--lab-development',action='store_true');a=p.parse_args()
    from storage_maintenance import guard
    # The measured 0.9-021 incremental distribution is 750 MiB on disk.
    # Reserve 2 GiB for its build context, temporary image tar and archive.
    guard(2 if a.runtime_release else 8)
    try:pack(a)
    except (ValueError,subprocess.CalledProcessError):raise SystemExit('Construction de distribution Agent refusée ; aucun upload effectué.') from None
