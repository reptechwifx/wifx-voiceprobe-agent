#!/usr/bin/env python3
"""Export Agent à liste autorisée ; aucun historique, aucune publication implicite."""
import argparse,hashlib,json,pathlib,shutil,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
SCRIPTS=['package-windows-agent-lab.py','install-agent.sh','install-agent-from-source.sh','update-agent.sh','uninstall-agent.sh','configure-agent.py','validate-agent-config.py','build-pjsip.sh','instrument-pjsip.py','reset-agent-password.py','installation-info.py','agent-distribution.py','package-agent-release.py','build-agent-binaries.py','build-agent-python-runtime.py','prepare-agent-public-runtime.py','agent_build_container.py']
EXACT={'agent/VERSION','agent/LICENSE','agent/NOTICE.md','infrastructure/agent/container-entrypoint.py','infrastructure/agent/voiceprobe-agent.service','docs/installation/agent-public-template.md'}|{'scripts/'+x for x in SCRIPTS}
PREFIXES=('agent/src/','agent/web/','agent/installer/','agent/tests/','agent/public/','agent/windows/')
DENIED={'agent/src/gateway.py','agent/BUILD_ID'}

def export(destination):
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT):raise ValueError('Sources commitées et propres requises.')
    destination=destination.resolve()
    if destination.exists():raise ValueError('Destination existante ; aucun écrasement.')
    files=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0');selected=[]
    for name in files:
        if not name or name in DENIED or not (name in EXACT or name.startswith(PREFIXES)):continue
        p=pathlib.Path(name)
        if (any(x.startswith('.') for x in p.parts) and name!='agent/public/.gitattributes') or p.suffix in ('.key','.pem','.sqlite','.db','.pyc','.exe','.dll','.pyd','.pfx','.p12','.nupkg','.so','.a','.lib','.o','.obj','.dmp') or '__pycache__' in p.parts:raise ValueError('Fichier non publiable dans la liste Agent.')
        source=ROOT/p
        known_version_link=(name=='agent/VERSION' and source.is_symlink() and source.resolve()==(ROOT/'VERSION').resolve() and not (ROOT/'VERSION').is_symlink())
        if (source.is_symlink() and not known_version_link) or not source.is_file():raise ValueError('Fichier non régulier refusé : '+name)
        selected.append(name)
    if not EXACT<=set(selected):raise ValueError('Fichier Agent requis absent de la liste autorisée.')
    destination.mkdir(parents=True)
    receipt={}
    for name in selected:
        target_name=name.removeprefix('agent/public/') if name.startswith('agent/public/') else name
        source=ROOT/name;target=destination/target_name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target);target.chmod(source.stat().st_mode&0o777)
        receipt[target_name]=hashlib.sha256(source.read_bytes()).hexdigest()
    shutil.copyfile(ROOT/'agent/VERSION',destination/'VERSION');shutil.copyfile(ROOT/'agent/LICENSE',destination/'LICENSE')
    if not (destination/'README.md').exists():shutil.copyfile(ROOT/'docs/installation/agent-public-template.md',destination/'README.md')
    (destination/'.gitignore').write_text('var/\n.env\n*.key\n*.pem\n!signing-public.pem\n*.crt\nagent/BUILD_ID\n__pycache__/\n*.exe\n*.dll\n*.pyd\n*.pfx\n*.p12\n*.nupkg\n')
    (destination/'.dockerignore').write_text('.git\nvar\n**/.env\n**/*.key\n**/*.pem\n**/*.crt\n**/__pycache__\n')
    if (destination/'controller').exists() or (destination/'agent/src/gateway.py').exists() or (destination/'.github/workflows').exists():raise ValueError('Frontière de publication violée.')
    print(json.dumps({'export':str(destination),'allowed_tracked_files':len(selected),'private_history_exported':False}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('destination',type=pathlib.Path)
    try:export(parser.parse_args().destination)
    except (OSError,ValueError) as e:raise SystemExit(str(e)) from None
