"""Run a disposable build helper under the existing storage campaign."""
import os
import subprocess
from storage_maintenance import Maintenance, LABEL, PROJECT, ROOT


def run_container(docker, arguments):
    labels = {PROJECT: 'voiceprobe', LABEL+'workspace': str(ROOT),
              LABEL+'campaign': os.environ['VP_STORAGE_CAMPAIGN'], LABEL+'disposable': 'true'}
    options = [item for key, value in labels.items() for item in ('--label', key+'='+value)]
    cid = subprocess.check_output(docker+['create', *options, *arguments], text=True).strip()
    Maintenance().register('container', cid)
    try:
        subprocess.run(docker+['start', '--attach', cid], check=True)
        code = subprocess.check_output(docker+['inspect', '--format', '{{.State.ExitCode}}', cid], text=True)
        if int(code):
            raise subprocess.CalledProcessError(int(code), arguments)
    finally:
        running = subprocess.check_output(docker+['inspect', '--format', '{{.State.Running}}', cid], text=True).strip()
        if running == 'true':
            subprocess.run(docker+['stop', '--time', '10', cid], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(docker+['rm', cid], check=True, stdout=subprocess.DEVNULL)
