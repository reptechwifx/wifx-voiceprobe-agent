#!/usr/bin/env python3
"""Healthcheck local Agent sans authentification/secrets affichés ni appel SIP lancé."""
import json,os,ssl,sys,time,urllib.request
from pathlib import Path

def main():
    try:
        path=Path(os.environ.get('CONFIG_FILE','/var/lib/voiceprobe/config.json'));config=json.loads(path.read_text());status=json.loads((path.parent/'.management-status.json').read_text())
        assert time.time()-status['sampled_at']<15 and status['pjsip_version']=='2.16'
        host=config.get('bind','127.0.0.1');host='127.0.0.1' if host=='0.0.0.0' else host
        secure=bool(config.get('tls_cert'));url=('https' if secure else 'http')+'://'+host+':'+str(config.get('port',18441))+'/login'
        context=ssl.create_default_context(cafile=config['tls_cert']) if secure else ssl.create_default_context()
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
        with opener.open(url,timeout=3) as response:assert response.status==200
        return 0
    except Exception:
        print('Agent local/SIP non prêt ; consulter voiceprobe-agent diagnose sans secrets.');return 1

if __name__=='__main__':sys.exit(main())
