"""Real DHCP leases and HTTPS/WSS reconnection in two disposable Linux namespaces.

The HTTPS/WSS peer is a minimal protocol fixture, not a Laravel Controller.
No host interface, route, firewall, service or customer equipment is changed.
"""
import asyncio
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
BUSYBOX = os.environ['VP_LAB_BUSYBOX']
os.environ['NO_PROXY'] = '10.254.0.1,127.0.0.1,::1'
assert os.stat('/proc/self/ns/net').st_ino != int(os.environ['VP_LAB_PARENT_NETNS'])


def run(*arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=10)


def wait_for(check, message, timeout=40):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.2)
    raise AssertionError(message)


def server(folder):
    settings = json.loads((folder/'peer.json').read_text())
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            assert self.headers.get('Authorization') == 'Bearer isolated-dhcp-lab-token'
            body = settings if self.path.endswith('/config') else {'commands': []}
            self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
            self.wfile.write(json.dumps(body).encode())
        def do_POST(self):
            assert self.headers.get('Authorization') == 'Bearer isolated-dhcp-lab-token'
            self.rfile.read(int(self.headers.get('Content-Length',0)))
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"accepted":true}')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(folder/'cert.pem',folder/'key.pem')
    https_server = http.server.ThreadingHTTPServer(('0.0.0.0',18443),Handler)
    https_server.socket = context.wrap_socket(https_server.socket,server_side=True)
    threading.Thread(target=https_server.serve_forever,daemon=True).start()
    async def websocket(ws, path):
        with (folder/'wss-events').open('a') as event:
            event.write(ws.remote_address[0]+'\n')
        assert ws.request_headers.get('Authorization') == 'Bearer isolated-dhcp-lab-token'
        try:
            while True:
                await ws.send('{"type":"poll"}'); await asyncio.sleep(1)
        except Exception:
            pass
    async def serve():
        from websockets.legacy.server import serve
        async with serve(websocket,'0.0.0.0',18444,ssl=context):
            await asyncio.Future()
    asyncio.run(serve())


if len(sys.argv)>1 and sys.argv[1]=='peer':
    server(Path(sys.argv[2])); sys.exit()

sys.path.insert(0,os.environ['VOICEPROBE_PJSUA2_SDK'])
sys.path.insert(0,str(ROOT/'agent/src'))
import main

with tempfile.TemporaryDirectory() as directory:
    folder=Path(directory)
    run('ip','link','set','lo','up')
    anchor=subprocess.Popen(['unshare','--net',BUSYBOX,'sleep','600'])
    server_process=dhcp=client=None
    processes=[]; observations=[]; failures=[]
    try:
        wait_for(lambda:Path('/proc/'+str(anchor.pid)+'/ns/net').exists() and os.stat('/proc/'+str(anchor.pid)+'/ns/net').st_ino != os.stat('/proc/self/ns/net').st_ino,'server namespace')
        prefix=['nsenter','--target',str(anchor.pid),'--net']
        run('ip','link','add','vp-client','type','veth','peer','name','vp-server')
        run('ip','link','set','vp-server','netns',str(anchor.pid))
        run('ip','link','set','vp-client','up')
        run(*prefix,'ip','link','set','lo','up')
        run(*prefix,'ip','link','set','vp-server','up')
        run(*prefix,'ip','addr','add','10.254.0.1/32','dev','lo')
        run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=isolated-dhcp-lab',
            '-addext','subjectAltName=IP:10.254.0.1','-keyout',str(folder/'key.pem'),'-out',str(folder/'cert.pem'))
        spec=importlib.util.spec_from_file_location('prepare',ROOT/'scripts/configure-agent.py')
        prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)
        config=folder/'config.json'; prepare.prepare(config,'isolated-dhcp-password',retain_credentials=False)
        cfg=json.loads(config.read_text())
        cfg.update(controller_url='https://10.254.0.1:18443',wss_url='wss://10.254.0.1:18444',
                   ca_file=str(folder/'cert.pem'),token='isolated-dhcp-lab-token',adoption_state='adopted')
        cfg.pop('enrollment_secret',None);config.write_text(json.dumps(cfg));os.environ['CONFIG_FILE']=str(config)
        (folder/'peer.json').write_text(json.dumps({'id':cfg['id'],'name':'DHCP LAB','accounts':[],
            'mode':'bidirectional','max_calls':1,'capacity_protocol':2,'configuration_revision':'isolated-lab-v1'}))
        peer_log=(folder/'peer.log').open('w')
        server_process=subprocess.Popen([*prefix,sys.executable,__file__,'peer',str(folder)],stdout=peer_log,stderr=peer_log)
        agent=main.Agent(); identity=hashlib.sha256((folder/'identity.key').read_bytes()).hexdigest()
        hook=folder/'lease-hook'; events=folder/'lease-events'
        hook.write_text('''#!/bin/sh
set -eu
[ "$interface" = vp-client ] || exit 1
case "$1" in
 deconfig) ip -4 addr flush dev vp-client ;;
 bound|renew)
  ip -4 addr flush dev vp-client
  ip addr add "$ip/24" dev vp-client
  ip route replace default via "$router" dev vp-client
  printf '%s %s\\n' "$1" "$ip" >> "'''+str(events)+'''"
 ;;
esac
''');hook.chmod(0o700)
        def stop(process):
            if process and process.poll() is None:
                process.terminate(); process.wait(5)
        def acquire(network,address):
            run(*prefix,'ip','-4','addr','flush','dev','vp-server')
            run(*prefix,'ip','addr','add',network+'.1/24','dev','vp-server')
            dhcp_config=folder/'udhcpd.conf'
            dhcp_config.write_text('start '+address+'\nend '+address+'\ninterface vp-server\noption subnet 255.255.255.0\noption router '+network+'.1\noption lease 60\nlease_file '+str(folder/'leases')+'\npidfile '+str(folder/'server.pid')+'\n')
            (folder/'leases').unlink(missing_ok=True)
            daemon=subprocess.Popen([*prefix,BUSYBOX,'udhcpd','-f',str(dhcp_config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(daemon)
            time.sleep(.3)
            lease=subprocess.Popen([BUSYBOX,'udhcpc','-f','-i','vp-client','-s',str(hook),'-p',str(folder/'client.pid'),'-t','5','-T','1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(lease)
            wait_for(lambda:events.exists() and address in events.read_text(),'DHCP lease '+address,15)
            return daemon,lease
        def movement():
            try:
                time.sleep(2)
                assert not agent.controller_connected
                observations.append('boot_without_lease')
                dhcp,client=acquire('192.168.0','192.168.0.30')
                wait_for(lambda:agent.controller_connected and agent.wss_connected,'first HTTPS/WSS connection')
                observations.append('real_DHCP_192.168.0.30_HTTPS_WSS_connected')
                before=events.read_text().count('\n');client.send_signal(signal.SIGUSR1)
                wait_for(lambda:events.read_text().count('\n')>before,'actual DHCP renewal',15)
                observations.append('real_DHCP_renewal')
                run('ip','link','set','vp-client','down')
                wait_for(lambda:not agent.controller_connected,'HTTPS outage detection',15)
                observations.append('link_down_HTTPS_disconnected')
                stop(client);stop(dhcp)
                run('ip','-4','addr','flush','dev','vp-client')
                run('ip','link','set','vp-client','up')
                dhcp,client=acquire('172.30.155','172.30.155.200')
                wait_for(lambda:agent.controller_connected and agent.wss_connected and (folder/'wss-events').exists() and '172.30.155.200' in (folder/'wss-events').read_text(),'HTTPS/WSS reconnect on new lease',60)
                assert agent.cfg['id']==cfg['id'] and agent.cfg['token']==cfg['token']
                assert hashlib.sha256((folder/'identity.key').read_bytes()).hexdigest()==identity
                observations.append('real_DHCP_172.30.155.200_HTTPS_WSS_reconnected_identity_preserved')
            except BaseException as error:
                failures.append(type(error).__name__+': '+str(error))
                print('VP_LAB_DIAGNOSTIC '+json.dumps({'https':agent.controller_connected,'wss':agent.wss_connected,'error':agent.last_error,'peer_exit':server_process.poll(),'peer_log':(folder/'peer.log').read_text()[-3000:]}),flush=True)
            finally:
                agent.request_stop()
        worker=threading.Thread(target=movement);worker.start()
        agent.run(install_signals=False,export_management=False);worker.join(10)
        assert not worker.is_alive() and not failures,failures
        print('VP_LAB_RESULT '+json.dumps({'scope':'real DHCP and real Agent TLS/WSS transport against minimal protocol fixture; two private namespaces', 'observations':observations}),flush=True)
    finally:
        for process in [*processes,server_process,anchor]:
            if process and process.poll() is None:
                process.terminate()
                try:process.wait(5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
