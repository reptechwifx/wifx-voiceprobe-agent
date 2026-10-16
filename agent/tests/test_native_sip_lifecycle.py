"""Opt-in real PJSUA2 callback regression. Loopback only; run in an isolated LAB."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

WORKER = '"""Real PJSUA2 2.16 callback regression, using only isolated loopback SIP traffic."""\nimport sys,socket,time,threading,types,sqlite3,tempfile,pathlib,gc,json,os\nsys.path.insert(0,sys.argv[1])\nif os.getenv(\'VOICEPROBE_PJSUA2_SDK\'):\n sys.path.insert(0,os.environ[\'VOICEPROBE_PJSUA2_SDK\'])\n if os.name==\'nt\':dll_directory=os.add_dll_directory(os.environ[\'VOICEPROBE_PJSUA2_SDK\'])\nimport main,pjsua2 as pj\nendpoint=pj.Endpoint();endpoint.libCreate();config=pj.EpConfig();config.uaConfig.threadCnt=0;config.uaConfig.mainThreadOnly=True;config.logConfig.level=0;config.logConfig.consoleLevel=0;endpoint.libInit(config);endpoint.audDevManager().setNullDev()\nfor transport in [pj.PJSIP_TRANSPORT_TCP,pj.PJSIP_TRANSPORT_UDP]:\n t=pj.TransportConfig();t.port=15060;endpoint.transportCreate(transport,t)\nendpoint.libStart();tmp=tempfile.TemporaryDirectory();db=sqlite3.connect(\':memory:\');db.executescript(\'CREATE TABLE incoming_active(run_id TEXT PRIMARY KEY,payload TEXT);\')\nagent=types.SimpleNamespace(remote={\'mode\':\'bidirectional\'},cfg={\'max_calls\':4},prepared={},calls={},rejected=[],capacity=lambda a:True,lock=threading.Lock(),db=db,data=pathlib.Path(tmp.name),journal=main.EventJournal(),store_active=lambda _:None)\naccount=main.ProbeAccount(agent,{\'id\':1,\'username\':\'100\',\'server\':\'127.0.0.1\',\'max_duration_s\':3,\'max_calls\':4,\'call_mode\':\'bidirectional\'});cfg=pj.AccountConfig();cfg.idUri=\'sip:100@127.0.0.1\';account.create(cfg)\nresults=[]\nfor transport in [\'tcp\',\'udp\']:\n for code in [403,405,486]:\n  account.config[\'call_mode\']=\'caller\' if code==405 else \'bidirectional\';account.trusted_sources=set() if code==403 else {\'127.0.0.1\'};agent.capacity=lambda a:code!=486\n  for index in range(5):\n   s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if transport==\'tcp\' else socket.SOCK_DGRAM);s.settimeout(2);s.connect((\'127.0.0.1\',15060))\n   callid=f\'008-{transport}-{code}-{index}\'\n   message=f\'INVITE sip:100@127.0.0.1:15060 SIP/2.0\\r\\nVia: SIP/2.0/{transport.upper()} 127.0.0.1:15061;branch=z9hG4bK{callid};rport\\r\\nMax-Forwards: 70\\r\\nFrom: <sip:101@127.0.0.1>;tag={callid}\\r\\nTo: <sip:100@127.0.0.1>\\r\\nCall-ID: {callid}@localhost\\r\\nCSeq: 1 INVITE\\r\\nContact: <sip:101@127.0.0.1:15061;transport={transport}>\\r\\nContent-Length: 0\\r\\n\\r\\n\'\n   responses=[]\n   def send():\n    s.send(message.encode())\n    try:\n     while True:\n      reply=s.recv(8192).decode();responses.append(reply)\n      if f\'SIP/2.0 {code}\' in reply:break\n    except (OSError,UnicodeError):pass\n   thread=threading.Thread(target=send);thread.start();end=time.monotonic()+2.5\n   while thread.is_alive() and time.monotonic()<end:\n    endpoint.libHandleEvents(10);main.Agent.respond_incoming(agent)\n   thread.join(3);s.close();assert any(f\'SIP/2.0 {code}\' in v for v in responses),(transport,code,index)\n   agent.rejected[:]=[c for c in agent.rejected if not c.finished]\n  results.append({\'transport\':transport,\'final_status\':code,\'real_invites\':5,\'survived\':True})\naccount.shutdown();agent.rejected.clear();agent.calls.clear();account=None;gc.collect();endpoint.libDestroy();print(json.dumps({\'pjsip\':\'2.16\',\'native_callback_regressions\':results,\'passed\':True}),flush=True)\n'


@unittest.skipUnless(os.getenv('VOICEPROBE_NATIVE_SIP_TESTS') == '1', 'Real PJSUA2 isolated LAB runtime required')
class NativeIncomingLifecycleTest(unittest.TestCase):
    def test_final_responses_after_callback_return_survive_tcp_udp_rejections(self):
        process = subprocess.run([sys.executable, '-c', WORKER, str(Path(__file__).resolve().parents[1] / 'src')], capture_output=True, timeout=60)
        self.assertEqual(0, process.returncode, process.stderr.decode(errors='replace'))
        document = json.loads(next(line for line in process.stdout.decode().splitlines() if line.startswith('{')))
        self.assertTrue(document['passed'])
        self.assertEqual(30, sum(case['real_invites'] for case in document['native_callback_regressions']))
        self.assertEqual({403, 405, 486}, {case['final_status'] for case in document['native_callback_regressions']})


if __name__ == '__main__':
    unittest.main()
