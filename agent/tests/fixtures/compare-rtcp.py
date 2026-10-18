"""Compare the actual PJSIP receiver and independent collector executables."""
from pathlib import Path
import argparse,json,subprocess
parser=argparse.ArgumentParser();parser.add_argument('--driver',required=True);parser.add_argument('--observer',required=True);parser.add_argument('--report',required=True);parser.add_argument('--sanitized',action='store_true');args=parser.parse_args()

def run(rows, origin, freq=1_000_000_000, rate=8000):
 commands=[f'i {rate} {origin} {freq}']+[f'p {ticks} {ts} {seq} {hz} {clock}' for ticks,ts,seq,hz,clock in rows]
 p=subprocess.run([args.driver],input='\n'.join(commands)+'\n',text=True,capture_output=True,check=True)
 return [json.loads(line) for line in p.stdout.splitlines() if line.startswith('{')]

def stream(origin, frequency=1_000_000_000, delay=lambda i:(i%2)*.5, first=90000, count=3001, seq=1000):
 return [(origin+round((i*20+delay(i))*frequency/1000),(first+160*i)&0xffffffff,(seq+i)&65535,frequency,8000) for i in range(count)]
results=[];baseline=None
boundary=(1<<64)//8000
for codec in ['PCMA','PCMU','G722']:
 for name,origin in [('control',10_000_000_000),('cross_26d_boundary',boundary-10_000_000_000),('after_30_days',30*86400*10**9),('after_365_days',365*86400*10**9),('near_uint64', (1<<64)-70_000_000_000)]:
  rows=stream(origin);actual=run(rows,origin)
  assert all(x['invalid_flags']==0 for x in actual)
  last=actual[-1];assert last['samples']>2900 and last['max_us']<=625
  if baseline is None:baseline=last
  assert all(last[k]==baseline[k] for k in ['samples','mean_us','max_us','mean_precise_us','scaled'])
  results.append({'codec':codec,'case':name,**last,'restart_required':False})
for name,freq in [('windows_qpc_10mhz',10_000_000),('microsecond_clock',1_000_000)]:
 origin=365*86400*freq;actual=run(stream(origin,freq),origin,freq)[-1]
 assert actual['invalid_flags']==0 and actual['max_us']==baseline['max_us'];results.append({'case':name,**actual})
for name,rows in [('timestamp_wrap',stream(10**10,first=0xfffff000,seq=65500)),('zero_transit',stream(10**10,first=80000)),
                  ('real_600ms_jitter',stream(10**10,delay=lambda i:(i%2)*600)),('persistent_1s_delay',stream(10**10,delay=lambda i:1000 if i>=100 else 0)),('isolated_1s_delay',stream(10**10,delay=lambda i:1000 if i==100 else 0))]:
 # Arrival order is the receiver's order. A delayed packet may be reordered;
 # PJSIP deliberately filters sequence discontinuities while the collector does not.
 rows=sorted(rows,key=lambda x:x[0]);actual=run(rows,10**10)
 assert all(x['invalid_flags']==0 for x in actual)
 values=[];j=0.;prev=None;n=0
 for row,stat in zip(rows,actual):
  if stat['samples']>n:
   transit=((row[0]*8000//row[3])&0xffffffff)-row[1]
   # Previous transit comes from PJSIP's documented accepted packet population;
   # the arithmetic oracle remains independent (floating point RFC recurrence).
   delta=((stat['transit']-prev+(1<<31))%(1<<32))-(1<<31)
   j+=(abs(delta)-j)/16
   values.append(j/8)
  prev=stat['transit'];n=stat['samples']
 if values:
  assert abs(actual[-1]['mean_precise_us']/1000-sum(values)/len(values))<.20
  assert abs(actual[-1]['max_us']/1000-max(values))<.20
 # Independently compiled temporal collector: relative timestamps, all accepted packets.
 commands=''.join(f'p {seq} {ts} {(ticks-10**10)/1e6+1000:.6f} 123\nj\n' for ticks,ts,seq,hz,rate in rows)
 independent=subprocess.run([args.observer],input=commands,text=True,capture_output=True,check=True)
 obs=[json.loads(line)['jitter_ms'] for line in independent.stdout.splitlines()]
 results.append({'case':name,'pjsip':actual[-1],'collector_mean_ms':sum(obs)/len(obs),'collector_max_ms':max(obs),'population_explanation':'PJSIP filters sequence discontinuities and initial packets; observer keeps chronological distinct arrivals'})
 if name=='real_600ms_jitter':assert max(obs)>10
 if name=='persistent_1s_delay':assert actual[-1]['max_us']>60000 and max(obs)>60
for name,field,value,flag in [('frequency_change',3,10_000_000,2),('clock_backwards',0,10**10,4),('rtp_clock_change',4,16000,8),('clock_unavailable',3,0,1),('ambiguous_half_wrap',1,(90000+50*160-4+(1<<31))&0xffffffff,32)]:
 rows=stream(10**10,count=100);changed=list(rows[50]);changed[field]=value;rows[50]=tuple(changed)
 actual=run(rows,10**10)
 assert actual[-1]['invalid_flags']&flag
 assert actual[-1]['samples']==actual[49]['samples']
 results.append({'case':name,**actual[-1],'invalid_statistics_not_accumulated':True})
Path(args.report).write_text(json.dumps({'passed':True,'actual_pjsip_rtcp_source':True,'sanitizers':['undefined','float-cast-overflow'] if args.sanitized else [],'cases':results,'production_clock_modified':False},indent=2)+'\n')
print(json.dumps({'passed':True,'cases':len(results),'baseline':baseline}))
