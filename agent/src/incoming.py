"""Prepared run correlation; never rely on the SIP Call-ID."""
import re
import time

def correlate(prepared, account_id, message, source, trusted_sources, now=None):
    now=time.monotonic() if now is None else now
    header=re.search(r'^X-VoiceProbe-Test:\s*([a-f0-9-]{36})\s*$',message,re.I|re.M)
    caller=re.search(r'^From:.*(?:sip:|tel:)([^@;>\s]+)',message,re.I|re.M)
    caller=caller.group(1) if caller else None
    candidates=[]
    for run_id,p in prepared.items():
        if p['account_id']!=account_id or p['expires']<=now or caller!=p.get('expected_user'):continue
        if header and header.group(1)==run_id:candidates.append(run_id)
        elif not header and p.get('correlation_mode')=='window' and source in trusted_sources:candidates.append(run_id)
    return candidates[0] if len(candidates)==1 else None


def trusted_pbx_addresses(server):
    """DNS outage disables window correlation; keep normal REGISTER retry alive."""
    import socket
    try:
        return {a[4][0] for a in socket.getaddrinfo(server.split(":")[0],5060,type=socket.SOCK_DGRAM)}
    except OSError:
        return set()
