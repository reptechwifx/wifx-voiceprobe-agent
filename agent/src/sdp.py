"""Account codec constraints via PJSUA2's supported SDP modification callback."""

import re


def constrain_audio(sdp, allowed, preferred=None):
    # A scenario codec is an explicit measurement choice; constrain both PBX legs.
    effective = [preferred] if preferred in allowed else allowed
    lines = sdp.replace("\r\n", "\n").splitlines()
    names = {"0": "PCMU/8000", "8": "PCMA/8000", "9": "G722/16000"}
    for line in lines:
        match = re.match(r"a=rtpmap:(\d+)\s+([^\s]+)", line)
        if match:
            codec = match.group(2).removesuffix("/1")
            names[match.group(1)] = (
                "G722/16000" if codec.upper() in ("G722/8000", "G722/16000") else codec
            )
    removed = set()
    result = []
    for line in lines:
        if line.startswith("m=audio "):
            fields = line.split()
            payloads = [p for p in fields[3:] if names.get(p) in effective]
            payloads.sort(key=lambda p: effective.index(names[p]))
            payloads += [p for p in fields[3:] if names.get(p, "").lower() == "telephone-event/8000"]
            removed.update(set(fields[3:]) - set(payloads))
            result.append(" ".join(fields[:3] + payloads))
        else:
            match = re.match(r"a=(?:rtpmap|fmtp|rtcp-fb):(\d+)", line)
            if not match or match.group(1) not in removed:
                result.append(line)
    return "\r\n".join(result) + "\r\n"
