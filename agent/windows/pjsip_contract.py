"""Build-time contract for the Windows receiver observer and RTCP arithmetic."""
import ast
import hashlib
import json
from pathlib import Path


def validate_binding(directory, project):
    directory, project = Path(directory), Path(project)
    metadata = json.loads((directory / 'binary.json').read_text(encoding='utf-8'))
    expected = {
        'rtp_observer_protocol': 1,
        'rtp_playout_distribution_protocol': 2,
        'rtcp_arithmetic': 'vp-rtcp-safe-v1',
        'observer_sha256': hashlib.sha256((project / 'agent/installer/rtp-observer.h').read_bytes()).hexdigest(),
        'rtcp_arithmetic_sha256': hashlib.sha256((project / 'agent/installer/rtcp-safe.h').read_bytes()).hexdigest(),
        'rtcp_patch_sha256': hashlib.sha256((project / 'scripts/instrument-pjsip.py').read_bytes()).hexdigest(),
    }
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise ValueError('Binding Windows sans observateur RTP ou correctif RTCP conforme ; reconstruire le SDK.')
    wrapper = ast.parse((directory / 'pjsua2.py').read_text(encoding='utf-8'))
    if not any(isinstance(node, ast.ClassDef) and node.name == 'Call'
               and any(isinstance(child, ast.FunctionDef) and child.name == 'getVoiceProbeStats'
                       for child in node.body) for node in wrapper.body):
        raise ValueError('Observateur RTP absent du binding Python Windows.')
    binary = (directory / '_pjsua2.pyd').read_bytes()
    if b'Call_getVoiceProbeStats' not in binary or b'vp-rtcp-safe-v1' not in binary:
        raise ValueError('Observateur RTP ou correctif RTCP absent du module natif Windows.')
    return {**expected, 'binding_sha256': hashlib.sha256(binary).hexdigest(),
            'wrapper_sha256': hashlib.sha256((directory / 'pjsua2.py').read_bytes()).hexdigest()}
