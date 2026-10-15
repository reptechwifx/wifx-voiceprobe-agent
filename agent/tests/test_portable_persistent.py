"""Persistent Windows policy is tested independently from native SIP or GUI."""
import base64
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from portable_runtime import PortableError, PortableLease, portable_diagnostic, status_view, verify_provisioning
import test_portable_runtime as v1tests

INSTANCE = 'c5739aa2-eccd-45ae-bf82-6de06d021074'
INTERVENTION = '1bcd6e7e-91e5-4de6-bad4-a2597745f977'


class PersistentProvisioningTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        v1tests.ProvisioningTest.setUpClass.__func__(cls)

    payload = v1tests.ProvisioningTest.payload
    envelope = v1tests.ProvisioningTest.envelope
    # Inherit the real signing helpers but keep the v1 regression class separate.
    def persistent_payload(self):
        value = self.payload()
        value.update(schema='wifx-voiceprobe-portable-provisioning-v2', mode='persistent',
                     instance_id=INSTANCE, support_reference='WSUP-1234567', client_name='Client LAB',
                     starts_at='2026-10-01T00:00:00Z', operational_expires_at='2026-10-22T00:00:00Z',
                     invitation_expires_at=value['expires_at'], expected_agent_id=None,
                     expected_fingerprint=None, artifact_template_sha256='a'*64, package_nonce='b'*64)
        return value

    def check(self, payload, **kwargs):
        return verify_provisioning(json.dumps(self.envelope(payload)).encode(), {self.key_id:self.pem},
                                   agent_version='0.9-004', now=1_800_000_000, **kwargs)

    def test_v2_requires_signature_and_exact_template_binding(self):
        value = self.persistent_payload()
        for args in ({}, {'expected_template_sha256':'c'*64},
                     {'expected_template_sha256':'a'*64, 'expected_package_nonce':'c'*64}):
            with self.assertRaises(PortableError): self.check(value, **args)
        self.assertEqual(value, self.check(value, expected_template_sha256='a'*64, expected_package_nonce='b'*64))

    def test_expired_invitation_can_be_verified_for_existing_cng_only_not_authority(self):
        value = self.persistent_payload(); value['expires_at'] = value['invitation_expires_at'] = '2020-01-01T00:00:00Z'
        verified = self.check(value, expected_template_sha256='a'*64)
        self.assertEqual('persistent', verified['mode'])
        self.assertFalse(PortableLease(recoverable_expiry=True).allowed())

    def test_v2_malformed_metadata_or_identity_binding_refused(self):
        for key,value in [('instance_id','bad'), ('support_reference','WSUP123'), ('support_reference','secret'),
                          ('expected_agent_id', INSTANCE), ('package_nonce','c'*63), ('artifact_template_sha256','x'*64),
                          ('operational_expires_at','2020-01-01T00:00:00Z')]:
            document = self.persistent_payload(); document[key] = value
            with self.subTest(key=key), self.assertRaises(PortableError):
                self.check(document, expected_template_sha256='a'*64)


class PersistentLeaseTest(unittest.TestCase):
    def setUp(self):
        self.now = 10.0
        self.lease = PortableLease(clock=lambda:self.now, recoverable_expiry=True)

    def apply(self, state='authorized', intervention=INTERVENTION):
        return self.lease.apply({'state':state, 'lease_seconds':60 if state=='authorized' else 0,
                                 'intervention_id':intervention, 'support_reference':'WSUP-42'}, self.lease.begin_request())

    def test_expiry_can_recover_only_from_new_authenticated_lease(self):
        self.assertTrue(self.apply()); self.now += 61
        self.assertFalse(self.lease.allowed()); self.assertEqual('expired',self.lease.snapshot()['state'])
        self.lease.deny('expired'); self.assertFalse(self.lease.allowed())
        self.assertTrue(self.apply()); self.assertEqual('authorized',self.lease.snapshot()['state'])

    def test_pending_reactivation_and_intervention_update(self):
        self.assertFalse(self.apply('pending')); self.assertTrue(self.apply())
        self.assertEqual('WSUP-42',self.lease.snapshot()['support_reference'])
        self.assertTrue(self.apply(intervention=INSTANCE)); self.assertEqual(INSTANCE,self.lease.snapshot()['intervention_id'])

    def test_revocation_is_terminal_even_after_expiry_or_stale_valid_response(self):
        self.apply(); request=self.lease.begin_request(); self.lease.deny('revoked'); self.lease.deny('expired')
        self.assertFalse(self.apply()); self.assertEqual('revoked',self.lease.snapshot()['state'])
        self.assertFalse(self.lease.apply({'state':'authorized','lease_seconds':60,'intervention_id':INTERVENTION},request))

    def test_missing_intervention_never_grants_calls(self):
        with self.assertRaises(PortableError):
            self.lease.apply({'state':'authorized','lease_seconds':60},self.lease.begin_request())
        self.assertFalse(self.lease.allowed())

    def test_v1_expiry_remains_terminal(self):
        lease=PortableLease(clock=lambda:self.now); lease.deny('expired')
        self.assertFalse(lease.apply({'state':'authorized','lease_seconds':60},lease.begin_request()))


class DiagnosticTest(unittest.TestCase):
    def test_network_diagnostics_are_evidence_based_and_never_expose_raw_exception(self):
        for category,text in [('tls','Certificat'),('timeout','délai'),('network_dns','DNS'),('http','refusée')]:
            message=portable_diagnostic({'controller_error_category':category,'last_error':'Bearer SECRET'}, {'state':'authorized'})
            self.assertIn(text,message); self.assertNotIn('SECRET',message)
        self.assertIn('Appel établi, mais aucun média reçu.',portable_diagnostic({'media_evidence':'no_rtp'}, {'state':'authorized'}))
        self.assertNotIn('pare-feu',portable_diagnostic({'media_evidence':'no_rtp'}, {'state':'authorized'}))
        self.assertIn('qualité dégradée',portable_diagnostic({'media_evidence':'degraded'}, {'state':'authorized'}))

    def test_ticket_is_sanitized_independently_from_backend_content(self):
        for reference,expected in [('WSUP-123','WSUP-123'),('password SECRET',''),('WSUP-99999999','')]:
            value=status_view({}, {'state':'pending','remaining_seconds':0,'support_reference':reference})
            self.assertEqual(expected,value['ticket_reference']); self.assertNotIn('SECRET',json.dumps(value))


class PersistentEngineHooksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_configuration import main
        from unittest.mock import patch
        with patch.dict(sys.modules, {'main':main}):
            import portable_agent
        cls.main=main; cls.portable=portable_agent

    def test_commands_from_previous_intervention_cannot_start_or_prepare_calls(self):
        from unittest.mock import Mock, patch
        agent=self.portable.PortableAgent.__new__(self.portable.PortableAgent)
        agent.persistent=True; agent.lease=PortableLease(recoverable_expiry=True)
        agent.lease.apply({'state':'authorized','lease_seconds':60,'intervention_id':INTERVENTION,'support_reference':'WSUP-42'},agent.lease.begin_request())
        for kind in ('call','prepare','cancel'):
            with patch.object(self.main.Agent,'execute') as execute:
                with self.assertRaises(PortableError):
                    agent.execute({'kind':kind,'payload':{'intervention_id':INSTANCE}})
                execute.assert_not_called()
        with patch.object(self.main.Agent,'execute') as execute:
            command={'kind':'call','payload':{'intervention_id':INTERVENTION}}
            agent.execute(command);execute.assert_called_once_with(command)
        agent.lease.deny('expired')
        with patch.object(self.main.Agent,'execute') as execute:
            with self.assertRaises(PortableError): agent.execute(command)
            execute.assert_not_called()

    def test_configuration_digest_never_retains_password_or_recreates_accounts_on_poll(self):
        from unittest.mock import patch
        agent=self.portable.PortableAgent.__new__(self.portable.PortableAgent)
        agent.running=True;agent.calls={};agent.remote_fingerprint=None;agent.lease=PortableLease()
        agent.lease.apply({'state':'authorized','lease_seconds':60},agent.lease.begin_request())
        config={'accounts':[{'password':'SYNTHETIC_SECRET_ONLY','transport':'udp'}]}
        def apply(instance, value):
            instance.remote=value
            instance.remote_fingerprint=json.dumps(value,sort_keys=True)
        with patch.object(self.main.Agent,'apply_config',autospec=True,side_effect=apply) as shared:
            agent.apply_config(config)
            digest=agent.remote_fingerprint
            self.assertEqual(64,len(digest));self.assertNotIn('SYNTHETIC',digest)
            self.assertNotIn('password',digest)
            agent.apply_config(dict(config));shared.assert_called_once()
            config['accounts'][0]['transport']='tcp'
            agent.apply_config(config);self.assertEqual(2,shared.call_count)
            self.assertNotEqual(digest,agent.remote_fingerprint)
            agent.calls={'live':object()};config['accounts'][0]['transport']='udp'
            agent.apply_config(config);self.assertEqual(2,shared.call_count)

    def test_media_diagnostic_requires_actual_received_packets_or_analyzed_audio(self):
        from unittest.mock import patch
        agent=self.portable.PortableAgent.__new__(self.portable.PortableAgent)
        agent.completed_tests=0
        cases=[({'established':True,'rtp':{'rx':{'packets':0}}},'no_rtp'),
               ({'established':False,'rtp':{'rx':{'packets':0}}},None),
               ({'established':True,'rtp':{},'audio':{'interrupted_s':4}},None),
               ({'established':True,'rtp':{'rx':{'packets':20}},'audio':{'interrupted_s':0}},None),
               ({'established':True,'rtp':{'rx':{'packets':20}},'audio':{'interrupted_s':1}},'degraded')]
        with patch.object(self.main.Agent,'pending_report'):
            for metrics,expected in cases:
                agent.pending_report('fixture',metrics)
                self.assertEqual(expected,agent._media_evidence)
        self.assertEqual(len(cases),agent.completed_tests)


if __name__=='__main__': unittest.main()
