"""Launch gate: incomplete cloud configuration cannot produce attestations."""
import asyncio
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from proofos_collector.readiness import configuration_issues


class ConfigurationReadinessTests(unittest.TestCase):
    def test_requires_explicit_key_and_target(self):
        self.assertEqual(configuration_issues({}), (
            'signing_key_not_configured',
            'observation_target_not_configured_or_invalid',
        ))

    def test_preconfigured_key_and_target(self):
        self.assertEqual(configuration_issues({
            'PROOFOS_COLLECTOR_PRIVATE_KEY_FILE': '/run/secrets/collector.pem',
            'PROOFOS_COLLECTOR_TARGET': 'https://example.com/healthz',
        }), ())

    def test_invalid_targets_and_timeouts(self):
        for target in ('', 'http://', 'file:///tmp/x', 'https://u:p@example.com',
                       'https://example.com#fragment', 'https://example.com:bad', 'https://['):
            with self.subTest(target=target):
                self.assertIn('observation_target_not_configured_or_invalid',
                              configuration_issues({'PROOFOS_COLLECTOR_TARGET': target}))
        for timeout in ('nan', 'inf', '-inf', '0', '-1', 'bad'):
            with self.subTest(timeout=timeout):
                self.assertIn('observation_timeout_invalid', configuration_issues({
                    'PROOFOS_COLLECTOR_TIMEOUT': timeout}))

    def test_auto_creation_is_not_production_identity(self):
        for flag in ('1', 'true', 'YES'):
            self.assertIn('automatic_key_creation_enabled', configuration_issues({
                'PROOFOS_COLLECTOR_CREATE_KEY': flag}))

    def test_cloud_request_refused_before_probe(self):
        import proofos_collector.app as module
        request = module.CollectRequest(execution_id='e', task_id='t',
            evidence_kind='runtime', profile_id='runtime-health-v1', request_nonce='n')
        with patch.object(module, 'CLOUD_RUNTIME', True), patch.object(
            module, 'READINESS_ISSUES', ('signing_key_not_configured',)
        ), patch.object(module, 'probe_health') as probe:
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(module.collect(request))
            self.assertEqual(caught.exception.status_code, 503)
            probe.assert_not_called()
            self.assertEqual(module.healthz()['status'], 'ok')
            self.assertEqual(module.readyz().status_code, 503)
            self.assertEqual(module.readyz().headers['cache-control'], 'no-store')
        with patch.object(module, 'READINESS_ISSUES', ()):
            self.assertEqual(module.readyz().status_code, 200)

    def test_environment_mutation_cannot_relabel_ephemeral_signer(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith('PROOFOS_COLLECTOR_')}
        env['VERCEL'] = '1'
        code = '''
import os
from proofos_collector.app import readyz, CLOUD_RUNTIME
os.environ['PROOFOS_COLLECTOR_PRIVATE_KEY_FILE'] = '/pretend/key.pem'
os.environ['PROOFOS_COLLECTOR_TARGET'] = 'https://example.com/healthz'
assert CLOUD_RUNTIME
assert readyz().status_code == 503
'''
        for invalid in ({}, {'PROOFOS_COLLECTOR_TARGET': 'http://'},
                        {'PROOFOS_COLLECTOR_TIMEOUT': 'bad'},
                        {'PROOFOS_COLLECTOR_TIMEOUT': '0'}):
            with self.subTest(invalid=invalid):
                result = subprocess.run([sys.executable, '-c', code],
                    env={**env, **invalid}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
