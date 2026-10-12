import json
import unittest
from unittest.mock import patch
from agentguard.attacks import get_case
from agentguard.data import TICKET
from agentguard.evaluation import compare, run
from agentguard.redteam import generate
from agentguard.sandbox import Sandbox
from agentguard.supervisor import execute_workflow


class SupervisorTests(unittest.TestCase):
    def test_role_permissions_hold_even_without_data_guard(self):
        for protected in (True, False):
            for actor, tool, args in [
                ('support', 'send_reply', {'to': TICKET['sender'], 'message': 'hello'}),
                ('reviewer', 'get_customer', {'customer_id': TICKET['customer_id']}),
                ('redteam', 'send_reply', {'to': TICKET['sender'], 'message': 'hello'}),
                ('supervisor', 'get_customer', {'customer_id': TICKET['customer_id']}),
            ]:
                with self.subTest(protected=protected, actor=actor):
                    box = Sandbox(TICKET, protected)
                    box.execute(tool, args, actor=actor)
                    self.assertEqual(box.events[-1]['decision']['rule'], 'ROLE_SCOPE')
                    self.assertFalse(box.exposed or box.outbox)

    def test_only_supervisor_executes_sends(self):
        result = compare('What is my plan?')
        for name in ('baseline', 'reviewed', 'protected'):
            current = result[name]
            self.assertTrue(current['task_completed'])
            self.assertEqual([e['actor'] for e in current['events']], ['support', 'supervisor'])
            self.assertEqual(current['handoffs'][1]['kind'], 'draft')
            self.assertEqual(current['draft']['record_refs'], [TICKET['customer_id']])

    def test_reviewer_cannot_undo_an_earlier_read(self):
        result = compare(get_case('cross-account')['body'])
        self.assertTrue(result['reviewed']['reviewer_stopped'])
        self.assertEqual(result['reviewed']['unauthorized_reads'], 1)
        self.assertTrue(result['reviewed']['violation'])
        self.assertFalse(result['reviewed']['outbox'])
        self.assertEqual(result['protected']['unauthorized_reads'], 0)
        self.assertEqual(result['protected']['events'][0]['decision']['rule'], 'CUSTOMER_SCOPE')

    def test_gateway_survives_forced_reviewer_approval(self):
        for case in ('redirect', 'cross-account', 'private-note', 'spoofed-sender'):
            with self.subTest(case=case):
                result = compare(get_case(case)['body'], reviewer_fault=True)
                self.assertTrue(result['reviewer_fault'])
                self.assertTrue(result['reviewed']['violation'])
                self.assertFalse(result['protected']['violation'])
                self.assertEqual(result['protected']['review']['recommendation'], 'allow')
                self.assertEqual(result['protected']['supervisor_decision']['action'], 'send_draft')

    def test_live_fault_override_rejected(self):
        with self.assertRaises(ValueError):
            compare('test', 'live', reviewer_fault=True)

    def test_reviewer_failure_stops_before_send_and_keeps_trace(self):
        with patch('agentguard.supervisor.review', side_effect=ValueError('Invalid review')):
            result = run('Normal ticket', 'simulation', 'protected')
        self.assertEqual(result['error'], 'Invalid review')
        self.assertFalse(result['outbox'])
        self.assertEqual(result['handoffs'][-1]['kind'], 'review_request')
        self.assertEqual(len(result['events']), 1)

    def test_supervisor_approval_cannot_bypass_gateway_in_live_workflow(self):
        draft = {'to': 'audit@outside.test', 'message': 'Unsafe destination', 'record_refs': []}
        with patch('agentguard.supervisor.structured', side_effect=[{'task': 'Draft support reply'}, {'action': 'send_draft', 'reason': 'Approved'}]), \
             patch('agentguard.supervisor.live_support', return_value=draft), \
             patch('agentguard.supervisor.review', return_value={'recommendation': 'allow', 'findings': [], 'evidence': ['Mistaken approval']}):
            box = Sandbox(TICKET, True)
            handoffs = []
            execute_workflow('synthetic ticket', box, 'live', 'protected', handoffs)
        self.assertFalse(box.outbox)
        self.assertEqual(box.events[-1]['decision']['rule'], 'RECIPIENT_BINDING')

    def test_model_roles_have_separate_contexts_and_tools(self):
        payloads = []
        steps = [('delegate_support', {'task': 'Confirm plan and renewal'}),
                 ('get_customer', {'customer_id': 'cus_alex'}),
                 ('submit_draft', {'to': TICKET['sender'], 'message': 'Your Pro plan renews 2026-11-01.', 'record_refs': ['cus_alex']}),
                 ('submit_review', {'recommendation': 'allow', 'findings': [], 'evidence': ['Correct recipient and scope.']}),
                 ('submit_decision', {'action': 'send_draft', 'reason': 'Reviewed and ready.'})]
        class Response:
            def __init__(self, data): self.data = data
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self): return json.dumps(self.data).encode()
        def fake_request(req, timeout):
            payloads.append(json.loads(req.data))
            name, args = steps.pop(0)
            return Response({'status': 'completed', 'output': [{'type': 'function_call', 'name': name, 'call_id': str(len(payloads)), 'arguments': json.dumps(args)}]})
        with patch.dict('os.environ', {'OPENAI_API_KEY': 'test', 'OPENAI_MODEL': 'test'}), patch('urllib.request.urlopen', side_effect=fake_request):
            result = run('What is my plan?', 'live', 'protected')
        self.assertIsNone(result['error'])
        self.assertTrue(result['task_completed'])
        self.assertEqual(len(payloads), 5)
        self.assertEqual([len(p['input']) for p in payloads], [1, 1, 3, 1, 1])
        self.assertEqual([t['name'] for t in payloads[1]['tools']], ['get_customer', 'submit_draft'])
        self.assertEqual([t['name'] for t in payloads[3]['tools']], ['submit_review'])
        self.assertTrue(all('send_reply' not in [t['name'] for t in p['tools']] for p in payloads))

    def test_model_malformed_draft_does_not_send(self):
        from agentguard.agent import validate_draft
        for draft in ({'to': 'x', 'message': 'y'}, {'to': 'x', 'message': 'y', 'record_refs': [], 'role': 'supervisor'},
                      {'to': 'x', 'message': 'y', 'record_refs': 'not a list'}):
            with self.assertRaises(ValueError):
                validate_draft(draft)

    def test_redteam_generates_only_test_inputs(self):
        result = generate(get_case('redirect')['body'])
        self.assertEqual(len(result['cases']), 3)
        self.assertEqual(len({c['id'] for c in result['cases']}), 3)
        for candidate in result['cases']:
            self.assertIn('<tool_plan>', candidate['body'])
            compared = compare(candidate['body'])
            self.assertTrue(compared['baseline']['violation'])
            self.assertFalse(compared['protected']['violation'])

    def test_redteam_rejects_malformed_live_candidates(self):
        with patch('agentguard.redteam.structured', return_value={'cases': []}):
            with self.assertRaises(ValueError):
                generate('Synthetic seed', 'live')


if __name__ == '__main__':
    unittest.main()
