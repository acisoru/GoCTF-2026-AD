import contextlib
import io
import json
import unittest
from unittest.mock import patch
import urllib.error

import checker


class SkipperProtocolTest(unittest.TestCase):
    def run_action(self, *args, response=None, error=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(checker.sys, 'argv', ['checker.py', *args]), \
                patch.object(checker, 'request', return_value=response, side_effect=error), \
                patch.object(checker, 'probe'), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                self.assertRaises(SystemExit) as result:
            checker.main()
        return result.exception.code, stdout.getvalue(), stderr.getvalue()

    def test_info_returns_metadata_in_stdout(self):
        code, public, private = self.run_action('info')
        self.assertEqual(code, 101)
        self.assertEqual(json.loads(public), {
            'vulns': 1, 'timeout': 30, 'attack_data': True, 'puts': 1, 'gets': 1,
        })
        self.assertEqual(private, '')

    def test_check_success(self):
        self.assertEqual(self.run_action('check', 'host', response={'status': 'ok'}),
                         (101, 'OK\n', ''))

    def test_put_keeps_read_key_out_of_stdout(self):
        code, public, private = self.run_action('put', 'host', 'unused', 'FLAG', '1', response={
            'id': 'queue-id', 'created_at': 12345, 'read_key': 'private-key',
        })
        self.assertEqual((code, public, private),
                         (101, 'queue-id 12345\n', 'queue-id:private-key\n'))

    def test_get_success(self):
        with patch.object(checker, 'uncrypt', return_value=b'FLAG'):
            self.assertEqual(self.run_action(
                'get', 'host', 'queue-id:private-key', 'FLAG', '1',
                response={'messages': [{'ciphertext': 'cipher'}]},
            ), (101, 'OK\n', ''))

    def test_missing_flag_is_corrupt(self):
        self.assertEqual(self.run_action(
            'get', 'host', 'queue-id:private-key', 'FLAG', '1', response={'messages': []},
        ), (102, 'flag disappeared\n', ''))

    def test_bad_health_is_mumble(self):
        self.assertEqual(self.run_action('check', 'host', response={'status': 'bad'}),
                         (103, 'bad health response\n', ''))

    def test_malformed_response_keeps_diagnostic_in_stderr(self):
        code, public, private = self.run_action('check', 'host', response={})
        self.assertEqual((code, public), (103, 'checker failure\n'))
        self.assertEqual(private, "KeyError('status')\n")

    def test_connection_error_is_down(self):
        error = urllib.error.URLError('connection refused')
        self.assertEqual(self.run_action('check', 'host', error=error),
                         (104, 'http failure\n', str(error) + '\n'))

    def test_invalid_arguments_are_checker_failed(self):
        for args in ((), ('unknown',), ('unknown', 'host'), ('check',),
                     ('check', 'host', 'extra'), ('put', 'host'),
                     ('get', 'host', 'id', 'FLAG', '2')):
            with self.subTest(args=args):
                code, public, private = self.run_action(*args)
                self.assertEqual(code, 110)
                self.assertTrue(public.strip())
                self.assertEqual(private, '')


if __name__ == '__main__':
    unittest.main()
