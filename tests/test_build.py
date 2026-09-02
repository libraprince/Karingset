import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('build', ROOT / 'scripts' / 'build.py')
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class BuildParserTests(unittest.TestCase):
    def test_policy_rule_with_no_resolve(self):
        bucket = BUILD.empty()
        self.assertTrue(BUILD.add('IP-CIDR,1.2.3.0/24,DIRECT,no-resolve', bucket))
        self.assertIn('1.2.3.0/24', bucket['ip_cidr'])

    def test_domain_rule_with_option(self):
        bucket = BUILD.empty()
        self.assertTrue(BUILD.add('DOMAIN-SUFFIX,example.com,PROXY,no-resolve', bucket))
        self.assertIn('example.com', bucket['domain_suffix'])

    def test_policy_extraction_ignores_options(self):
        self.assertEqual(
            BUILD.find_policy(['IP-CIDR', '1.2.3.0/24', 'DIRECT', 'no-resolve']),
            'DIRECT',
        )

    def test_host_wildcard(self):
        bucket = BUILD.empty()
        self.assertTrue(BUILD.add('HOST-WILDCARD,*.example.com', bucket))
        self.assertEqual(bucket['domain_regex'], {'^.*\\.example\\.com$'})

    def test_ip6_cidr_uses_sing_box_ip_cidr(self):
        bucket = BUILD.empty()
        self.assertTrue(BUILD.add('IP6-CIDR,2001:db8::/32', bucket))
        self.assertIn('2001:db8::/32', bucket['ip_cidr'])


if __name__ == '__main__':
    unittest.main()
