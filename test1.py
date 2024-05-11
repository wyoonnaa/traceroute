# sudo python3 -m unittest tests.py

import unittest
from trace import is_local_ip, whois_query, traceroute

class TestTracerouteFunctions(unittest.TestCase):

    def test_whois_query_valid_domain(self):
        domain_name = "msu.ru"
        whois_result = whois_query(domain_name)
        self.assertTrue(whois_result.strip())

    def test_is_local_ip_private_ip(self):
        ip_address = "192.168.1.1"
        result = is_local_ip(ip_address)
        self.assertEqual(result, 'local')

    def test_is_local_ip_public_ip(self):
        ip_address = "8.8.8.8"
        result = is_local_ip(ip_address)
        self.assertEqual(result, 'no local')

    def test_is_local_ip_invalid_ip(self):
        invalid_ip = "8474737364oskdk"
        result = is_local_ip(invalid_ip)
        self.assertEqual(result, 'invalid')

    def test_is_local_ip_ipv6_local(self):
        ipv6_local = "2001:0DB8:0000:0000:ABCD::1234"
        result = is_local_ip(ipv6_local)
        self.assertEqual(result, 'local')

    def test_is_local_ip_ipv6_random(self):
        ipv6_random = "ed9a:fe9d:77ed:b4e5:f338:4d34:3b23:3068"
        result = is_local_ip(ipv6_random)
        self.assertEqual(result, 'no local')

    def test_traceroute_run(self):
        self.assertRaises(SystemExit, traceroute, "127.0.0.1")


if __name__ == '__main__':
    unittest.main()
