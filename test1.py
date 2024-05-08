import unittest
from trace import whois, ip_local, traceroute, parse_whois_info

class TestTracerouteFunctions(unittest.TestCase):

    def test_whois_valid_domain(self):
        domain_name = "msu.ru"
        whois_result = whois(domain_name)
        self.assertIsNotNone(whois_result)

    def test_ip_local_private_ip(self):
        ip_address = "192.168.1.1"
        result = ip_local(ip_address)
        self.assertEqual(result, 'local')

    def test_ip_local_public_ip(self):
        ip_address = "8.8.8.8"
        result = ip_local(ip_address)
        self.assertEqual(result, 'no local')

if __name__ == '__main__':
    unittest.main()

# cd /Users/mac/Desktop/python_23_24/task
# sudo python3 -m unittest tests.py