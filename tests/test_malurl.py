# Copyright: 2022, Alexan Mardigian

import unittest
from configparser import ConfigParser
from urllib.parse import quote_plus
import sys
sys.path.insert(1, "../malurl")
from malurl import MalURL, DOES_NOT_EXIST, NA

OK = 200
NOT_FOUND = 404

class TestMalURL(unittest.TestCase):
    def setUp(self):
        config = ConfigParser()
        config.read('malurlscan.conf')
        cfg = config['malurlscan']
        self.malurl = MalURL(cfg['apikey'], cfg['strictness'])
        self.malurl.fetch('https://google.com')

    def test_MalURL_invalid_url(self):
        self.assertEqual(False, self.malurl._is_valid_url('google'))

    def test_MalURL_valid_url(self):
        self.assertEqual(True, self.malurl._is_valid_url('http://google.com'))

    def test_MalURL_fetch_invalid_url(self):
        url = 'google'
        self.malurl.fetch(url)
        test = self.malurl.results
        expected = {
            "success": False,
            "message": f"Invalid url {url}"
        }
        self.assertEqual(expected, test)

    def test_MalURL__get_invalid_key(self):
        self.malurl.fetch('google')
        self.assertEqual(self.malurl._get('test'), '')

    def test_MalURL_fetch_valid_key(self):
        self.malurl.fetch('google')
        self.assertEqual(self.malurl._get('status_code'), NOT_FOUND)

    def test_MalURL_fetch_valid_url(self):
        test = self.malurl.results
        self.assertEqual(OK, test['status_code'])

    def test_MalURL_fetch_invalid_url(self):
        self.malurl.fetch('google')
        self.assertEqual(NOT_FOUND, self.malurl._get('status_code'))

    def test_MalURL_unsafe(self):
        self.assertEqual(False, self.malurl.unsafe())

    def test_MalURL_domain(self):
        self.assertNotEqual('', self.malurl.domain())

    def test_MalURL_ip_address(self):
        self.assertNotEqual('', self.malurl.ip_address())

    def test_MalURL_server(self):
        self.assertNotEqual('', self.malurl.server())

    def test_MalURL_content_type(self):
        self.assertNotEqual(NA, self.malurl.content_type())

    def test_MalURL_risk_score(self):
        self.assertNotEqual(DOES_NOT_EXIST, self.malurl.risk_score())

    def test_MalURL_status_code(self):
        self.assertNotEqual(0, self.malurl.status_code())

    def test_MalURL_page_size(self):
        self.assertNotEqual(0, self.malurl.page_size())

    def test_MalURL_domain_rank(self):
        self.assertNotEqual(DOES_NOT_EXIST, self.malurl.domain_rank())

    def test_MalURL_dns_valid(self):
        self.assertEqual(False, self.malurl.dns_valid())

    def test_MalURL_dns_invalid(self):
        self.malurl.fetch('google')
        self.assertEqual(False, self.malurl.dns_valid())

    def test_MalURL_suspcious(self):
        self.assertEqual(False, self.malurl.suspicious())

    def test_MalURL_phishing(self):
        self.assertEqual(False, self.malurl.phishing())

    def test_MalURL_malware(self):
        self.assertEqual(False, self.malurl.malware())

    def test_MalURL_parking(self):
        self.assertEqual(False, self.malurl.parking())

    def test_MalURL_spamming(self):
        self.assertEqual(False, self.malurl.spamming())

    def test_MalURL_adult(self):
        self.assertEqual(False, self.malurl.adult())

    def test_MalURL_category(self):
        self.assertNotEqual('', self.malurl.category())

    def test_MalURL_domain_age(self):
        self.assertNotEqual({}, self.malurl.domain_age())

    def test_MalURL_message(self):
        self.assertNotEqual('', self.malurl.message())

    def test_MalURL_request_id(self):
        self.assertNotEqual('', self.malurl.request_id())

    def test_MalURL_errors(self):
        self.assertEqual([], self.malurl.errors())

    def test_MalURL_strictness_less_than_zero(self):
        m = MalURL(self.malurl.apikey, -9)
        m.fetch('https://google.com')
        self.assertEqual(self.malurl.status_code(), OK)

    def test_MalURL_strictness_greater_than_two(self):
        m = MalURL(self.malurl.apikey, 9)
        m.fetch('https://google.com')
        self.assertEqual(self.malurl.status_code(), OK)

if __name__ == "__main__":
    unittest.main()