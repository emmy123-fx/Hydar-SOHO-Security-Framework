import unittest

from modules.vulnerability_engine import detect_vulnerabilities
from modules.risk_engine import calculate_risk
from modules.recommendation_engine import recommend


class CoreLogicTests(unittest.TestCase):

    def test_vulnerability_rules(self):
        sample = [
            {"port": 23, "service": "telnet", "version": ""},
            {"port": 80, "service": "http", "version": ""},
            {"port": 22, "service": "ssh", "version": "OpenSSH 1.9"},
        ]
        issues = detect_vulnerabilities(sample)
        self.assertTrue(any('Telnet' in i['issue'] for i in issues))
        self.assertTrue(any('HTTP' in i['issue'] for i in issues))
        self.assertTrue(any('SSH version' in i['issue'] for i in issues))

    def test_risk_scores(self):
        issues = [
            {"severity": "High"},
            {"severity": "Medium"},
            {"severity": "Low"},
        ]
        score = calculate_risk(issues)
        self.assertEqual(score['score'], 30+15+5)
        self.assertEqual(score['level'], 'Medium')

    def test_recommendations(self):
        issues = [{"issue": "Telnet service detected"}, {"issue": "FTP service detected"}]
        recs = recommend(issues)
        self.assertIn('Disable Telnet', recs[0])
        self.assertIn('SFTP', recs[1])


if __name__ == '__main__':
    unittest.main()
