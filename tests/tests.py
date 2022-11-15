import os
import subprocess
import unittest

SCAN_COMMAND = ["python3", "main.py"]
SOOS_CLIENT_ID_DEV = ""
SOOS_API_KEY_DEV = ""
DEV_ENV = "https://dev-api.soos.io/api/"


class BaseLineTestCases(unittest.TestCase):
    def test_baseline_scan_dev(self):
        print('Testing Baseline Scan')
        PARAMS = [
            f"--clientId={SOOS_CLIENT_ID_DEV}",
            f"--apiKey={SOOS_API_KEY_DEV}",
            "--projectName=\"SOOS DAST Integration Test\"",
            f"--apiURL={DEV_ENV}",
            "--branchName=\"Broken Crystals\""
            "--ajaxSpider=True",
            "https://brokencrystals.com/"
        ]
        process = subprocess.run(SCAN_COMMAND + PARAMS, capture_output=True,
                                 text=True)
        print(process.stdout)
        self.assertEqual(process.returncode, 0)

    def test_baseline_scan_dev_error(self):
        print('Testing Baseline Scan')
        PARAMS = [
            f"--clientId={SOOS_CLIENT_ID_DEV}",
            f"--apiKey={SOOS_API_KEY_DEV}",
            "--projectName=\"SOOS DAST Integration Test\"",
            f"--apiURL={DEV_ENV}",
            "--branchName=\"Broken Crystals\""
            "--ajaxSpider=True",
            "https://no-exist.soos.io/"
        ]
        process = subprocess.run(SCAN_COMMAND + PARAMS, capture_output=True,
                                 text=True)
        print(process.stdout)
        self.assertEqual(process.returncode, 1)
