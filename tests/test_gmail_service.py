#https://github.com/X/smithy-core/blob/master/smithy/core/tests/test_db.py
#https://github.com/X/calc/blob/master/calc/tests/test_notifications.py
#https://docs.python.org/2/library/unittest.html#unittest.TestCase.assertIsInstance

"""
Tests for `mail_service.gmail_service`.
"""

import unittest

from mail_service.gmail_service import GmailService
from mock import Mock


class CheckAccountV1TestCase(unittest.TestCase):
    """
    Tests for `gmail_service.check_account_v1`.
    """
    def setUp(self):
        self.gmail = GmailService()

    def test_check_account_v1(self):
        """
        Tests the account check under 'normal' conditions.
        """
        #self.assertIsInstance(credentials, SignedJwtAssertionCredentials)
        #self.assertIsInstance(service, Resource)

        #self.assertEqual(credentials.access_token, None)
        #self.assertEqual(http, service._http)
