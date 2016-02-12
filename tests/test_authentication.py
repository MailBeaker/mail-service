"""
Tests for `mail_service.gmail_service.authentication`.
"""

import unittest

from googleapiclient.discovery import Resource
from oauth2client.client import SignedJwtAssertionCredentials, AccessTokenCredentials
from mail_service.gmail_service import authentication
from mock import Mock


class AuthenticateTestCase(unittest.TestCase):
    """
    Tests for `authentication.authenticate`.
    """

    def test_auth_with_no_access_token(self):
        """
        Tests the authentication routine when no auth token is used.
        """
        service = "gmail"
        discovery = "gmail_discovery.json"
        version = "v1"
        email = "test@example.com"
        access_token = None
        http = Mock()

        credentials, http, service = authentication.authenticate(
                                    service,
                                    discovery,
                                    version,
                                    sub=email,
                                    access_token=access_token,
                                    http=http)

        self.assertIsInstance(credentials, SignedJwtAssertionCredentials)
        self.assertIsInstance(service, Resource)

        self.assertEqual(credentials.access_token, None)
        self.assertEqual(http, service._http)

    def test_auth_with_access_token(self):
        """
        Tests the authentication routine when a cached auth token is provided.
        """
        service = "gmail"
        discovery = "gmail_discovery.json"
        version = "v1"
        email = "test@example.com"
        access_token = "ya29.EAHi9TCEHi5Jaak_RV8A1KqCFg2G3soR5Wc0I" \
                       "j0dnRo56rLaPSmo4fgx1nkxed0OYBFFIuV_GlGH4A"
        http = Mock()

        credentials, http, service = authentication.authenticate(
                                    service,
                                    discovery,
                                    version,
                                    sub=email,
                                    access_token=access_token,
                                    http=http)

        self.assertIsInstance(credentials, AccessTokenCredentials)
        self.assertIsInstance(service, Resource)

        self.assertEqual(credentials.access_token, access_token)
        self.assertEqual(http, service._http)

