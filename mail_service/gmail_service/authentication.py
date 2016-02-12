import httplib2
import logging
import os

from apiclient.discovery import build_from_document
from mail_service import settings
from oauth2client.client import SignedJwtAssertionCredentials, AccessTokenCredentials


def authenticate(service, discovery, version, sub=None, access_token=None, http=None):
    """
    Authenticate to the Gmail API with the account specified by 'sub'.

    :param service: The API service object to authentication.
    :param discovery: The service descriptor file to use for API endpoint discovery.
    :param version: The version of the Gmail API to authentication to.
    :param sub: (optional) The user to authenticate the service object to.
    :param access_token: (optional) The OAuth2 token (usually from the cache) to use for authentication.
    :param http: Optional HTTP object to use (used in tests).
    :return: A tuple of (the authenticated credential object, the authenticated http object,
             and the service object).
    """

    if access_token:
        credentials = AccessTokenCredentials(access_token, user_agent="mailbeaker/1.0")
    else:
        logging.info("No access_token provided, establishing new token.",
                     extra={"email": sub})

        key = settings.GOOGLE_OAUTH2_PRIVATE_KEY
        credentials = \
            SignedJwtAssertionCredentials(service_account_name=settings.GOOGLE_OAUTH2_SERVICE_ACCOUNT_EMAIL,
                                          private_key=key,
                                          scope=settings.GOOGLE_OAUTH2_SCOPE,
                                          sub=sub)

    if not http:
        # Authorize the httplib2.Http object with our credentials
        http = httplib2.Http()
        http = credentials.authorize(http)

    # We'll read the description of this API's function from
    # a JSON input file. Normally the client reaches out to either:
    # - https://www.googleapis.com/discovery/v1/apis/gmail/v1/rest
    # - https://www.googleapis.com/discovery/v1/apis/admin/directory_v1/rest
    # ... to get this information via apiclient.discovery.build(),
    # but that method causes a significant perfomance impact.
    path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(path, discovery)
    discovery = open(path).read()
    service = build_from_document(discovery, http=http, base="https://www.googleapis.com/")

    return credentials, http, service
