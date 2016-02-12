import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import os
from base64 import b64decode

AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID', 'changeme')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY', 'changeme')

GOOGLE_OAUTH2_PRIVATE_KEY="""
BASE64 ENCODED P12 FILE CONTENTS HERE"""

# Google API settings for the Gmail Service
GOOGLE_OAUTH2_SERVICE_ACCOUNT_EMAIL = os.getenv("GOOGLE_OAUTH2_SERVICE_ACCOUNT_EMAIL", "changeme")
GOOGLE_OAUTH2_SCOPE = os.getenv("GOOGLE_OAUTH2_SCOPE", "https://mail.google.com/ https://www.googleapis.com/auth/admin.directory.user.readonly")
GOOGLE_OAUTH2_PRIVATE_KEY = b64decode(os.getenv("GOOGLE_OAUTH2_PRIVATE_KEY", GOOGLE_OAUTH2_PRIVATE_KEY).strip())

# Splunk settings
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'splunk.example.com')
SPLUNK_PORT = os.getenv('SPLUNK_PORT', '8089')
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD', 'changeme')
SPLUNK_INDEX = os.getenv('SPLUNK_INDEX', 'main')
SPLUNK_VERIFY = os.getenv('SPLUNK_VERIFY', 'False')
SPLUNK_VERIFY = False if SPLUNK_VERIFY == 'False' else True

# Logging settings
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(created)f %(exc_info)s %(filename)s %(funcName)s %(levelname)s %(levelno)s %(lineno)d %(module)s %(message)s %(pathname)s %(process)s %(processName)s %(relativeCreated)d %(thread)s %(threadName)s'
        }
    },
    'handlers': {
        'splunk': {
            'level': 'INFO',
            'class': 'splunk_handler.SplunkHandler',
            'formatter': 'json',
            'host': SPLUNK_HOST,
            'port': SPLUNK_PORT,
            'username': SPLUNK_USERNAME,
            'password': SPLUNK_PASSWORD,
            'index': SPLUNK_INDEX,
            'sourcetype': 'json',
            'verify': SPLUNK_VERIFY
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
        }
    },
    'loggers': {
        '': {
            'handlers': ['console', 'splunk'],
            'level': 'INFO'
        }
    }
}


try:
    from .settingslocal import *
except ImportError:
    pass
