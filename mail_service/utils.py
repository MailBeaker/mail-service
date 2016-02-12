from mail_service import settings
from logging import config

config.dictConfig(settings.LOGGING)
