import datetime
import logging

from celery import Celery
from mail_service.gmail_service import GmailService


celery = Celery('EOD_TASKS')
celery.config_from_object('mail_service.gmail_service.celeryconfig')

@celery.task(name='check_account_v1')
def check_account_v1(email, new_history_id, **kwargs):
    gmail = GmailService()
    gmail.check_account_v1(email, new_history_id, **kwargs)
    del gmail  # Force garbage collection


@celery.task(name='update_user_list_v1')
def update_user_list_v1(domain):
    gmail = GmailService()
    logging.info(gmail.update_user_list_v1(domain, "root@consuslabs.com"))
    del gmail  # Force garbage collection

@celery.task(name='refresh_domain_v1')
def refresh_domain_v1(domain, queue_time):
    gmail = GmailService()
    gmail.refresh_domain_v1(domain, queue_time)
    del gmail  # Force garbage collection

if __name__ == '__main__':
    celery.worker_main()
