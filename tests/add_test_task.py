#!/usr/bin/env python
import argparse
import datetime
import os

from celery import Celery
from random import SystemRandom
from apiclient.http import HttpMockSequence
from mail_service.gmail_service.worker import check_account_v1

celery = Celery('EOD_TASKS')
celery.config_from_object('celeryconfig')
cryptogen = SystemRandom()

HISTORY_ID = 6177392
USER = "mike@example.com"
USER_ID = "fee41cac0a4569a04d8a3de9"

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--num', required=True, type=int, help="Number of items to put on queue.")
    parser.add_argument('-p', '--percent', required=False, type=int, help="Percent (0-100) of checks that result in a (simulated) new Gmail message to process.")
    parser.add_argument('-d', '--date', action='store_true', help="Provide current time on each request? (requests >=15s old will be dropped by the message processor)")
    return parser.parse_args()

def add_check_account_task(num, date, percent):
    now = None
    if not percent:
        percent = 100

    message = "Adding %d tasks to the queue." % num
    if date:
        now = datetime.datetime.now()
        message = "%s Current time is being included on each request." % message

    message = "%s %d%% of checks will result in a (simulated) new Gmail message." % (message, percent)
    print(message)

    # Read in the JSON response simulations.
    path = os.path.dirname(os.path.realpath(__file__))
    history_hit = open(os.path.join(path, "history_hit.json")).read()
    history_miss = open(os.path.join(path, "history_miss.json")).read()
    message = open(os.path.join(path, "message.json")).read()
    single_message_metadata = open(os.path.join(path, "single_message_metadata.json")).read()
    insert = open(os.path.join(path, "insert.json")).read()
    profile = open(os.path.join(path, "profile.json")).read()

    for x in range(1, (num + 1)):
        rand = cryptogen.randrange(1,100)
        if rand <= percent:
            http = HttpMockSequence([
                ({'status': '200'}, history_hit),
                ({'status': '200', 'content-type': 'multipart/mixed; boundary="batch_VZm0VD2PDxI_AAZXUZ1osU4"'}, message),
                ({'status': '200'}, single_message_metadata),
                ({'status': '200'}, insert),
                ({'status': '200'}, ''),  # Delete message
                ({'status': '200'}, profile)])
        else:
            http = HttpMockSequence([
                ({'status': '200'}, history_miss)])

        check_account_v1.delay(USER, USER_ID, HISTORY_ID, queue_time=now, http=http)

def main():
    args = parse_args()
    add_check_account_task(args.num, args.date, args.percent)

if __name__ == "__main__":
    main()
