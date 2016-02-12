import base64
import datetime
import json
import logging

from apiclient import errors
from apiclient.http import BatchHttpRequest
from logging import config
from mail_service.parser import Parser
from mail_service import settings
from mail_service.gmail_service.authentication import authenticate
from oauth2client.client import AccessTokenCredentialsError
from sdk import beaker

SERVICE = "gmail"
QUEUE_TIMEOUT = 60

# Setup logging
config.dictConfig(settings.LOGGING)

class GmailService():
    """
    The Gmail Service class used to interface with the Gmail API.
    """
    def __init__(self):
        """
        Class setup function
        """
        self.beaker_client = beaker.Client()
        self.credentials = None
        self.http = None
        self.service = None
        self.email = None
        self.email_id = None
        self.abort_run = False

    def check_account_v1(self, email, new_history_id, queue_time=None, http=None):
        """
        Check a user's email account

        :param email: The user's email account.
        :param new_history_id: The new history ID for this account, as given by the Gmail Push message.
        :param queue_time: The max amount of time the message can be on the queue before getting purged.
        :param http: Optional HTTP object to use (used in tests).
        """
        queue_timeout = self._check_for_queue_timeout(queue_time)
        if queue_timeout:
            return

        self.email = email
        self.domain = email.split("@")[1]

        # Do a quick sanity check on the history ID value.
        #if last_history_id < 1:
        #    logging.critical("History ID failed sanity check, cannot continue!",
        #                     extra={'email': self.email,
        #                            'history_id': last_history_id})
        #    return

        # Service object is returned from authentication request to Google.
        self.credentials, self.http, self.service = authenticate(service="gmail", discovery="gmail_discovery.json",
                                                                 version="v1",
                                                                 sub=self.email,
                                                                 access_token=self._get_auth_token(),
                                                                 http=http)
        # Get the Beaker EmailMeta object for this user.
        email_meta = self.beaker_client.get_email_by_address(email)

        if not email_meta:
            logging.error("Could not associate the e-mail address to a " \
                          "Beaker user, cannot continue!",
                          extra={'email': self.email})
            return

        # Get some data from the EmailMeta for later use.
        self.email_id = email_meta['id']
        last_history_id = email_meta['history_id']
        email_whitelisted = email_meta['whitelisted']
        email_blacklisted = email_meta['blacklisted']

        # Get the Beaker Domain object.
        domain = self.beaker_client.get_domain_by_domain_name(self.domain)

        if not domain:
            logging.error("Could not associate the e-mail address to a " \
                          "Beaker domain, cannot continue!",
                          extra={'email': self.email,
                                 'domain': self.domain})
            return

        # If True, whitelist mode active; else blacklist mode
        domain_whitelist_enabled = domain['whitelisted']

        # Time to determine whether or not we should actually check this account.
        proceed = False
        if domain_whitelist_enabled:
            proceed = email_whitelisted
        else:
            proceed = email_blacklisted

        if not proceed:
            logging.info("Processing disabled for this address; will not continue!",
                         extra={'email': self.email,
                                'domain_whitelist_enabled': domain_whitelist_enabled,
                                'email_whitelisted': email_whitelisted,
                                'email_blacklisted': email_blacklisted})
            return

        # Get the last value of the historyId, used to get changes.
        last_history_id = email_meta['history_id']

        # If the last history ID is the same as was in the PubSub, ignore it.
        if last_history_id >= new_history_id:
            return

        # Go get the history of this e-mail and return a list of changes.
        try:
            changes = self._get_history(last_history_id)
        # This is our first attempt at using the access token, so make sure it works.
        except AccessTokenCredentialsError:
            logging.error("Access token not accepted. Clearing token from cache.",
                          extra={'email': self.email})
            self._clear_auth_token()
            return
        except AttributeError:
            # Google returned a 404, meaning that the account's specified history ID did not exist.
            # This is common, and happens if we ask for a history ID that is too old.
            # Instead, we'll retrieve the most recent one and update Beaker with the info.
            #logging.warning("History ID %d not found for user, getting current history." %
            #                last_history_id,
            #                extra={'email': self.email})
            #new_history_id = self._get_history_id(last_history_id=last_history_id)
            logging.warning("Specified history ID not found for user, setting to the value "
                            "provided in the PubSub message.",
                            extra={'email': self.email,
                                   'last_history_id': last_history_id})

            # Update Beaker
            beaker_email = {
                "history_id": str(new_history_id),
            }
            self.beaker_client.update_email(self.email_id, beaker_email)
            return

        # There will be a number of duplicate message IDs that we'll receive.
        # We must find all message IDs, and then dedup them.
        # TODO probably no longer needed with 'messagesAdded' feature.  Strip this out.
        updated_message_ids = []
        for change in changes:
            if not 'messagesAdded' in change:
                continue

            for messageAdded in change['messagesAdded']:
                message = messageAdded['message']
                message_id = message['id']
                if not message_id in updated_message_ids:
                    updated_message_ids.append(message_id)

        # Each of the message IDs need to be processed. We'll submit them in a bulk request.
        batch = BatchHttpRequest()
        items_in_batch = 0
        for updated_message_id in updated_message_ids:
            # Check Redis to see if this message ID is marked
            # as being processed.
            lock = self._get_message_lock(updated_message_id)
            if lock:
                logging.info("Message has already been locked for processing.",
                             extra={"email": self.email,
                                    "service_message_id": updated_message_id})
                continue
            else:
                self._save_message_lock(updated_message_id)

            # Check with Beaker to see if this is a message we've already processed.
            # This is an expensive operation, so we cache heavily on the Beaker side (1hr).
            # The above operation to check with Redis first should reduce/nearly eliminate
            # the use of this check.
            service_message = self.beaker_client.get_message_by_service_id(updated_message_id, cache_maxage=3600)
            if service_message:
                logging.info("Message has already been processed.",
                             extra={"email": self.email,
                                    "service_message_id": updated_message_id})
                continue

            logging.info("Preparing to process message.",
                         extra={"email": self.email,
                                "service_message_id": updated_message_id})
            batch.add(self.service.users().messages().get(userId=self.email, id=updated_message_id, format='raw'),
                      request_id=updated_message_id, callback=self._process_message)
            items_in_batch += 1

        #new_history_id = last_history_id
        new_history_id_from_profile = new_history_id
        if items_in_batch > 0:
            # The bulk query for the changed messages have been staged, now run them.
            self._execute_batch(batch)
            new_history_id_from_profile = self._get_history_id(last_history_id=last_history_id)

            # After executing the batch, check and see if any of the runs called for an abort.
            if self.abort_run:
                return

        # Once our run is finished, check and see if we
        # had to initiate a new auth token and, if so,
        # cache it. See function declaration for details.
        self._save_auth_token()

        logging.info("The last history ID was %s. The history ID in the PubSub was %s. "
                     "Next time, start at history ID %s (from profile)" % (last_history_id, str(new_history_id), str(new_history_id_from_profile)),
                     extra={'email': self.email,
                            "old_history_id": last_history_id,
                            "new_history_id_pubsub": new_history_id,
                            "new_history_id_profile": new_history_id_from_profile,
                            "processed_message_count": items_in_batch})

        # If the history ID has changed, inform Beaker.
        if last_history_id != new_history_id_from_profile:
            beaker_email = {
                "history_id": str(new_history_id_from_profile),
            }
            self.beaker_client.update_email(self.email_id, beaker_email)

    def _get_history(self, last_history_id, http=None):
        """
        Gets the history for this Gmail account.

        :param last_history_id: The history ID as of the last check; our starting point.
        :param http: Optional HTTP object to use (used in tests).
        :return: A list of changes to messages on this account.
        """
        if not http: http=self.http

        changes = []

        try:
            history = self.service.users().history().list(userId=self.email, startHistoryId=last_history_id,
                                                          labelId="INBOX").execute(http=http)
            changes = history['history'] if 'history' in history else []

            while 'nextPageToken' in history:
                page_token = history['nextPageToken']
                history = (self.service.users().history().list(userId=self.email,
                                                               startHistoryId=last_history_id,
                                                               pageToken=page_token).execute(http=http))
                if 'history' in history:
                    history = history['history']
                    changes.extend(history)
        except errors.HttpError as e:
            if hasattr(e, 'content'):
                content = e.content.decode('ascii')
                try:
                    error = json.loads(content).get('error', None)
                    if error:
                        if error.get('code') == 404:
                            raise AttributeError('History ID for specified account does not exist '
                                                 '(Google returned status 404).')
                        logging.exception("Error %d: %s" % (error.get('code'), error.get('message')),
                                          extra={"email": self.email})
                    else:
                        logging.exception("An exception was raised during retrieval of inbox history information, "
                                          "but no error information was returned by Google.",
                                          extra={'email': self.email})
                except ValueError:
                    logging.error("An exception was raised during retrieval of inbox history information and "
                                  "information was returned by Google, but the JSON error "
                                  "payload could not be loaded.",
                                  extra={'email': self.email})
            else:
                logging.exception("Exception while attempting to get inbox history information via Gmail API.",
                                  extra={'email': self.email})

        return changes

    def _get_history_id(self, last_history_id=None, http=None):
        """
        Get the current history ID for this Gmail account.

        :param last_history_id: The history ID as of the last check; our starting point.
        :param http: Optional HTTP object to use (used in tests).
        :return: The user's current history ID.
        """
        if not http: http=self.http

        new_history_id = last_history_id

        try:
            profile = self.service.users().getProfile(userId=self.email).execute(http=http)
            new_history_id = profile["historyId"]
        except errors.HttpError as e:
            if hasattr(e, 'content'):
                content = e.content.decode('ascii')
                try:
                    error = json.loads(content).get('error', None)
                    if error:
                        logging.exception("Error %d: %s" % (error.get('code'), error.get('message')),
                                          extra={'email': self.email})
                    else:
                        logging.exception("An exception was raised during retrieval of profile information, "
                                          "but no error information was returned by Google.",
                                          extra={'email': self.email})
                except ValueError:
                    logging.error("An exception was raised during retrieval of profile information and "
                                  "information was returned by Google, but the JSON error "
                                  "payload could not be loaded.",
                                  extra={'email': self.email})
            else:
                logging.exception("Exception while attempting to get profile information via Gmail API.",
                                  extra={'email': self.email})

        return new_history_id

    def _get_message(self, message_id, format="raw", http=None):
        """
        Get a message from this Gmail account.

        :param message_id: The Message ID to retrieve.
        :param http: Optional HTTP object to use (used in tests).
        :return: The requested Message from this account.
        """
        if not http: http=self.http

        try:
            return self.service.users().messages().get(userId=self.email, id=message_id,
                                                format=format).execute(http=http)
        except errors.HttpError as e:
            if hasattr(e, 'content'):
                content = e.content.decode('ascii')
                try:
                    error = json.loads(content).get('error', None)
                    if error:
                        logging.exception("Error %d: %s" % (error.get('code'), error.get('message')),
                                          extra={"email": self.email,
                                                 "service_message_id": message_id})
                    else:
                        logging.exception("An exception was raised while attempting to get a message, "
                                          "but no error information was returned by Google.",
                                          extra={"email": self.email,
                                                 "service_message_id": message_id})
                except ValueError:
                    logging.error("An exception was raised while attempting to get a message and "
                                  "information was returned by Google, but the JSON error "
                                  "payload could not be loaded.",
                                  extra={"email": self.email,
                                         "service_message_id": message_id})
            else:
                logging.exception("Exception while attempting to get message via Gmail API.",
                                  extra={"email": self.email,
                                         "service_message_id": message_id})

    def _execute_batch(self, batch, http=None):
        """
        Run a batch job.

        :param batch: The batch job to execute.
        :param http: Optional HTTP object to use (used in tests).
        """
        if not http: http=self.http

        try:
            batch.execute(http=http)
        except errors.HttpError as e:
            if hasattr(e, 'content'):
                content = e.content.decode('ascii')
                try:
                    error = json.loads(content).get('error', None)
                    if error:
                        logging.exception("Error %d: %s" % (error.get('code'), error.get('message')),
                                          extra={'email': self.email})
                    else:
                        logging.exception("An exception was raised during a batch processing job, "
                                          "but no error information was returned by Google.",
                                          extra={'email': self.email})
                except ValueError:
                    logging.error("An exception was raised during a batch processing job and "
                                  "information was returned by Google, but the JSON error "
                                  "payload could not be loaded.",
                                  extra={'email': self.email})
            else:
                logging.exception("Exception while attempting to process a batch job via Gmail API.",
                                  extra={'email': self.email})

    def _delete_message(self, message_id, http=None):
        """
        Delete the message with the specified ID from this Gmail account.

        :param message_id: The message ID to delete from Gmail.
        :param http: Optional HTTP object to use (used in tests).
        """
        if not http: http=self.http

        try:
            self.service.users().messages().delete(userId=self.email, id=message_id).execute(http=http)
            logging.info("Message was deleted.",
                         extra={"email": self.email,
                                "service_message_id": message_id})
        except errors.HttpError as e:
            if hasattr(e, 'content'):
                content = e.content.decode('ascii')
                try:
                    error = json.loads(content).get('error', None)
                    if error:
                        logging.exception("Error %d: %s" % (error.get('code'), error.get('message')),
                                          extra={"email": self.email,
                                                 "service_message_id": message_id})
                    else:
                        logging.exception("An exception was raised while attempting to delete a message, "
                                          "but no error information was returned by Google.",
                                          extra={"email": self.email,
                                                 "service_message_id": message_id})
                except ValueError:
                    logging.error("An exception was raised while attempting to delete a message and "
                                  "information was returned by Google, but the JSON error "
                                  "payload could not be loaded.",
                                  extra={"email": self.email,
                                         "service_message_id": message_id})
            else:
                logging.exception("Exception while attempting to delete message via Gmail API.",
                                  extra={"email": self.email,
                                         "service_message_id": message_id})

    def _insert_message(self, new_message, http=None):
        """
        Insert the provided message into this Gmail account.

        :param new_message: The MIME message to insert.
        :param http: Optional HTTP object to use (used in tests).
        :return: A tuple of ([boolean] insert successful, the Gmail message object,
                 [boolean] insert failed because of a missing thread).
        """
        if not http: http=self.http

        insert_successful = False
        inserted_message = None
        missing_thread = False
        try:
            inserted_message = self.service.users().messages().insert(userId=self.email,
                                                                      internalDateSource="dateHeader",
                                                                      body=new_message).execute(http=http)
            insert_successful = True
        except errors.HttpError as e:
            if hasattr(e, 'content'):
                content = e.content.decode('ascii')
                try:
                    error = json.loads(content).get('error', None)
                    if error:
                        # If we get a 404 error, it almost certainly means we couldn't put this message into the
                        # specified threadId (thread no longer exists).  We remove that declaration and try again.
                        if error.get('code') == 404 and 'threadId' in new_message:
                            missing_thread = True
                        else:
                            logging.exception("Error %d: %s" % (error.get('code'), error.get('message')),
                                              extra={'email': self.email})
                    else:
                        logging.exception("An exception was raised while attempting to insert a message, "
                                          "but no error information was returned by Google.",
                                          extra={'email': self.email})
                except ValueError:
                    logging.error("An exception was raised while attempting to insert a message and "
                                  "information was returned by Google, but the JSON error "
                                  "payload could not be loaded.",
                                  extra={'email': self.email})
            else:
                logging.exception("Exception while attempting to insert a message via Gmail API.",
                                  extra={'email': self.email})

        return (insert_successful, inserted_message, missing_thread)

    def _process_message(self, message_id, message, exception):
        """
        Prepare to process the provided message object (invoked from a batch request).

        :param message_id: The ID of the message to process.
        :param message: The Message to process.
        :param exception: The exception from the batch request (should always be 'None').
        """
        if exception is None:
            if self.abort_run:
               return

            try:
                self._process_message_worker(message_id, message)
            except Exception as e:
                logging.exception("An exception was raised during message processing. "
                                  "This run will be aborted prematurely to avoid looping.",
                                  extra={"email": self.email,
                                         "service_message_id": message_id})
                self.abort_run = True
        else:
            if isinstance(exception, errors.HttpError):
                if hasattr(exception, 'content'):
                    content = exception.content.decode('ascii')
                    try:
                        error = json.loads(content).get('error', None)
                        if error:
                            if error.get('code') == 404:
                                logging.info("Message is no longer available.",
                                             extra={"email": self.email,
                                                    "service_message_id": message_id})
                            else:
                                logging.exception("Error %d: %s" % (error.get('code'), error.get('message')),
                                                  extra={"email": self.email,
                                                     "service_message_id": message_id})
                        else:
                            logging.exception("An exception was raised in response to a query in a batch job, "
                                              "but no error information was returned by Google.",
                                              extra={"email": self.email,
                                                     "service_message_id": message_id})
                    except ValueError as e:
                        logging.error("An exception was raised in response to a query in a batch job and "
                                      "information was returned by Google, but the JSON error "
                                      "payload could not be loaded.",
                                      extra={"email": self.email,
                                             "service_message_id": message_id})
                else:
                    logging.exception("Exception while attempting to process "
                                      "response to a batch job via Gmail API.",
                                      extra={"email": self.email,
                                             "service_message_id": message_id})
            else:
                logging.exception("Exception while attempting to process response "
                                  "to a batch job via Gmail API.",
                                  extra={"email": self.email,
                                         "service_message_id": message_id})
            return

    def _process_message_worker(self, message_id, message):
        """
        Do the heavy lifting by processing the provided message object.

        :param message_id: The ID of the message to process.
        :param message: The Message to process.
        """

        # Some items have no labels (like chat history) and cannot be processed.
        if not 'labelIds' in message:
            return

        # Make sure this message still sits in the inbox. If not, we're going to skip it.
        if not "INBOX" in message['labelIds']:
            logging.info("Message is no longer in the Inbox",
                         extra={"email": self.email,
                                "service_message_id": message_id})
            return

        # Only process unread messages.  This weeks us from processing a message
        # that someone is currently reading.
        if not "UNREAD" in message['labelIds']:
            logging.info("Message is not marked as unread (initial check).",
                         extra={"email": self.email,
                                "service_message_id": message_id})
            return

        # Collect the thread and message IDs here, because we'll be using them often.
        thread_id = message['threadId']
        message_id = message['id']

        # Get the message_content, then send it through the parser system.
        message_content = base64.urlsafe_b64decode(message['raw'])
        #message_content = message_content.decode('ascii')

        try:
            processor = Parser(SERVICE, message_id, message_content,
                               self.email, self.domain)
            message_content = processor.outbound_message.as_string()
            beaker_message = processor.get_message()
        except:
            logging.exception("An uncaught exception occured in message parsing.",
                              extra={"email": self.email,
                                     "service_message_id": message_id})
            return

        # Prepare the new message object for posting to Google.
        new_message = dict()
        message_content = base64.urlsafe_b64encode(message_content.encode('ascii'))
        new_message['raw'] = message_content.decode('ascii')
        new_message['threadId'] = thread_id

        # Transfer the old labels to the new message, if they are present.
        if 'labelIds' in message:
            new_message['labelIds'] = message['labelIds']

            # Remove sent and draft labels, they are reserved
            # and cannot be set (https://developers.google.com/gmail/api/guides/labels)
            if "SENT" in new_message['labelIds']: new_message['labelIds'].remove("SENT")
            if "DRAFT" in new_message['labelIds']: new_message['labelIds'].remove("DRAFT")

        # Right before inserting the new message, we do a final check to make sure the original
        # is still marked as 'unread'.
        message_attributes = self._get_message(message_id, format="minimal")
        if not message_attributes:
            logging.info("Message vanished during processing (final check).",
                         extra={"email": self.email,
                                "service_message_id": message_id})

            return

        if not "UNREAD" in message_attributes['labelIds']:
            logging.info("Message is not marked as unread (final check).",
                         extra={"email": self.email,
                                "service_message_id": message_id})
            return

        insert_successful, inserted_message, missing_thread = self._insert_message(new_message)
        if insert_successful:
            logging.info("Message was processed successfully.",
                         extra={"email": self.email,
                                "service_message_id": message_id})
        else:
           if missing_thread:
               # If we get an error, it almost certainly means we couldn't put this message into the
               # specified threadId (thread no longer exists).  We remove that declaration and try again.
               logging.info("Thread %s is missing." % str(thread_id),
                            extra={"email": self.email,
                                   "service_message_id": message_id})
               del(new_message['threadId'])
               insert_successful, inserted_message, _ = self._insert_message(new_message)
               if not insert_successful:
                   logging.error("Could not insert message via Gmail API on the second attempt.",
                                 extra={"email": self.email,
                                        "service_message_id": message_id})
                   return
           else:
               logging.error("Could not insert message via Gmail API on the first attempt.",
                             extra={"email": self.email,
                                    "service_message_id": message_id})
               return

        inserted_message_id = inserted_message['id']

        # Update Beaker's Message object with the new Service Message ID.
        # NOTE: This blocks the thread, and could be spun into
        # it's own thread in the future, if deemed necessary.
        beaker_message_update = { "service_message_id": inserted_message_id }
        self.beaker_client.update_message(beaker_message['id'], beaker_message_update)

        # Tell Gmail to get rid of the old, unprocessed copy of the message.
        self._delete_message(message_id)

    def _check_for_queue_timeout(self, queue_time):
        if not queue_time:
            return False

        # TODO: Log the time difference here to both Splunk and statsd
        now = datetime.datetime.now()
        diff = (now - queue_time).seconds
        if diff >= QUEUE_TIMEOUT:
            logging.warning("Queue timeout.",
                             extra={'email': self.email,
                                    'queue_time': diff})
            return True
        else:
            logging.info("Determined amount of time on queue.",
                         extra={'email': self.email,
                                'queue_time': diff})

        return False

    def _save_auth_token(self):
        """
        If a new set of credentials had to be established for the mail
        checking run that just finished (e.g. the cache didn't have any),
        then we save the server's access_token and expiration reponses
        for future use.
        """
        # 'token_response' is only populated if the credentials in question
        # were authorized fresh, and not initiated from the cache.
        if not self.credentials.access_token or not self.credentials.token_response:
            return

        self.beaker_client.save_auth_token(SERVICE, self.email, self.credentials.access_token,
                                      self.credentials.token_response.get('expires_in', None))

    def _get_auth_token(self):
        """
        Check if there's an existing OAuth2 token authorized for this e-mail address.

        :return: An authorized OAuth2 token from the cache.
        """
        token = self.beaker_client.get_auth_token(SERVICE, self.email)
        return token

    def _clear_auth_token(self):
        """
        Clear any existing OAuth2 tokens for this e-mail address.
        """
        self.beaker_client.clear_auth_token(SERVICE, self.email)

    def _get_message_lock(self, service_message_id):
        """
        Check for a lock on a given service message ID.
        """
        self.beaker_client.get_message_lock(service_message_id)

    def _save_message_lock(self, service_message_id):
        """
        Set a lock for a given service message ID.
        """
        self.beaker_client.save_message_lock(service_message_id)

    ###################
    """
    TODO
    Most of the above code is specific to modifying e-mail messages.
    We need to split the functions in this file out into new files,
    one for e-mail related functions and one (or more) for functions
    related to things like updating the user list.
    """
    ###################

    def refresh_domain_v1(self, domain, queue_time=None, http=None):
        if not http: http=self.http
        #domain = self.beaker_client.get_domain_by_domain_name(domain)
        #domain_id = domain['id']
        #admin_emails = self.beaker_client.get_organization_user_emails(domain_id)
        #print(admin_emails)
        print(domain)

    def update_user_list_v1(self, domain, admin_email, http=None):
        """
        Get a list of users for a domain. An admin_email is required to act on the behalf of.

        :param domain: The domain to retrieve users for.
        :param admin_email: An admin on the Google Apps domain to act on behalf of.
        :param http: Optional HTTP object to use (used in tests).
        :return: A list of all users for the account.
        """
        if not http: http=self.http
        self.email = admin_email

        self.credentials, self.http, self.service = authenticate(service="admin", discovery="admin_sdk_discovery.json",
                                                                 version="directory_v1",
                                                                 sub=admin_email,
                                                                 access_token=self._get_auth_token(),
                                                                 http=http)

        all_users = []
        page_token = None
        params = {'domain': domain, 'fields': "users(id,name,primaryEmail,isAdmin)"}
        # [{'isAdmin': True, 'name': {'familyName': 'Labs', 'givenName': 'Consus', 'fullName': 'Consus Labs'}, 'primaryEmail': 'root@consuslabs.com', 'id': '104606403928391733102'}, {'isAdmin': False, 'name': {'familyName': 'Support', 'givenName': 'Consus Labs', 'fullName': 'Consus Labs Support'}, 'primaryEmail': 'support@consuslabs.com', 'id': '117148913238924156783'}]
        while True:
            try:
                if page_token:
                    params['pageToken'] = page_token

                current_page = self.service.users().list(**params).execute(http=http)

                all_users.extend(current_page['users'])
                page_token = current_page.get('nextPageToken')
                if not page_token:
                   break
            except errors.HttpError as e:
                if hasattr(e, 'content'):
                    content = e.content.decode('ascii')
                    try:
                        error = json.loads(content).get('error', None)
                        if error:
                            logging.exception("Error %d: %s" % (error.get('code'), error.get('message')),
                                              extra={"email": self.email})
                        else:
                            logging.exception("An exception was raised while attempting to list domain users, "
                                              "but no error information was returned by Google.",
                                              extra={"email": self.email})
                    except ValueError:
                        logging.error("An exception was raised while attempting to list domain users and "
                                      "information was returned by Google, but the JSON error "
                                      "payload could not be loaded.",
                                      extra={"email": self.email})
                else:
                    logging.exception("Exception while attempting to list domain users via Directory API.",
                                      extra={"email": self.email})
                return

        return all_users
