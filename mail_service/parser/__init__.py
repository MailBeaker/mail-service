import authres
import authres.dmarc
import email
import logging
import re
import socket
import sys

from datetime import datetime, timedelta
from base64 import b64encode
from bs4 import BeautifulSoup
from email.utils import parseaddr
from mail_service import settings
from sdk import beaker
from sdk import sdk_settings
from urllib.parse import urlparse

class Parser():
    def __init__(self, service_name, service_message_id, original_message, email,
                 domain_name):
        """
        Class constructor.

        :param service_message_id: The Gmail message ID for this item.
        :param original_message: The String comprising the source message, including full headers and body.
        :param email: The email address of the customer.
        :param domain_name: The domain name of the customer.
        """
        self.beaker_client = beaker.Client()

        # Trim any extra newlines, whitespace
        self.original_message = original_message.strip()

        self.service_name = service_name
        self.service_message_id = service_message_id
        self.message_id = None
        self.message = None
        self.signed_message_id = None
        self.domain_id = None
        self.has_rules = False
        self.outbound_message = None
        self.domain_name = domain_name
        self.message_from_address = None
        self.message_from_name = None
        self.envelope_from_address = None
        self.rcpt_to_address = email
        self.link_ids = list()
        self.link_urls = list()
        self.authentication_results = None
        self.spf_result = None
        self.dkim_result = None
        self.dmarc_result = None

        self._parse_message()

    def get_body(self):
        """
        The function which returns the body in the form of a String, omitting all headers.

        :return: The String representation of the state of the self.outbound_message object, minus headers.
        """
        email_content = self.outbound_message.as_string(False)
        return email_content.split("\n\n", 1)[1].strip()

    def get_message(self):
        """
        The function which returns Beaker's Message object for this Message.

        :return: The Message dictionary.
        """
        return self.message

    def _parse_message(self):
        """
        The main function that coordinates the parsing of a message and its Content-Type segments.
        """

        # Send the original_message string to the email class to create an email object.
        self.outbound_message = email.message_from_bytes(self.original_message)

        # Process this message's header information.
        if self.outbound_message['From']:
            self.message_from_name, self.message_from_address = parseaddr(self.outbound_message['From'])
        if self.outbound_message['Return-Path']:
            _, self.envelope_from_address = parseaddr(self.outbound_message['Return-Path'])

        # Some sanity checks that we use to ensure that sender and recipient
        # information is never empty.
        if not self.envelope_from_address and self.message_from_address:
            self.envelope_from_address = self.message_from_address

        # Process the Date header and make sure we're not handling some super old
        # message that for whatever reason didn't make it into the DB.
        # The max amount of skew allowed is 5 minutes.
        received_date = self.outbound_message['Received'].split(';')[-1]
        if received_date:
            received_date = received_date.strip()
            date_tuple = email.utils.parsedate_tz(received_date)
            if date_tuple:
                date = datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
                if date:
                    now = datetime.now()
                    if (now - date) > timedelta(minutes = 5):
                        raise Exception("Message is older than 5 minutes (based on first 'Received' header) " \
                                        "and will not be processed.")

        # Process the Authentication-Results header.
        if self.outbound_message['Authentication-Results']:
           self.authentication_results = self.outbound_message['Authentication-Results']
           authres_header = "Authentication-Results: %s" % self.outbound_message['Authentication-Results']

           try:
               # Set the class properties for DKIM, SPF, and DMARC auth results.
               for result in authres.AuthenticationResultsHeader.parse(authres_header).results:
                   if hasattr(self, "%s_result" % result.method):
                       setattr(self, "%s_result" % result.method, result.result)
           except authres.AuthResError:
               logging.info("Error while parsing the Authentication-Results header.",
                            extra={"Authentication-Results": self.authentication_results,
                                   "email": self.rcpt_to_address,
                                   "service_message_id": self.message_id})

        # Get domain information, which will include the rules for this domain.
        domain = self.beaker_client.get_domain_by_domain_name(self.domain_name)
        self.domain_id = domain["id"]

        if "rules" in domain and len(domain["rules"]) > 0:
             self.has_rules = True

        # Create the message DB object here and get the message ID.
        payload = {
            'domain_name': self.domain_name,
            'message_from_address':  self.message_from_address,
            'envelope_from_address': self.envelope_from_address,
            'rcpt_to_address':  self.rcpt_to_address,
            'authentication_results': self.authentication_results,
            'service_name': self.service_name,
            'service_message_id': "NULL",
            'dmarc_result': self.dmarc_result,
            'spf_result': self.spf_result,
            'dkim_result': self.dkim_result
        }

        try:
            message = self.beaker_client.create_message(payload)
        except Exception:
            logging.exception("Error while attempting to create Message.",
                              extra={"email": self.rcpt_to_address,
                                     "service_message_id": self.message_id,
                                     "payload": payload})
            raise Exception("Could not create Message object; cannot continue.")

        self.message = message
        self.message_id = message["id"]
        self.signed_message_id = message["signed_id"]

        # Walk each message segment.
        self._walk_message()

        # Add our branding
        if not self.outbound_message['X-Protected-By']:
            self.outbound_message.add_header('X-Protected-By', str('MailBeaker'))

        if self.has_rules:
            # Run the rule set for this domain against this message.
            link_rules_dict = self.check_rules()

            # And parse the resulting dictionary to notify Beaker.
            for link_id, rule_ids in list(link_rules_dict.items()):
                rule_ids = rule_ids["rule_ids"]
                for rule_id in rule_ids:
                    self.beaker_client.mark_link_with_rule(rule_id, link_id)

        # Add the Signed ID JWT to the message header.
        self.outbound_message.add_header('X-MailBeaker-Message', self.signed_message_id)

    def _generate_rules_recipients_list(self):
        # Build a list of all potential recipient combinations
        recipients = list()
        recipients.append(self.rcpt_to_address)

        if self.outbound_message['To']:
            to_header_recipients = self.outbound_message['To']
            to_header_recipients = ''.join(to_header_recipients.splitlines())
            to_header_recipients = email.utils.getaddresses([to_header_recipients])
            for name, address in to_header_recipients:
                # "Matthew Sullivan" <sullivan.matt@gmail.com> --> ("Matthew Sullivan", "sullivan.matt@gmail.com")
                recipients.append(address)

        # And any addresses in 'Cc' message header.
        if self.outbound_message['Cc']:
            cc_header_recipients = self.outbound_message['Cc']
            cc_header_recipients = ''.join(cc_header_recipients.splitlines())
            cc_header_recipients = email.utils.getaddresses([cc_header_recipients])
            for name, address in cc_header_recipients:
                recipients.append(address)

        # The list of message recipients might have duplicate values. Clean them.
        recipients = list(set(recipients))
        return recipients

    def check_rules(self):
        subject = "(no subject)"
        if self.outbound_message['Subject']:
            subject = self.outbound_message['Subject'].strip()

        link_rules_dict = self.beaker_client.check_rules(
            message_from_address=self.message_from_address,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            link_ids=self.link_ids,
            senders=None,
            receivers=None,
            subject=subject,
            body=self.get_body(),
            urls=None
            )

        return link_rules_dict

    def _walk_message(self):
        """
        The function which walks the e-mail object payloads and replaces all the links in HTML segments.  If
        the message is text-only, then the message is converted to HTML first.
        """

        # Do a check here to see if the message has an HTML payload in it.
        has_html = self._has_html()

        # If the message is multipart, walk it and check each segment.
        if self.outbound_message.is_multipart():
            for msg_part in self.outbound_message.walk():
                self._perform_message_segment_conversion(msg_part, has_html)

        else:
            self._perform_message_segment_conversion(self.outbound_message, has_html)

    def _perform_message_segment_conversion(self, msg_part, has_html):
        """
        The function which investigates each payload and replaces all the links in HTML segments.  If the message
        is text-only, then the message is converted to HTML first.

        :param msg_part: The text payload to analyze. Note that this object is mutable, and gets modified directly
        by passing the payload in. It never needs returned.
        :param has_html: A boolean indicating whether the entire message contained any text/html payloads.
        """

        # Check to see if this message has an attachment.
        if msg_part['Content-Disposition']:
            # TODO move to separate attachment-handling function.
            attachment_filename = msg_part.get_filename()
            # fp.write(part.get_payload(decode=True))
            logging.info("This message has an attachment.",
                         extra={"email": self.rcpt_to_address,
                                "service_message_id": self.message_id,
                                "attachment_filename": attachment_filename})

        # If this portion of the message isn't text, we'll just exit early
        # because there's nothing for us to process.
        if not msg_part.get_content_type().lower().startswith("text/"):
            return

        # If this segment has a specific Content-Transfer-Encoding, we need to keep it.
        nested_content_transfer_encoding = None
        if msg_part['Content-Transfer-Encoding']:
            nested_content_transfer_encoding = msg_part['Content-Transfer-Encoding']

        # We do everything in UTF-8. Your e-mail client doesn't support UTF-8?
        # Well... too damn bad. Leave that shit in the 90s where it belongs.
        # This will also set the Content-Transfer-Encoding to base64, so
        # make sure we adjust for that.
        msg_part.set_charset("UTF-8")

        nested_payload = msg_part.get_payload(i=None, decode=True)
        if not nested_payload:
            return

        if not nested_content_transfer_encoding or \
                        nested_content_transfer_encoding == "7bit" or nested_content_transfer_encoding == "8bit":
            # This segment has no Content-Transfer-Encoding, or it's 7 or 8-bit and we should be worried
            # about exceeing the 1,000 character MIME line limit. We're going to convert it
            # to quoted-printable on its way out to better align with MIME standards and ensure
            # that other mail systems won't attempt to line break the text and break DKIM signatures.
            nested_content_transfer_encoding = "quoted-printable"

        # If the overall message contains no HTML portion, but it does contain a plaintext segment,
        # then we convert the plaintext to HTML so we can ensure links are replaced in a pretty way.
        if not has_html and msg_part.get_content_type().lower().startswith("text/plain"):
            nested_payload = nested_payload.replace(b'\r\n', b'<br />')  # Change Windows newlines to HTML breaks
            nested_payload = nested_payload.replace(b'\n', b'<br />')  # Change Linux newlines to HTML breaks
            msg_part.set_type("text/html")

        nested_payload = self._perform_message_segment_replacements(nested_payload, msg_part.get_content_type())
        msg_part.set_payload(nested_payload)

        # Now we have some new shiny data. Re-apply the old Content-Transfer-Encoding.
        if nested_content_transfer_encoding:
            if nested_content_transfer_encoding.lower() == "quoted-printable":
                del msg_part['Content-Transfer-Encoding']  # The encoding process below re-adds it.
                email.encoders.encode_quopri(msg_part)
            elif nested_content_transfer_encoding.lower() == "base64":
                del msg_part['Content-Transfer-Encoding']  # The encoding process below re-adds it.
                email.encoders.encode_base64(msg_part)

    def _perform_message_segment_replacements(self, message_segment, segment_content_type):
        """
        The main function that coordinates the replacement of links in a message segment.

        :param message_segment: The human-readable form of the message segment.
        :param segment_content_type: The Content-Type encoding the segment was transported in.
        :return: The processed message segment.
        """
        found_valid_links = False

        # If the type is text/html, then we do some replacement work.
        if not segment_content_type.startswith("text/html"):
            return message_segment

        # Retain a copy of the original message segment, used later in this function.
        original_message_segment = message_segment

        # Convert any non-links to links in the HTML.
        message_segment = self._convert_urls_to_links_in_html(message_segment)

        if b'href=' in message_segment:
            message_segment, found_valid_links = self._replace_hrefs(message_segment)

        # If valid links were found, append the notice HTML header
        #if found_valid_links:
        #    message_segment = self._add_html_header(message_segment)
        # TODO make an endpoint for reporting ^

        # Add the original message segment as a base64-encoded HTML comment.
        #original_message_segment = "<!--\nMessage Protected by MailBeaker " \
        #                           "(mailbeaker.com)\nOriginal message content:\n%s\n-->" \
        #                           % b64encode(original_message_segment).decode('ascii')
        #return message_segment + original_message_segment.encode('utf-8')
        return message_segment

    def _replace_hrefs(self, in_body):
        """
        The function which replaces hrefs in each body segment.

        :param in_body: The human-readable form of the message segment.
        :return: The message segment with all links replaced.
        """

        found_valid_links = False
        original_a_tags = list()  # Stores discovered anchor tags
        original_hrefs = list()  # Stores discovered links

        message_html_soup = BeautifulSoup(in_body)

        # Find all 'a' and 'area' tags containing the 'href' property
        for discovered_href in message_html_soup.findAll(['a', 'area'], href=True):
            url = discovered_href['href'].strip()
            if (len(url) == 0 or
                url.startswith("mailto:") or
                url.startswith("tel:") or
                url.startswith("#") or
                # Allow Google calendar response links ('Yes', 'No', 'Maybe') to not be replaced.
                # On Android, this will cause a better experience because the Calendar handler
                # ties directly into Gmail app.
                # TODO Make a regex to work with international Google TLDs
                url.startswith("https://www.google.com/calendar/event?action=RESPOND")
            ):
                continue

            # Check this link to see if it's a MailBeaker link. If it is,
            # we unwrap it.
            discovered_href['href'] = self._unwrap_mailbeaker_link(url)

            found_valid_links = True
            original_a_tags.append(discovered_href)
            original_hrefs.append(discovered_href['href'])

        try:
            replacement_link_ids, replacement_links = self.beaker_client.generate_replacement_links(original_hrefs,
                                                                                               self.message_id,
                                                                                               self.domain_id,
                                                                                               # The following is used to not save a beta user's links, by request.
                                                                                               email=self.rcpt_to_address)
        except Exception as e:
            # Something failed while attempting to retrieve a new link URL, just go on.
            logging.exception("Link generation failed.",
                              extra={"email": self.rcpt_to_address,
                                     "service_message_id": self.message_id,
                                     "links": original_hrefs})  # TODO temp, remove from logging in the near future
            return in_body, found_valid_links

        for i, anchor_tag in enumerate(original_a_tags):
            try:
                a_title = "Protected by MailBeaker.  Original link destination: " + \
                          self._html_encode(anchor_tag['href'])

                anchor_tag['title'] = a_title
                anchor_tag['href'] = replacement_links[i].replace("\"", "")
            except Exception as e:
                # Something failed while attempting to replace the link. Warn and proceed.
                logging.exception("Link replacement failed.",
                                  extra={"email": self.rcpt_to_address,
                                         "service_message_id": self.message_id})

        # Dump the Soup back out to a string in the proper encoding
        in_body = message_html_soup.encode_contents(encoding='utf-8')

        # Update the message object's lists for links and link IDs.
        self.link_urls.extend(original_hrefs)
        self.link_ids.extend(replacement_link_ids)

        return in_body, found_valid_links

    def _unwrap_mailbeaker_link(self, url):
        """
        The function which tries to find existing MailBeaker links and unwrap them into their original URLs.

        :param url: The link URL to inspect. If the URL is a MailBeaker processed link, it will be unwrapped.
        :return: A non-MailBeaker URL.
        """

        # Our links will contain '/v1/' in them.
        if not "/v1/" in url:
            return url

        mailbeaker_links = re.findall( '/v1/(.*?)/', url, re.DOTALL | re.IGNORECASE)
        if len(mailbeaker_links) != 1:
            return url

        # Found a regex match.
        link_jwt = mailbeaker_links[0]

        # Check for valid JWT formatting. JWTs will have exactly two periods.
        if link_jwt.count('.') != 2:
            return url


        # !! TODO !! - Hook this back up using the SDK JWT lib

        # At this point we're pretty confident that we're dealing with a JWT.
        # Let's try to decode it and we'll see if it's one of ours.
        #try:
        #    link_jwt = jwt.decode(link_jwt.decode('ascii'), sdk_settings.API_V1_ECDSA_PUBLIC, algorithms=['ES256'])
        #    link_url = link_jwt["u"]
        #    # If the above doesn't throw an exception, then it's a link of ours.
        #    logging.info("An existing MailBeaker link was detected and unwrapped successfully.",
        #                 extra={"email": self.rcpt_to_address,
        #                        "service_message_id": self.message_id})
        #    return link_url

        #except jwt.DecodeError:  # TODO consider lowering this logging level:
        #    logging.exception("JWT decode error encountered while attempting " \
        #                      "to decode a suspected existing MailBeaker link.",
        #                      extra={"email": self.rcpt_to_address,
        #                             "service_message_id": self.message_id,
        #                             "url": url})
        #except jwt.ExpiredSignature:
        #    logging.exception("Signature error encountered while attempting " \
        #                      "to decode a suspected existing MailBeaker link.",
        #                      extra={"email": self.rcpt_to_address,
        #                             "service_message_id": self.message_id,
        #                             "url": url,
        #                             "jwt": link_jwt})

        # Our fall-through case. If something in the JWT process caused an exception,
        # we are going to just return the original, unmodified URL.
        return url


    def _add_html_header(self, in_body):
        """
        The function which adds an HTML header to HTML messages presenting a 'report' link.

        :param in_body: The segment of the message body to append the HTML header to.
        :return: The modified segment of the message body with the HTML header.
        """

        header = ('<div style="font-family:'
                 '\'Arial\',\'Helvetica\',\'sans-serif\';'
                 'font-size:12px;padding:4px 8px 4px 8px;'
                 'background-color:#75489c"> <span style="color: '
                 '#FFFFFF"><strong>MailBeaker</strong></span>'
                 '&nbsp;&nbsp;<span style="font-size: 1.5em; '
                 'color: #FFFFFF">&#9993;</span><span style="color: '
                 '#FFFFFF">&nbsp;&nbsp;&nbsp; | &nbsp;&nbsp;&nbsp;'
                 '</span><a style="color: #FFFFFF" '
                 'href="#" '
                 'target="_blank">Is this message suspicious? '
                 'Report it!</a></div><br />\n')

        return header + in_body

    def _has_html(self):
        """
        The function which checks for HTML content in a message.

        :return: Whether or not the message object contains HTML content.
        """

        for part in self.outbound_message.walk():
            if part.get_content_type().startswith("text/html"):
                return True
        return False

    def _generate_search_text(self, input_text):
        """
        The function which generates search text by removing certain HTML entities.

        :param input_text: The input string which will be stripped down to useful search text.
        :return: The processed search text, ready for use in a replacement routine.
        """

        search_text = input_text

        # Note: I've attempted this in BeautifulSoup in the past because it seemed
        # to me there must be a better way to do this, but for all my effort I've
        # actually not yet come up with a better way than these regex searches.

        # We start with finding and temporarily removing all 'a' tags and anything inside them.
        hrefs_pattern = re.compile(rb'<a .*?>.*?<.*?\/a.*?>', re.DOTALL | re.IGNORECASE) # "<a *>*<*/a*>"
        for item in hrefs_pattern.findall(input_text):
            search_text = search_text.replace(item, b" " * len(item))  # Replace with number of spaces in match

        # Remove any 'style' tags and anything inside them.
        style_pattern = re.compile(rb'<style.*?>.*?<.*?\/style.*?>', re.DOTALL | re.IGNORECASE) # "<style*>*<*/style*>"
        for item in style_pattern.findall(input_text):
            search_text = search_text.replace(item, b" " * len(item))  # Replace with number of spaces in match

        # Then remove anything that occurs inside of a tag at all.
        # e.g. "<div I am stupid>Doh!</div>" becomes "Doh!"
        tags_pattern = re.compile(rb'<.*?>', re.DOTALL | re.IGNORECASE)  # Anything between <>
        for item in tags_pattern.findall(input_text):
            search_text = search_text.replace(item, b" " * len(item))  # Replace with number of spaces in match

        # And now, in the end, we have a string that has the same length as the
        # original input value, but contains no meaningful tags.
        return search_text

    def _convert_urls_to_links_in_html(self, html_content):
        """
        The function which converts non-linked URLs to links in HTML content.

        :param html_content: The HTML string to investigate for non-linked URLs.
        :return: The modified string, with non-linked URLs converted to 'a' tags.
        """

        # Here's a pretty darn good URL pattern for matching.
        # https://gist.github.com/gruber/8891611
        url_pattern = re.compile(rb'(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:\'".,<>?])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))',
        re.DOTALL | re.IGNORECASE)

        search_text = self._generate_search_text(html_content)
        offset = 0  # We use this to keep track of length differences as we replace strings.

        for match in url_pattern.finditer(search_text):
            start_position = match.start() + offset
            end_position = match.end() + offset

            insert_text = self._substitute_url_for_html_link(match.group().decode('ascii'))

            if not isinstance(insert_text, bytes):
                insert_text = insert_text.encode('utf-8')

            if not isinstance(html_content, bytes):
                html_content = html_content.encode('utf-8')

            html_content = html_content[:start_position] + insert_text + html_content[end_position:]
            offset = offset + len(insert_text) - (end_position - start_position)

        return html_content

    def _substitute_url_for_html_link(self, url):
        """
        The function which takes a plain-text URL and returns an HTML link.

        :param url: The plain-text URL string.
        :return: A string containing the HTML link.
        """

        # Before putting in a link, we want to do some basic sanity
        # checking on it. Use urlparse, get the domain, and try to
        # resolve it.
        try:
            u = urlparse(url)
            domain = u.hostname
            resolved = socket.gethostbyname(u.hostname)
        except Exception as e:
            # If we encounter any errors parsing, we can
            # assume something is wrong with this candidate URL,
            # and just decide to skip it.
            logging.info("A candidate URL was discovered, but did not pass sanity check.",
                         extra={"email": self.rcpt_to_address,
                                "service_message_id": self.message_id,
                                "candidate_url": url,
                                "exception": str(e)})
            return url

        replacement_url = url
        if not '://' in url:
            replacement_url = 'http://' + replacement_url

        return "<a href=\"%s\">%s</a>" % (replacement_url, url)

    def _html_encode(self, text):
        """
        Returns HTML with escaped special characters (e.g. '&' becomes '&amp;')

        :param text: The text to replace characters in with HTML entities.
        :return: The HTML text with special characters replaced with HTML entities.
        """

        return (text
                .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("'", "&#39;").replace('"', "&quot;")
        )
