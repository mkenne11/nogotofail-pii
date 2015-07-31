r'''
Copyright 2014 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''
from nogotofail.mitm import util
from nogotofail.mitm.connection.handlers.data import handlers
from nogotofail.mitm.connection.handlers.data import HttpDetectionMessageBodyHandler
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
from nogotofail.mitm.util import PIIDetectionUtilities
import logging
import urlparse


@handler.passive(handlers)
class HTTPPIIDetectionHandler(HttpDetectionMessageBodyHandler):
    """Check if PII appears in plain text http traffic http query strings.
    """
    name = "httppii"
    description = "Detect PII in clear text http requests and responses"

    def on_http_request(self, http):
        client = self.connection.app_blame.clients.get(self.connection
                        .client_addr)
        if (client):
            headers = dict(http.headers)
            host = headers.get("host", self.connection.server_addr)
            content_type = headers.get("content-type", "")
            url = host + http.path
            # Extract query string from request url.
            url_parts = urlparse.urlparse(url)
            query_string = url_parts[4]
            combined_pii = client.combined_pii
            # self.log(logging.DEBUG, "piiquerystringdetection: " + \
            #     "Request query string - %s; encoding - %s" % \
            #     (query_string, content_encoding))
            #     "headers host - %s; encoding - %s" % \
            #     (host, http.headers))
            # Fetch combined collection of PII

            # Search for PII in HTTP query string
            if (query_string):
                self._alert_on_PII_query_string(query_string, combined_pii, url)
            # Search for PII in HTTP headers
            valid_header_text = ""
            # Remove headers which won't contain PII
            valid_headers = {k: v for k, v in headers.iteritems()
                             if k not in PIIDetectionUtilities.IGNORE_HEADERS}
            if (valid_headers):
                valid_header_text = \
                    str(valid_headers.values()).translate(None, "[']")
                self._alert_on_pii_headers(valid_header_text, combined_pii, url)
            # Search for PII in HTTP message body
            if (content_type in PIIDetectionUtilities.VALID_CONTENT_TYPES):
                msg_content = self._get_request_message_content(http)
                self._alert_on_pii_request_message_body(msg_content, combined_pii, url)

    def on_http_response(self, http):
        """ Method processes unencrypted (non-HTTPS) HTTP response message bodies
        """
        client = self.connection.app_blame.clients.get(self.connection.client_addr)
        if (client):
            if (http):
                headers = dict(http.getheaders())
                # host = headers.get("host", "")
                content_type = headers.get("content-type", "")
                content_len = int(headers.get("content-length", 0))

                if (content_type in PIIDetectionUtilities.VALID_CONTENT_TYPES
                    and content_len > 0):
                    url = ""
                    # Fetch message body content
                    msg_content = self._get_response_message_content(http)
                    # Fetched combined PII collection
                    combined_pii = client.combined_pii
                    self._alert_on_pii_response_message_body(msg_content,
                            combined_pii, url)

    """ Private methods checking for PII with HTTP content
    """
    def _alert_on_PII_query_string(self, query_string, combined_pii, url):
        """ Test and alert on instances of PII found in query string
        """
        pii_identifiers_found = []
        pii_location_found = []
        pii_details_found = []
        error_message = ""
        # Check if PII found in query string
        if (combined_pii["identifiers"]):
            pii_identifiers_found = \
                PIIDetectionUtilities.detect_pii_ids(query_string,
                                        combined_pii["identifiers"])
        if (combined_pii["location"]):
            pii_location_found = \
                PIIDetectionUtilities.detect_pii_location(query_string,
                                        combined_pii["location"])
        if (combined_pii["details"]):
            pii_details_found = \
                PIIDetectionUtilities.detect_pii_details(query_string,
                                        combined_pii["details"])
        # If PII is found in query string raise INFO message in
        # message and event logs
        if (pii_identifiers_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_QRY_STRING,
                  ": Personal IDs found in request query string ",
                  str(pii_identifiers_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_location_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_QRY_STRING,
                  ": Location found in request query string ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_details_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_QRY_STRING,
                  ": Personal details found in request ",
                  "query string - ", str(pii_details_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)

    def _alert_on_pii_headers(self, header_text, combined_pii, url):
        """ Test and alert on instances of PII found in HTTP headers
        """
        pii_identifiers_found = []
        pii_location_found = []
        pii_details_found = []
        # Check if PII found in query string
        if (combined_pii["identifiers"]):
            pii_identifiers_found = \
                PIIDetectionUtilities.detect_pii_ids(header_text,
                                        combined_pii["identifiers"])
        if (combined_pii["location"]):
            pii_location_found = \
                PIIDetectionUtilities.detect_pii_location(header_text,
                                        combined_pii["location"])
        if (combined_pii["details"]):
            pii_details_found = \
                PIIDetectionUtilities.detect_pii_details(header_text,
                                        combined_pii["details"])
        # If PII is found in headers raise INFO message in
        # message and event logs
        if (pii_identifiers_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_HEADER,
                  ": Personal IDs found in request headers ",
                  str(pii_identifiers_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_location_found):
            error_message = \
                [PIIDetectionUtilities.CAVEAT_PII_HEADER,
                 ": Location found in request headers ",
                 "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_details_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_HEADER,
                  ": Personal details found in request headers - ",
                  str(pii_details_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)

    def _alert_on_pii_request_message_body(self, msg_content, combined_pii, url):
        """ Test and alert on instances of PII found in HTTP message body
        """
        pii_identifiers_found = []
        pii_location_found = []
        pii_details_found = []
        # Check if PII found in message body
        if (combined_pii["identifiers"]):
            pii_identifiers_found = \
                PIIDetectionUtilities.detect_pii_ids(msg_content,
                                        combined_pii["identifiers"])
        if (combined_pii["location"]):
            pii_location_found = \
                PIIDetectionUtilities.detect_pii_location(msg_content,
                                        combined_pii["location"])
        if (combined_pii["details"]):
            pii_details_found = \
                PIIDetectionUtilities.detect_pii_details(msg_content,
                                        combined_pii["details"])
        # If PII is found in message body raise INFO message in
        # message and event logs
        if (pii_identifiers_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_MSG_BODY,
                  ": Personal IDs found in request message body ",
                  str(pii_identifiers_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_location_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_MSG_BODY,
                  ": Location found in request message body ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_details_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_MSG_BODY,
                  ": Personal details found in request message body - ",
                  str(pii_details_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)

    def _alert_on_pii_response_message_body(self, msg_content, combined_pii, url):
        """ Test and alert on instances of PII found in HTTP message body
        """
        pii_identifiers_found = []
        pii_location_found = []
        pii_details_found = []
        # Check if PII found in message body
        if (combined_pii["identifiers"]):
            pii_identifiers_found = \
                PIIDetectionUtilities.detect_pii_ids(msg_content,
                                        combined_pii["identifiers"])
        if (combined_pii["location"]):
            pii_location_found = \
                PIIDetectionUtilities.detect_pii_location(msg_content,
                                        combined_pii["location"])
        if (combined_pii["details"]):
            pii_details_found = \
                PIIDetectionUtilities.detect_pii_details(msg_content,
                                        combined_pii["details"])
        # If PII is found in message body raise INFO message in
        # message and event logs
        if (pii_identifiers_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_MSG_BODY,
                  ": Personal IDs found in response message body ",
                  str(pii_identifiers_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_location_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_MSG_BODY,
                  ": Location found in response message body ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_details_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_MSG_BODY,
                  ": Personal details found in response message body - ",
                  str(pii_details_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
