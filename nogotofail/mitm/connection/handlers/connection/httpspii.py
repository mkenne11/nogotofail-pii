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
import logging
from nogotofail.mitm.connection.handlers.connection import LoggingHandler
from nogotofail.mitm.connection.handlers.connection import handlers
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
from nogotofail.mitm import util
from nogotofail.mitm.util import PIIDetectionUtilities
import httplib
import urlparse
import zlib


class PIIDetectionHandler(LoggingHandler):

    name = "piidetection"
    description = "Detect HTTPS requests and responses and allow \
        classes that inherit from this to process"

    # HTTP headers to ignore not containing PII
    IGNORE_HEADERS = ["host", "connection", "content-length", "accept",
                      "user-agent", "content-type", "accept-encoding",
                      "accept-language", "accept-charset"]
    # HTTP request and response valid "content-type" header values
    VALID_CONTENT_TYPES = ["text/html", "application/json",
                           "text/plain", "text/xml", "application/xml"]

    def on_ssl(self, client_hello):
        self.ssl = True
        self.client_session_id = client_hello.session_id
        # self.log(logging.DEBUG, "*** HTTPSDecryptTest > " +
        #     "TLS on_ssl method triggered")
        return True

    def on_request(self, request):
        http = util.http.parse_request(request)
        if self.ssl and http and not http.error_code:
            host = http.headers.get("host", self.connection.server_addr)
            if not self.connection.hostname:
                self.connection.hostname = host
            self.on_https_request(http)
        return request

    def on_https_request(self, http):
        host = http.headers.get("host", self.connection.server_addr)

    def on_response(self, response):
        http = util.http.parse_response(response)
        if self.ssl and http:
            headers = dict(http.getheaders())
            host = headers.get("host", self.connection.server_addr)
            if not self.connection.hostname:
                self.connection.hostname = host
            if not self.connection.ssl:
                self.on_https_response(http)
        return response

    def on_https_response(self, http):
        comment = "Code to be added in class inheriting this."

    def _get_request_message_content(self, http):
        http_content = ""
        headers = dict(http.headers)
        content_len = int(headers.get("content-length", 0))
        # Retrieve content from HTTP request message body
        if (content_len > 0):
            http_content = http.rfile.read(content_len)
        return http_content

    def _get_response_message_content(self, http):
        """ Method returns the HTTP message body content. Compressed content is
            uncompressed and content is truncated to a managable size """
        CHUNK_SIZE = 1024
        http_content = ""
        headers = dict(http.getheaders())
        content_type = headers.get("content-type", "")
        content_len = int(headers.get("content-length", "0"))
        content_encoding = headers.get("content-encoding", "")
        content_chunk_list = []
        if (content_len == 0):
            return http_content
        number_of_chunks = 0
        try:
            while True:
                content_chunk = http.read(CHUNK_SIZE)
                content_chunk_list.append(content_chunk)
                number_of_chunks += 1
                # Stop reading HTTP content after all chunks are read
                if not content_chunk:
                    break
                    # Stop reading HTTP content after 2 chunks
                elif ((content_type == "text/html" or
                       content_type == "text/plain") and
                      number_of_chunks == 2):
                    break
        except httplib.IncompleteRead, e:
            content_chunk = e.partial
            content_chunk_list.append(content_chunk)
        http_content = ''.join(content_chunk_list)
        # self.log(logging.DEBUG, "HTTP response headers: " + \
        #    "content-type - %s; content-encoding - %s" \
        try:
            # Decompress compressed content
            if ("deflate" in content_encoding or "gzip" in content_encoding):
                http_content = zlib.decompress(http_content, zlib.MAX_WBITS|32)
                # self.log(logging.DEBUG, "HTTP Content - %s."
                #    % http_content)
        except zlib.error, e:
            # Handling decompression of a truncated or partial file
            # is read
            zlib_partial = zlib.decompressobj(zlib.MAX_WBITS | 32)
            http_content = zlib_partial.decompress(http_content)
        return http_content


@handler(handlers, default=True)
class EncryptedPIIDetectionHandler(PIIDetectionHandler):

    name = "encryptedpii"
    description = (
        "Testing to see if encrypted PII is present in HTTPS content.")
    MITM_CA = "./ca-chain-cleartext.key.cert.pem"
    ca = util.CertificateAuthority(MITM_CA)
    certificate = None

    def on_https_request(self, http):
        client = self.connection.app_blame.clients.get(self.connection
                        .client_addr)
        if (client):
            headers = dict(http.headers)
            host = headers.get("host", self.connection.server_addr)
            content_type = headers.get("content-type", "")
            # debug_message = [
            #     "*** EncryptedPII > ",
            #     "TLS on_request - unencrypted HTTPS: host - ",
            #     host, ", path - ", http.path]
            # self.log(logging.DEBUG, "".join(debug_message))
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
                self._test_pii_query_string(query_string, combined_pii, url)
            # Search for PII in HTTP headers
            valid_header_text = ""
            # Remove headers which won't contain PII
            valid_headers = {k: v for k, v in headers.iteritems()
                             if k not in self.IGNORE_HEADERS}
            if (valid_headers):
                valid_header_text = \
                    str(valid_headers.values()).translate(None, "[']")
                self._test_pii_headers(valid_header_text, combined_pii, url)
            # Search for PII in HTTP message body
            if (content_type in self.VALID_CONTENT_TYPES):
                msg_content = self._get_request_message_content(http)
                self._test_pii_request_message_body(msg_content, combined_pii, url)

    def on_https_response(self, http):
        client = self.connection.app_blame.clients.get(self.connection \
                    .client_addr)
        if (client):
            headers = dict(http.getheaders())
            host = headers.get("host", self.connection.server_addr)
            content_type = headers.get("content-type", "")
            # debug_message = [
            #    "*** EncryptedPII > ", "TLS on_response method: host - ", host,
            #    ", content_type - ", content_type]
            # self.log(logging.DEBUG, "".join(debug_message))
            if (content_type in self.VALID_CONTENT_TYPES):
                http_content = self._get_response_message_content(http)
                url = ""
                # Fetched combined PII collection
                combined_pii = client.combined_pii
                # Check for PII items in HTTP response message body
                self._test_pii_response_message_body(self, http_content,
                                                     combined_pii, url)

    def on_certificate(self, server_cert):
        subject = server_cert.get_subject()
        for k, v in subject.get_components():
            if k == "CN":
                cn = v
        debug_message = ["Generating MitM TLS certificate with CN - ", cn]
        self.log(logging.DEBUG, "".join(debug_message))
    
        extensions = [server_cert.get_extension(i)
                      for i in range(server_cert.get_extension_count())]
        altnames = [extension for extension in extensions
                    if extension.get_short_name() == "subjectAltName"]
        san = altnames[0] if len(altnames) > 0 else None
        self.certificate = self.ca.get_cert(cn, san)
        return self.certificate

    """ Private methods checking for PII with HTTP content
    """
    def _test_pii_query_string(self, query_string, combined_pii, url):
        """ Test and alert on instances of PII found in query string
        """
        pii_identifiers_found = []
        pii_location_found = []
        pii_details_found = []
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
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_location_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_QRY_STRING,
                  ": Location found in request query string ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_details_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_QRY_STRING,
                  ": Personal details found in request ",
                  "query string - ", str(pii_details_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))

    def _test_pii_headers(self, header_text, combined_pii, url):
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
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_location_found):
            error_message = \
                [PIIDetectionUtilities.CAVEAT_PII_HEADER,
                 ": Location found in request headers ",
                 "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_details_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_HEADER,
                  ": Personal details found in request headers - ",
                  str(pii_details_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))

    def _test_pii_request_message_body(self, msg_content, combined_pii, url):
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
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_location_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_MSG_BODY,
                  ": Location found in request message body ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_details_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_MSG_BODY,
                  ": Personal details found in request message body - ",
                  str(pii_details_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))

    def _test_pii_response_message_body(self, msg_content, combined_pii, url):
        """ Test and alert on instances of PII found in HTTP message body
        """
        pii_identifiers_found = []
        pii_location_found = []
        pii_details_found = []
        # Check if PII found in query string
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
        # If PII is found in headers raise INFO message in
        # message and event logs
        if (pii_identifiers_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_MSG_BODY,
                  ": Personal IDs found in response message body ",
                  str(pii_identifiers_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_location_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_MSG_BODY,
                  ": Location found in response message body ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_details_found):
            error_message = \
                 [PIIDetectionUtilities.CAVEAT_PII_MSG_BODY,
                  ": Personal details found in response message body - ",
                  str(pii_details_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
