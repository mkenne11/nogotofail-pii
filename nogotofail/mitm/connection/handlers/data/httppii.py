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
from nogotofail.mitm import util
from nogotofail.mitm.connection.handlers.data import handlers
from nogotofail.mitm.connection.handlers.data import DataHandler
from nogotofail.mitm.connection.handlers.data import HttpDetectionHandler
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
import re
import urlparse
import itertools
from StringIO import StringIO
import gzip
import httplib
import zlib


@handler.passive(handlers)
class PIIQueryStringDetectionHandler(DataHandler):
    """Check if PII appears in plain text http traffic http query strings.
    """
    name = "piiquerystringdetection"
    description = "Detect PII in plain text http query string"

    def on_request(self, request):
        client = self.connection.app_blame.clients.get(self.connection.client_addr)
        if (client):
            # Fetch combined collection of PII
            combined_pii = client.combined_pii
            #server_pii = self.connection.get_pii()
            #self.log(logging.DEBUG, "Server PII - %s." % server_pii)
            #self.log(logging.DEBUG, "Client Combined PII - %s." % combined_pii)

            # Get HTTP request details
            http = util.http.parse_request(request)
            if not (http and not http.error_code):
                return request
            host = http.headers.get("host", self.connection.server_addr)
            #content_encoding = http.request_headers.get('content-encoding','')
            url = host + http.path
            # Extract query string from request url.
            url_parts = urlparse.urlparse(url)
            query_string = url_parts[4]
            #self.log(logging.DEBUG, "piiquerystringdetection: " + \
                #"Request query string - %s; encoding - %s" % \
                #(query_string, content_encoding))
                #"headers host - %s; encoding - %s" % \
                #(host, http.request_headers))

            # Search for PII in HTTP query string
            pii_identifiers_found = []
            pii_location_found = []
            pii_details_found = []

            if (query_string):
                if (combined_pii["identifiers"]):
                    pii_identifiers_found = \
                        PIIDetectionUtilities.detect_pii_ids(query_string, \
                            combined_pii["identifiers"])
                if (combined_pii["location"]):
                    pii_location_found = \
                        PIIDetectionUtilities.detect_pii_location(query_string, \
                            combined_pii["location"])
                if (combined_pii["details"]):
                    pii_details_found = \
                        PIIDetectionUtilities.detect_pii_details(query_string, \
                            combined_pii["details"])

                ### If PII found in query string raise a notification
                ###
                # If PII identifiers found in query string
                if (pii_identifiers_found):
                    error_message = \
                        ["PII: Personal IDs found in request query string ", \
                        str(pii_identifiers_found)]
                    self.log(logging.ERROR, "".join(error_message))
                    self.log_event(logging.ERROR, connection.AttackEvent(
                            self.connection, self.name, True, url))
                    self.connection.vuln_notify(
                        util.vuln.VULN_PII_QUERY_STRING_DETECTION)
                # If PII location found in query string
                if (pii_location_found):
                    error_message = \
                        ["PII: Location found in request query string ", \
                         "(longitude, latitude) - ", str(pii_location_found)]
                    self.log(logging.ERROR, "".join(error_message))
                    self.log_event(logging.ERROR, connection.AttackEvent(
                            self.connection, self.name, True, url))
                    self.connection.vuln_notify(
                        util.vuln.VULN_PII_QUERY_STRING_DETECTION)
                # If PII details found in query string
                if (pii_details_found):
                    error_message = \
                        ["PII: Personal details found in request ", \
                         "query string - ", str(pii_details_found)]
                    self.log(logging.ERROR, "".join(error_message))
                    self.log_event(logging.ERROR, connection.AttackEvent(
                            self.connection, self.name, True, url))
                    self.connection.vuln_notify(
                        util.vuln.VULN_PII_QUERY_STRING_DETECTION)


@handler.passive(handlers)
class PIIHTTPHeaderDetectionHandler(HttpDetectionHandler):
    """Check if PII appears in plain text http (non-https) page headers.
    """
    name = "piihttpheaderdetection"
    description = "Detect pii in plain text http headers"

    def on_http(self, http):
        # Search http header text for PII
        client = self.connection.app_blame.clients.get(self.connection.client_addr)
        #self.log(logging.DEBUG, "piihttpheaderdetection: Client headers - %s." \
        #    % client.info["headers"])
        if (client):
            ### Search http header text for personal IDs
            request_headers = dict(http.headers)
            host = request_headers.get("host", self.connection.server_addr)
            url = host + http.path

            #self.log(logging.DEBUG, "piihttpheaderdetection: " +
            #    "on_http request headers - %s. " % request_headers )
            ignore_headers = ["host", "connection", "content-length", "accept", \
                "user-agent", "content-type", "accept-encoding", \
                "accept-language", "accept-charset"]
            valid_header_text = ""
            valid_headers = {k:v for k, v in request_headers.iteritems()
                if k not in ignore_headers}
            ### If valid headers, search request query string for PII
            ###
            if (valid_headers):
                valid_header_keys = valid_headers.keys()
                valid_header_text = \
                    str(valid_headers.values()).translate(None,"[']")
                #self.log(logging.DEBUG, "piihttpheaderdetection: Remaining " +
                #    "valid http headers - %s." % valid_header_keys )

                combined_pii = client.combined_pii

                ### Search for personal ID values in the request headers
                #pii_identifiers_found = [k for k, v in perm_personal_ids.iteritems()
                #    if v in valid_header_text]

                ### Search for device location in request headers
                ###
                location_in_headers = False
                if (combined_pii["location"]):
                    longitude = combined_pii["location"]["longitude"]
                    latitude = combined_pii["location"]["latitude"]
                    #self.log(logging.DEBUG, "piiquerystringdetection: " + \
                    #    "Device location [formatted] - long:%s; lat:%s." \
                    #    % (longitude, latitude))
                    if (longitude in valid_header_text and \
                        latitude in valid_header_text):
                        location_in_headers = True

                ### Search for PII in HTTP headers
                pii_identifiers_found = []
                pii_location_found = []
                pii_details_found = []

                if (combined_pii["identifiers"]):
                    pii_identifiers_found = \
                        PIIDetectionUtilities.detect_pii_ids(valid_header_text, \
                            combined_pii["identifiers"])
                if (combined_pii["location"]):
                    pii_location_found = \
                        PIIDetectionUtilities.detect_pii_location(valid_header_text, \
                            combined_pii["location"])
                if (combined_pii["details"]):
                    pii_details_found = \
                        PIIDetectionUtilities.detect_pii_details(valid_header_text, \
                            combined_pii["details"])

                ### If PII found in headers raise a notification.
                ###
                # If PII identifiers found in headers
                if (pii_identifiers_found):
                    error_message = \
                        ["PII: Personal IDs found in request headers - ", \
                        str(pii_identifiers_found)]
                    self.log(logging.ERROR, "".join(error_message))
                    self.log_event(logging.ERROR, connection.AttackEvent(
                            self.connection, self.name, True, url))
                    self.connection.vuln_notify(
                        util.vuln.VULN_PII_HTTP_HEADER_DETECTION)
                # If PII location found in headers
                if (pii_location_found):
                    error_message = \
                        ["PII: Location found in request headers ", \
                        "(longitude, latitude) - ", str(pii_location_found)]
                    self.log(logging.ERROR, "".join(error_message))
                    self.log_event(logging.ERROR, connection.AttackEvent(
                            self.connection, self.name, True, url))
                    self.connection.vuln_notify(
                        util.vuln.VULN_PII_HTTP_HEADER_DETECTION)
                if (pii_details_found):
                    error_message = \
                        ["PII: Personal details found in request headers - ", \
                        str(pii_details_found)]
                    self.log(logging.ERROR, "".join(error_message))
                    self.log_event(logging.ERROR, connection.AttackEvent(
                            self.connection, self.name, True, url))
                    self.connection.vuln_notify(
                        util.vuln.VULN_PII_HTTP_HEADER_DETECTION)

    # Not checking response headers as PII as couldn't find examples
    # containing PII.
    """
    def on_http_response(self, http):

    """


@handler.passive(handlers)
class PIIHTTPBodyDetectionHandler(HttpDetectionHandler):
    """Check if PII appears in plain text http (non-https) page headers.
    """
    name = "piihttpbodydetection"
    description = "Detect pii in plain text http bodies"

    # Process unencrypted (non-HTTPS) HTTP request message bodies
    def on_http(self, http):
        client = self.connection.app_blame.clients.get(self.connection.client_addr)
        if (client):
            if (http):
                # HTTP request valid "content-type" header values
                valid_content_type = ["text/html","application/json","text/plain", \
                    "text/xml","application/xml"]
                headers = dict(http.headers)
                host = headers.get("host", self.connection.server_addr)
                content_type = headers.get("content-type", "")
                content_len = int(headers.get("content-length", 0))
                url = host + http.path
                #self.log(logging.DEBUG, "HTTP request body: " + \
                #    "content-type - %s; content-len - %s;" \
                #    % (content_type, content_len) )

                # Retrieve content from HTTP request message body
                if (content_type in valid_content_type) and (content_len > 0):
                    http_content = http.rfile.read(content_len)
                #    self.log(logging.DEBUG, "HTTP request body: " + \
                #        "content - %s" % http_content )
                    # Fetched combined PII collection
                    combined_pii = client.combined_pii
                    # Check for PII identifiers in HTTP body
                    pii_identifiers_found = \
                        PIIDetectionUtilities.detect_pii_ids(http_content, \
                            combined_pii["identifiers"])
                    # Check for PII location in HTTP body
                    pii_location_found = \
                        PIIDetectionUtilities.detect_pii_location(http_content, \
                            combined_pii["location"])
                    # Check for PII details in HTTP body
                    pii_details_found = \
                        PIIDetectionUtilities.detect_pii_details(http_content, \
                            combined_pii["details"])

                    ### If PII found in HTTP body raise a notification
                    ###
                    # If PII identifiers found in HTTP body
                    if (pii_identifiers_found):
                        error_message = \
                            ["PII: Personal IDs found in HTTP request message ", \
                            "body - ", str(pii_identifiers_found)]
                        self.log(logging.ERROR, "".join(error_message))
                        self.log_event(logging.ERROR, connection.AttackEvent(
                            self.connection, self.name, True, url))
                        self.connection.vuln_notify(
                            util.vuln.VULN_PII_HTTP_BODY_DETECTION)
                    # If PII location found in HTTP body
                    if (pii_location_found):
                        error_message = \
                            ["PII: Location found in HTTP request message body ", \
                            "(longitude, latitude) - ", str(pii_location_found)]
                        self.log(logging.ERROR, "".join(error_message))
                        self.log_event(logging.ERROR, connection.AttackEvent(
                            self.connection, self.name, True, url))
                        self.connection.vuln_notify(
                            util.vuln.VULN_PII_HTTP_BODY_DETECTION)
                    # If PII details found in HTTP body
                    if (pii_details_found):
                        error_message = \
                            ["PII: Personal details found in HTTP request ", \
                            "message body - ", str(pii_details_found)]
                        self.log(logging.ERROR, "".join(error_message))
                        self.log_event(logging.ERROR, connection.AttackEvent(
                            self.connection, self.name, True, url))
                        self.connection.vuln_notify(
                            util.vuln.VULN_PII_HTTP_BODY_DETECTION)


    # Process unencrypted (non-HTTPS) HTTP response message bodies
    def on_http_response(self, http):
        client = self.connection.app_blame.clients.get(self.connection.client_addr)
        if (client):
            if (http):
                # HTTP response valid "content-type" header values
                valid_content_type = ["text/html","application/json","text/plain", \
                    "text/xml","application/xml"]
                headers = dict(http.getheaders())
                #host = headers.get("host", "")
                content_encoding = headers.get("content-encoding", "")
                content_type = headers.get("content-type", "")

                content_chunk_list = []
                number_of_chunks = 0
                try:
                    while True:
                        content_chunk = http.read(1024)
                        content_chunk_list.append(content_chunk)
                        number_of_chunks += 1
                        # Stop reading HTTP content when all chunks have been read
                        if not content_chunk:
                            break
                        # Stop reading HTTP HTML and text content when 2 chunks
                        # have been read i.e. truncate content.
                        elif ((content_type == "text/html" or \
                            content_type == "text/plain") and \
                            number_of_chunks == 2):
                            break
                except httplib.IncompleteRead, e:
                    content_chunk = e.partial
                    content_chunk_list.append(content_chunk)

                http_content = ''.join(content_chunk_list)
                #self.log(logging.DEBUG, "HTTP response headers: " + \
                #    "content-type - %s; content-encoding - %s" \
                #    % (content_type, content_encoding) )

                if (content_type in valid_content_type):
                    try:
                        if ("deflate" in content_encoding or
                            "gzip" in content_encoding):
                            # Decompress Deflate HTTP body
                            http_content = zlib.decompress(http_content, \
                                zlib.MAX_WBITS|32)
                            #self.log(logging.DEBUG, "HTTP Content - %s."
                            #    % http_content)
                    # Handling decompression of a truncated or partial file
                    # is read.
                    except zlib.error, e:
                        zlib_partial = zlib.decompressobj(zlib.MAX_WBITS|32)
                        http_content = zlib_partial.decompress(http_content)

                    # Fetched combined PII collection
                    combined_pii = client.combined_pii
                    # Check for PII identifiers in HTTP body
                    pii_identifiers_found = \
                        PIIDetectionUtilities.detect_pii_ids(http_content, \
                            combined_pii["identifiers"])
                    # Check for PII location in HTTP body
                    pii_location_found = \
                        PIIDetectionUtilities.detect_pii_location(http_content, \
                            combined_pii["location"])
                    # Check for PII details in HTTP body
                    pii_details_found = \
                        PIIDetectionUtilities.detect_pii_details(http_content, \
                            combined_pii["details"])

                    ### If PII found in HTTP body raise a notification
                    ###
                    # If PII identifiers found in HTTP body
                    if (pii_identifiers_found):
                        self.log(logging.ERROR,
                            "PII: Personal IDs found in HTTP response body - %s."
                            % pii_identifiers_found)
                        self.log_event(
                            logging.ERROR, connection.AttackEvent(
                                self.connection, self.name, True, url))
                        self.connection.vuln_notify(
                            util.vuln.VULN_PII_HTTP_BODY_DETECTION)
                    # If PII location found in HTTP body
                    if (pii_location_found):
                        self.log(logging.ERROR,
                            "PII: Location found in HTTP response body " + \
                            "(longitude, latitude) - %s" \
                            % pii_location_found)
                        self.log_event(
                            logging.ERROR,
                            connection.AttackEvent(
                                self.connection, self.name, True, url))
                        self.connection.vuln_notify(
                            util.vuln.VULN_PII_HTTP_BODY_DETECTION)
                    # If PII details found in HTTP body
                    if (pii_details_found):
                        self.log(logging.ERROR,
                            "PII: Personal details found in HTTP response body - %s."
                            % pii_details_found)
                        self.log_event(
                            logging.ERROR,
                            connection.AttackEvent(
                                self.connection, self.name, True, url))
                        self.connection.vuln_notify(
                            util.vuln.VULN_PII_HTTP_BODY_DETECTION)


class PIIDetectionUtilities(object):
    """General functions that can be used to search for PII items in
       HTTP strings e.g. headers, query strings, bodies.
    """

    @staticmethod
    def detect_pii_ids(http_string, pii_identifiers):
        ### Check for PII identifiers in HTTP headers
        ###
        # Merge plain-text, base 64 and url encoded versions of PII
        # identifiers into one dictionary.
        pii_identifiers_found = []
        personal_ids = pii_identifiers["plain-text"]
        base64_personal_ids = pii_identifiers["base64"]
        urlencoded_personal_ids = pii_identifiers["url-encoded"]

        perm_personal_ids = {}
        perm_personal_ids = {k:v for d in
            (personal_ids, base64_personal_ids, urlencoded_personal_ids)
            for k, v in d.iteritems()}

        # Search query string for personal identifier values.
        pii_identifiers_found = [k for k, v in
            perm_personal_ids.iteritems() if v in http_string]
        return pii_identifiers_found

    @staticmethod
    def detect_pii_location(http_string, pii_location):
        ### Check for device location in HTTP headers
        ###
        pii_location_found = []
        longitude = pii_location["longitude"]
        latitude = pii_location["latitude"]

        if (longitude in http_string and latitude in http_string):
            pii_location_found.append(longitude)
            pii_location_found.append(latitude)
        return pii_location_found

    @staticmethod
    def detect_pii_details(http_string, pii_details):
        ### Search HTTP headers for PII details
        ###
        # Merge plain-text, base 64 and url encoded versions of PII
        # details into one dictionary.
        pii_details_found = []
        personal_details = pii_details["plain-text"]
        base64_personal_details = pii_details["base64"]
        urlencoded_personal_details = pii_details["url-encoded"]

        perm_personal_details = {}
        perm_personal_details = {k:v for d in
            (personal_details, base64_personal_details, \
                urlencoded_personal_details)
            for k, v in d.iteritems()}

        pii_details_found = [k for k, v in
            perm_personal_details.iteritems() if v in http_string]
        return pii_details_found
