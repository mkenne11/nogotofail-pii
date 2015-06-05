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
from nogotofail.mitm.connection.handlers.data import ClientReportDetection
from nogotofail.mitm.connection.handlers.data import DataHandler
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
import re
import urlparse
import itertools


@handler.passive(handlers)
class HttpDetectionHandler(DataHandler):

    name = "httpdetection"
    description = "Detect plaintext HTTP requests and warn on them"

    def on_request(self, request):
        http = util.http.parse_request(request)
        if http and not http.error_code:
            host = http.headers.get("host", self.connection.server_addr)
            if not self.connection.hostname:
                self.connection.hostname = host
            self.on_http(http)
        return request

    def on_http(self, http):
        host = http.headers.get("host", self.connection.server_addr)
        self.log(logging.ERROR, "HTTP request %s %s"
                 % (http.command, host + http.path))
        self.log_event(
            logging.ERROR,
            connection.AttackEvent(
                self.connection, self.name, True,
                host + http.path))
        self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP)


@handler.passive(handlers)
class HttpAuthHandler(HttpDetectionHandler):

    name = "httpauthdetection"
    description = "Detect authorization headers in HTTP requests"

    def on_http(self, http):
        auth = http.headers.get("Authorization", None)
        host = http.headers.get("host", self.connection.server_addr)
        if auth:
            self.log(
                logging.CRITICAL,
                "Authorization header in HTTP request %s %s" %
                (http.command, host + http.path))
            self.log_event(
                logging.ERROR,
                connection.AttackEvent(
                    self.connection, self.name, True,
                    host + http.path))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_AUTH)


class _HttpReqReplacement(DataHandler):
    """Basic class for replacing the conents of a HTTP Request
    """

    def filter(self, http):
        return False

    def replace(self, http):
        return ""

    def on_request(self, request):
        http = util.http.parse_request(request)
        if http and not http.error_code:
            host = http.headers.get("host", self.connection.server_addr)
            if not self.connection.hostname:
                self.connection.hostname = host
            if self.filter(http):
                return self.replace(http)
        return request


class _ResponseReplacement(DataHandler):
    """Basic class for replacing the contents of a HTTP response
    """
    skip = 0

    def filter(self, data):
        return False

    def replace(self, data):
        return ""

    def on_response(self, request):
        if self.skip > 0:
            if self.skip >= len(request):
                self.skip -= len(request)
                return ""
            request = request[self.skip:]
            self.skip = 0
        if self.filter(request):
            return self.replace(request)
        return request


@handler(handlers, default=False)
class AndroidWebviewJsRce(_ResponseReplacement):

    name = "androidwebviewjsrce"
    description = "Detect Android Webview Javascript RCE"
    base_url = "/favicon.ico"
    base_payload = """
    <script language='Javascript'>
    for (i in window.top) {
        var o = top[i];
        try {
            o.getClass().forName('java.lang.Runtime');
            document.write('<img src=\"%s\" style=\"display:none;\" width=\"1\" height=\"1\"/>');
        } catch (e) {}
    };</script>"""

    def filter(self, data):
        resp = util.http.parse_response(data)
        return (resp and resp.status == 200 and
                resp.getheader("content-type", "").startswith("text/html"))

    def build_payload(self):
        url = ClientReportDetection.add_callback_url(
            self.on_report, self.base_url)
        return self.base_payload % (url)

    def on_report(self, data):
        if data is None:
            return

        self.log(
            logging.CRITICAL,
            "Client is vulnerable to Android Javascript RCE")
        self.log_event(
            logging.ERROR,
            connection.AttackEvent(self.connection, self.name, True, None))
        self.connection.vuln_notify(util.vuln.VULN_ANDROID_JAVASCRIPT_RCE)
        return False

    def replace(self, response):
        resp = util.http.parse_response(response)
        headers = dict(resp.getheaders())
        old_length = int(headers.get("content-length", 0))
        contents = resp.read(old_length)
        # Look for the <body> tag and inject the script after
        # HACK: Parsing HTML with regex is evil and broken but proper parsing is
        # hard
        match = re.search("<body.*>", contents)
        if not match:
            return response
        payload = self.build_payload()
        contents = contents[:match.end()] + payload + contents[match.end():]

        message = ("{version} 200 OK\r\n" + "\r\n".join(
            ["%s: %s" % (k, v) for k, v in headers.items()]) + "\r\n\r\n" + "{data}")

        headers["content-length"] = old_length + len(payload)
        version = "HTTP/1.0" if resp.version == 10 else "HTTP/1.1"
        data = message.format(version=version, data=contents)

        # Handle any extra data in response after the HTTP response
        total_consumed = response.index("\r\n\r\n") + 4 + old_length
        if total_consumed < len(response):
            data += response[total_consumed:]
        return data


@handler(handlers, default=False)
class SSLStrip(_ResponseReplacement):
    """Replace https urls with http. Uses the reporting mechanism to
    detect when these URLs are later visited and warns/notifies.
    """

    name = "sslstrip"
    description = (
        "Runs sslstrip on http traffic. Detects when sslstrip'd urls are visited.")
    content_types = [
        "application/json",
        "application/javascript",
        "application/x-javascript",
        "application/xml",
        "application/xhtml",
        "application/xhtml+xml",
        "text/.*",
    ]

    def filter(self, data):
        resp = util.http.parse_response(data)
        content_type = resp.getheader(
            "content-type", "").strip() if resp else ""
        return resp and (
            (resp.status == 200 and any(
                re.match(type, content_type)
                for type in SSLStrip.content_types))
            or (resp.status / 100 == 3  # 3XX are HTTP redirects
                and resp.getheader("location", "").startswith("https://")))

    def replace(self, response):
        resp = util.http.parse_response(response)
        if resp.status == 200:
            return self.replace_ok(response)
        elif resp.status / 100 == 3:
            return self.replace_redirect(response)
        else:
            self.log(
                logging.FATAL,
                "Unexpected status %s in SSLstrip replace" % resp.status)
            return ""

    def build_report_callback(self, url):
        def on_report(data):
            if data is None:
                return

            self.log(logging.CRITICAL, "SSLStrip'd URL %s was visited!" % url)
            self.log_event(
                logging.CRITICAL,
                connection.AttackEvent(
                    self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_SSL_STRIP)
            return False
        return on_report

    def replace_ok(self, response):
        """Handle sslstrip on HTTP responses that contain data.

        This goes through and replaces URLs in the response content.
        """
        resp = util.http.parse_response(response)
        headers = dict(resp.getheaders())
        old_length = int(headers.get("content-length", 0))
        contents = resp.read(old_length)

        new_contents = ""
        prev = 0
        # Not perfect but hopefully close enough.
        urls = re.finditer(
            "https://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
            contents)
        for match in urls:
            url = match.group(0)
            callback = self.build_report_callback(url)
            # strip the https
            url = "http://" + url[8:]
            new_url = ClientReportDetection.add_callback_url(
                callback, url, timeout=20)
            new_contents += contents[prev:match.start()] + new_url
            prev = match.end()
            self.log(
                logging.DEBUG,
                "Replacing %s with %s" % (match.group(0), new_url))
        new_contents += contents[prev:]

        headers["content-length"] = len(new_contents)
        version = "HTTP/1.0" if resp.version == 10 else "HTTP/1.1"

        message = ("{version} 200 OK\r\n" + "\r\n".join(
            ["%s: %s" % (k, v) for k, v in headers.items()]) + "\r\n\r\n" + "{data}")
        data = message.format(version=version, data=new_contents)

        # Handle any extra data in response after the HTTP response
        total_consumed = response.index("\r\n\r\n") + 4 + old_length
        if total_consumed < len(response):
            data += response[total_consumed:]

        return data

    def replace_redirect(self, response):
        """Handle sslstrip for HTTP redirects.

        This does SSLstrip on the Location header.
        """
        resp = util.http.parse_response(response)
        headers = dict(resp.getheaders())
        location = headers["location"]
        callback = self.build_report_callback(location)
        new_location = "http://" + location[8:]
        new_location = ClientReportDetection.add_callback_url(
            callback, new_location, timeout=5)
        headers["location"] = new_location
        self.log(logging.DEBUG,
                 "Replacing redirect to %s with %s" %
                 (location, new_location))
        version = "HTTP/1.0" if resp.version == 10 else "HTTP/1.1"

        message = ("{version} {status} OK\r\n" + "\r\n".join(
            ["%s: %s" % (k, v) for k, v in headers.items()]) + "\r\n\r\n")
        data = message.format(version=version, status=resp.status)

        # Handle any extra data in response after the HTTP response
        total_consumed = response.index(
            "\r\n\r\n") + 4 + int(headers.get("content-length", 0))
        if total_consumed < len(response):
            data += response[total_consumed:]
        return data


@handler(handlers)
class ImageReplacement(_ResponseReplacement):
    """Replace images downloaded over HTTP with replace.png.
    Useful for detecting mixed content and a bit of a laugh.
    """

    name = "imagereplace"
    description = (
        "Replace responses with Content-Type of image/* with ./replace.png")
    file = "./replace.png"
    data = None

    def filter(self, response):
        resp = util.http.parse_response(response)
        return (resp and resp.status == 200
                and resp.getheader("content-type", "").startswith("image/")
                and response.find("\r\n\r\n") != -1)

    def replace(self, response):
        resp = util.http.parse_response(response)
        headers = dict(resp.getheaders())
        if not ImageReplacement.data:
            with open(self.file) as f:
                ImageReplacement.data = f.read()
        old_length = int(headers.get("content-length", 0))
        length = len(self.data)
        headers["content-length"] = length
        headers["content-type"] = "image/png"

        message = ("{version} 200 OK\r\n" + "\r\n".join(
            ["%s: %s" % (k, v) for k, v in headers.items()]) + "\r\n\r\n" + "{data}")
        # HTTPResponse.version is kind of weird
        version = "HTTP/1.0" if resp.version == 10 else "HTTP/1.1"
        data = message.format(version=version, data=self.data)
        # figure out if we need to skip data
        if old_length > 0:
            content_offset = response.find("\r\n\r\n")
            total_length = content_offset + old_length
            if len(response) < total_length:
                self.skip = total_length - len(response)
        return data

@handler(handlers, default=False)
class BlockHTTP(HttpDetectionHandler):
    """Simple handler that drops connections doing HTTP
    """

    name = "blockhttp"
    description = "Block HTTP traffic"

    def on_http(self, http):
        self.connection.close()

@handler(handlers)
class DisableCDCPEncryption(HttpDetectionHandler):
    """Disable the Chrome Data Compression Proxy encryption.
    See https://support.google.com/chrome/answer/3517349
    """
    name = "disablecdcpencryption"
    description = "Disable Chrome Data Compression Proxy encryption"

    def on_http(self, http):
        host = http.headers.get("host")
        path = http.path
        if host == "check.googlezip.net" and path == "/connect":
            self.connection.close()

@handler.passive(handlers)
class PIIQueryStringDetectionHandler(DataHandler):
    """Check if PII appears in plain text http traffic http query strings.
    """
    name = "piiquerystringdetection"
    description = "Detect PII in plain text http query string"

    def on_request(self, request):
        client = self.connection.app_blame.clients.get(self.connection.client_addr)
        if (client):
            #try:
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
            url = host + http.path
            # Extract query string from request url.
            url_parts = urlparse.urlparse(url)
            query_string = url_parts[4]
            #self.log(logging.DEBUG, "piiquerystringdetection: " + \
            #    "Request query string - %s." % query_string)

            pii_identifiers_found = []
            pii_location_found = []
            pii_details_found = []
            # Check for PII in query stringbefore proceeding.
            if (query_string):
                if (combined_pii["identifiers"]):
                    pii_identifiers_found = \
                        self.detect_pii_ids_querystring(query_string, \
                            combined_pii["identifiers"])
                if (combined_pii["location"]):
                    pii_location_found = \
                        self.detect_pii_location_querystring(query_string, \
                            combined_pii["location"])
                if (combined_pii["details"]):
                    pii_details_found = \
                        self.detect_pii_details_querystring(query_string, \
                            combined_pii["details"])

            ### If PII found in query string raise a notification
            ###
            # If PII identifiers found in query string
            if (pii_identifiers_found):
                self.log(logging.ERROR,
                    "NP: Personal IDs found in request query string - %s."
                    % pii_identifiers_found)
                self.log_event(
                    logging.ERROR, connection.AttackEvent(
                        self.connection, self.name, True, url))
                self.connection.vuln_notify(
                    util.vuln.VULN_PII_QUERY_STRING_DETECTION)
            # If PII location found in query string
            if (pii_location_found):
                self.log(logging.ERROR,
                    "NP: Location found in request query string " + \
                    "(longitude, latitude) - %s" \
                    % pii_location_found)
                self.log_event(
                    logging.ERROR,
                    connection.AttackEvent(
                        self.connection, self.name, True, url))
                self.connection.vuln_notify(
                    util.vuln.VULN_PII_QUERY_STRING_DETECTION)
            # If PII details found in query string
            if (pii_details_found):
                self.log(logging.ERROR,
                    "NP: Personal details found in request query string - %s."
                    % pii_details_found)
                self.log_event(
                    logging.ERROR,
                    connection.AttackEvent(
                        self.connection, self.name, True, url))
                self.connection.vuln_notify(
                    util.vuln.VULN_PII_QUERY_STRING_DETECTION)
            #except Exception as e:
            #    self.log(logging.ERROR, str(e))

    def detect_pii_ids_querystring(self, query_string, pii_identifiers):
        ### Check for personal identifiers in the request query string.
        ###
        # Merge plain-text, base 64 and url encoded versions of personal
        # IDs into one dictionary.
        pii_identifiers_found = []
        personal_ids = pii_identifiers["plain-text"]
        base64_personal_ids = pii_identifiers["base64"]
        urlencoded_personal_ids = pii_identifiers["url-encoded"]

        perm_personal_ids = {}
        perm_personal_ids = {k:v for d in
            (personal_ids, base64_personal_ids, urlencoded_personal_ids)
            for k, v in d.iteritems()}
        #self.log(logging.ERROR, "perm_personal_ids - %s."
        #    % perm_personal_ids)

        # Search query string for personal identifier values.
        pii_identifiers_found = [k for k, v in
            perm_personal_ids.iteritems() if v in query_string]
        return pii_identifiers_found

    def detect_pii_location_querystring(self, query_string, pii_location):
        ### Check for device location in query string
        ###
        pii_location_found = []
        longitude = pii_location["longitude"]
        latitude = pii_location["latitude"]
        #self.log(logging.DEBUG, "piiquerystringdetection: " + \
        #    "Device location [formatted] - long:%s; lat:%s." \
        #    % (longitude, latitude))
        if (longitude in query_string and latitude in query_string):
            pii_location_found.append(longitude)
            pii_location_found.append(latitude)
        return pii_location_found

    def detect_pii_details_querystring(self, query_string, pii_details):
        ### Search query string for Personal details
        ###
        pii_details_found = []
        personal_details = pii_details["plain-text"]
        base64_personal_details = pii_details["base64"]
        urlencoded_personal_details = pii_details["url-encoded"]

        perm_personal_details = {}
        perm_personal_details = {k:v for d in
            (personal_details, base64_personal_details, \
                urlencoded_personal_details)
            for k, v in d.iteritems()}

        #self.log(logging.DEBUG, "piiquerystringdetection: " + \
        #    "Personal Details [PT] - %s." \
        #    % combined_pii["details"]["plain-text"])
        pii_details_found = [k for k, v in
            perm_personal_details.iteritems() if v in query_string]
        return pii_details_found

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
            try:
                ### Search http header text for personal IDs
                request_headers = dict(http.headers)
                host = request_headers.get("host", self.connection.server_addr)
                url = host + http.path

                #self.log(logging.DEBUG, "piihttpheaderdetection: " +
                #    "on_http request headers - %s. " % request_headers )
                ignore_headers = ["host", "connection", "content-length", "accept",
                    "user-agent", "content-type", "accept-encoding", "accept-language",
                    "accept-charset"]
                valid_header_text = ""
                valid_headers = {k:v for k, v in request_headers.iteritems()
                    if k not in ignore_headers}

                ### If valid headers, search request query string for PII
                ###
                if (valid_headers):
                    valid_header_keys = valid_headers.keys()
                    valid_header_text = str(valid_headers.values()).translate(None,"[']")
                    self.log(logging.DEBUG, "piihttpheaderdetection: Remaining " +
                        "valid http headers - %s." % valid_header_keys )

                    combined_pii = client.combined_pii
                    #personal_ids = client.info["PII-Identifiers"]["plain-text"]
                    #base64_personal_ids = client.info["PII-Identifiers"]["base64"]
                    personal_ids = combined_pii["identifiers"]["plain-text"]
                    base64_personal_ids = combined_pii["identifiers"]["base64"]
                    # Merge plain-text and base 64 encoded versions of personal
                    # IDs into one dictionary.
                    perm_personal_ids = {k:v for d in
                        (personal_ids, base64_personal_ids)
                        for k, v in d.iteritems()}

                    ### Search for personal ID values in the request headers
                    pii_identifiers_found = [k for k, v in perm_personal_ids.iteritems()
                        if v in valid_header_text]

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

                    ### Search for PII details in the request headers
                    ###
                    personal_details = combined_pii["details"]["plain-text"]
                    if (personal_details):
                        #self.log(logging.DEBUG, "piihttpheaderdetection: " + \
                        #    "Personal Details [PT] - %s." \
                        #    % combined_pii["details"]["plain-text"])
                        # TODO: Add check for personal details.
                        iii = 1

                    ### If PII found in headers raise a notification.
                    ###
                    if (pii_identifiers_found):
                        self.log(logging.ERROR,
                            "NP: Personal IDs found in request headers - %s."
                            % pii_identifiers_found)
                        self.log_event(
                            logging.ERROR,
                            connection.AttackEvent(
                                self.connection, self.name, True, url))
                        self.connection.vuln_notify(
                            util.vuln.VULN_PII_HTTP_HEADER_DETECTION)
                    if (location_in_headers):
                        self.log(logging.ERROR,
                            "NP: Location found in request headers " + \
                            "(longitude, latitude) - ['%s', '%s']" \
                            % (longitude, latitude))
                        self.log_event(
                            logging.ERROR,
                            connection.AttackEvent(
                                self.connection, self.name, True, url))
                        self.connection.vuln_notify(
                            util.vuln.VULN_PII_HTTP_HEADER_DETECTION)
            except Exception as e:
                self.log(logging.ERROR, str(e))
