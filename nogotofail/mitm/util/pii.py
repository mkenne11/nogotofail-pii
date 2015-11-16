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


class PiiDetectionUtils(object):
    """General functions that can be used to search for PII items in
       HTTP strings e.g. headers, query strings, bodies.
    """
    
    # HTTP headers to ignore not containing PII
    IGNORE_HEADERS = ["host", "connection", "content-length", "accept",
                      "user-agent", "content-type", "accept-encoding",
                      "accept-language", "accept-charset"]
    # HTTP request and response valid "content-type" header values
    VALID_CONTENT_TYPES = ["text/html", "application/json",
                           "text/plain", "text/xml", "application/xml"]
    # PII log entry caveats
    CAVEAT_PII_QRY_STRING = "PII-QueryString"
    CAVEAT_PII_HEADER = "PII-Header"
    CAVEAT_PII_MSG_BODY = "PII-Message-Body"

    @staticmethod
    def detect_pii_ids(http_string, pii_identifiers):
        """ Method searches for PII identifiers within a HTTP string
            i.e. query string, headers, message body
        """
        # Merge plain-text, base 64 and url encoded versions of PII
        # identifiers into one dictionary.
        pii_identifiers_found = []
        personal_ids = pii_identifiers["plain-text"]
        base64_personal_ids = pii_identifiers["base64"]
        urlencoded_personal_ids = pii_identifiers["url-encoded"]

        perm_personal_ids = {}
        perm_personal_ids = {k: v for d in
                (personal_ids, base64_personal_ids, urlencoded_personal_ids)
                for k, v in d.iteritems()}
        # Search query string for personal identifier values.
        pii_identifiers_found = [k for k, v in
                            perm_personal_ids.iteritems() if v in http_string]
        return pii_identifiers_found

    @staticmethod
    def detect_pii_location(http_string, pii_location):
        """ Method searches for location (longitude/latitude) within a
        HTTP string i.e. query string, headers, message body
        """
        pii_location_found = []
        longitude = pii_location["longitude"]
        latitude = pii_location["latitude"]

        if (longitude in http_string and latitude in http_string):
            pii_location_found.append(longitude)
            pii_location_found.append(latitude)
        return pii_location_found

    @staticmethod
    def detect_pii_details(http_string, pii_details):
        """ Method searches for PII details within a HTTP string
            i.e. query string, headers, message body
        """
        # Merge plain-text, base 64 and url encoded versions of PII
        # details into one dictionary.
        pii_details_found = []
        personal_details = pii_details["plain-text"]
        base64_personal_details = pii_details["base64"]
        urlencoded_personal_details = pii_details["url-encoded"]

        perm_personal_details = {}
        perm_personal_details = {k: v for d in
            (personal_details, base64_personal_details,
                urlencoded_personal_details)
            for k, v in d.iteritems()}
        pii_details_found = [k for k, v in
                        perm_personal_details.iteritems() if v in http_string]
        return pii_details_found
