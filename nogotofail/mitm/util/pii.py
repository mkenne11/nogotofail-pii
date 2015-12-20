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

import base64
import urllib

# PII log entry caveats
CAVEAT_PII_QRY_STRING = "PII-QueryString"
CAVEAT_PII_HEADER = "PII-Header"
CAVEAT_PII_MSG_BODY = "PII-Message-Body"


class PiiDetection(object):
    """General functions that can be used to search for PII items in
       HTTP strings e.g. headers, query strings, bodies.
    """

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
    """
    @staticmethod
    def detect_pii_details(http_string, pii_details):
        # Method searches for PII details within a HTTP string
        #    i.e. query string, headers, message body
        #
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
"""


class PiiStore(object):
    """ Holds PII items supplied and methods for detecting these in
        HTTP content
    """

    # Dictionary contains specified pii items and base64 and url-encoded
    # variations of these.
    _pii_items = {}
    # Dictionary holds plain text version of pii items.
    _pii_items_plaintext = {}
    # Dictionary containing the device's location.
    _pii_location = {}

    def __init__(self, pii_items, pii_location):
        self._pii_items_plaintext = pii_items
        pii_items_plaintext = pii_items
        pii_items_base64 = {}
        pii_items_urlencoded = {}
        # Create base64 dictionary of PII items
        for id_key, id_value in pii_items_plaintext.iteritems():
            # Add a base64 version of ID to dictionary
            pii_items_base64[id_key + " (base64)"] = base64.b64encode(id_value)
        # Create url encoded dictionary of PII identifiers
        for id_key, id_value in pii_items_plaintext.iteritems():
            # Add a url encoded version of ID to dictionary if its different
            # from the plain text version
            id_value_urln = urllib.quote_plus(id_value)
            if (id_value != id_value_urln):
                pii_items_urlencoded[id_key + " (url encoded)"] = id_value_urln
        # Combine PII items and variations into a single dictionary.
        self._pii_items = {k: v for d in
            (pii_items_plaintext, pii_items_base64, pii_items_urlencoded)
            for k, v in d.iteritems()}
        # Assign device location to dictionary.
        self._pii_location["longitude"] = pii_location["longitude"]
        self._pii_location["latitude"] = pii_location["latitude"]

    @property
    def pii_items(self):
        return self._pii_items

    @property
    def pii_items_plaintext(self):
        return self._pii_items_plaintext

    @property
    def pii_location(self):
        return self._pii_location

    def detect_pii_items(self, http_string):
        """ Method searches for PII items within a HTTP string
            i.e. query string, headers, message body
        """
        pii_items_found = []
        # Search query string for pii items.
        if self._pii_items:
            pii_items_found = [k for k, v in
                self._pii_items.iteritems() if v in http_string]
        return pii_items_found

    def detect_pii_location(self, http_string):
        """ Method searches for location (longitude/latitude) within a
        HTTP string i.e. query string, headers, message body
        """
        pii_location_found = []
        if self._pii_location:
            longitude = self._pii_location["longitude"]
            latitude = self._pii_location["latitude"]
            if (longitude in http_string and latitude in http_string):
                pii_location_found.append(longitude)
                pii_location_found.append(latitude)
        return pii_location_found
