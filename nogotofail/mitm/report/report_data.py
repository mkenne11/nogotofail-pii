r'''
Copyright 2016 Google Inc. All rights reserved.

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

""" Classes create data reports based on nogotofail application and event
    logs.
"""

import abc
import json
import re
from nogotofail.mitm.util.pii import CAVEAT_PII_QRY_STRING, CAVEAT_PII_HEADER
from nogotofail.mitm.util.pii import CAVEAT_PII_MSG_BODY

CAVEAT_PII = "PII-"


class DataReport(object):
    """ Base class for data reports
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, application_log_info, event_log_info):
        self._application_log_info = application_log_info
        self._event_log_info = event_log_info

    @abc.abstractmethod
    def _parse_logs(self):
        """ Private method processes application and event log objects to
            produce the data report """

    def _scrub_dict(self, d):
        """" Function recursively removes empty elements from a dictionary """
        if type(d) is dict:
            return dict((k, self._scrub_dict(v)) for k, v in d.iteritems()
                        if v and self._scrub_dict(v))
        elif type(d) is list:
            return [self._scrub_dict(v) for v in d if v and self._scrub_dict(v)]
        else:
            return d

    """ Classes used for JSON pretty printing
    """
    class NoIndent(object):

        def __init__(self, value):
            self.value = value

        def __repr__(self):
            if not isinstance(self.value, (list, tuple)):
                return repr(self.value)
            else:  # assume it's a list or tuple of coordinates stored as dicts
                delimiters = '[]' if isinstance(self.value, list) else '()'
                pairs = ('{!r}:{}'.format(*component)
                             for coordinate in self.value
                                 for component in sorted(coordinate.items()))
                pairs = ('{{{}, {}}}'.format(*pair)
                             for pair in zip(*[iter(pairs)]*2))
                return delimiters[0] + ', '.join(pairs) + delimiters[1]

    class MyEncoder(json.JSONEncoder):

        def default(self, obj):
            return(repr(obj) if isinstance(obj, self.NoIndent) else
                   json.JSONEncoder.default(self, obj))

    """ Public properties
    """
    @property
    def json_report(self):
        """ Property returns application events reporting data dictionary """
        # return json.dumps(self._report_data)
        return json.dumps(self._report_data, cls=self.MyEncoder, indent=2)


class MessageReport(DataReport):
    """ Class creates a collection of application messages based on
        application and event log information.
    """

    def __init__(self, application_log_info, event_log_info):
        super(MessageReport, self) \
            .__init__(application_log_info, event_log_info)
        # Populate class dictionary.
        self._report_data = self._parse_logs()

    """ Private methods for creating the application_messages report structure.
    """
    def _parse_logs(self):
        """ Private method processes ProcessApplicationLog object to create an
            intermediate dictionary that can further processes into a JSON
            report format.
        """
        app_message_dict = {}
        app_log_info = self._application_log_info.log_dict
        event_log_info = self._event_log_info.log_dict

        #print "*** self._event_log_info: %s" % json.dumps(event_log_info)
        for key, log_item in app_log_info.iteritems():
            """ Fetch application entry fields from application and event log
                object """
            # print "*** App item message: " + str(log_item)
            # Fetch message dictionary from application log if it exists
            message = log_item.get("message", {})
            # Fetch client dictionary from application log if it exists
            try:
                client = log_item["client"]
                app_name = client["client_application"]
            except KeyError:
                client = {}
                app_name = ""
            # Fetch connection dictionary from application log if it exists
            try:
                connection = log_item["connection"]
                connection_id = connection["connection_id"]
                handler = connection["handler"]
            except KeyError:
                connection = {}
                handler = ""
            # Fetch hostname value for connection_id from event log
            try:
                event_log_entry = event_log_info[connection_id]
                hostname = event_log_entry["hostname"].replace("www.", "")
            except KeyError:
                hostname = ""

            app_entry = {}
            connection_list = []
            connection_entry = {}
            message_list = []
            app_entry_exists = False
            # If an app entry doesn't exist create an application entry dictionary \
            # and sub-entries.
            if (app_name and app_name != "unknown"):
                #print "*** App_name exists - %s" % app_name
                """ Check if an entry already exists in the application event
                    dictionary for current app """
                try:
                    app_entry = app_message_dict[app_name]
                    app_entry_exists = True
                    # If a connection list doesn't exist create one.
                except KeyError:
                    #app_entry_exists = False
                    pass
                """ Create new app message entry """
                #print "*** message log dictionary - %s" % message
                #print "*** connection log dictionary - %s" % connection
                message_entry = self._create_message_entry(message, connection)
                # An entry for app already exists in the application event dictionary
                if (app_entry):
                    # If a connection list exists
                    try:
                        connection_list = app_message_dict[app_name]["connections"]
                        # Find connection entry for current hostname exists.
                        for _conn_entry in connection_list:
                            # A connection entry for hostname exists
                            if (_conn_entry["hostname"] == hostname):
                                # Fetch connection entry and message list references
                                connection_entry = _conn_entry
                                # Is it possible for the messages_list to not exist?
                                message_list = connection_entry["messages"]
                                # Append message entry & to message list
                                message_list.append(message_entry)
                                break
                        # Where a connection entry for hostname doesn't exist
                        if not connection_entry:
                            # Create message list & and add message entry
                            message_list = []
                            message_list.append(message_entry)
                            # Create connection entry
                            connection_entry =  \
                                self._create_connection_entry(hostname, message_list)
                            # Append connection entry to connection list
                            connection_list.append(connection_entry)
                    # If a connection list yep doesn't exist for the app_entry
                    except KeyError:
                        # Create message list and append message entry
                        message_list = []
                        message_list.append(message_entry)
                        # Create connection entry
                        connection_entry =  \
                            self._create_connection_entry(hostname, message_list)
                        # Create connection list and append connection entry
                        connection_list = []
                        connection_list.append(connection_entry)
                # An entry for app doesn't yet exist in the application event dictionary
                else:
                    # print "*** Add new app entry: app_name - %s" % app_name
                    # Create message list & and add message entry
                    message_list = []
                    message_list.append(message_entry)
                    # Create connection entry
                    connection_entry =  \
                        self._create_connection_entry(hostname, message_list)
                    # Create connection list and append connection entry
                    connection_list = []
                    connection_list.append(connection_entry)
                    # Create app_entry and add connection_list
                    app_entry = {"app_name": app_name,
                                 "app_version": client["client_version"],
                                 "app_type": client["client_type"],
                                 "connections": connection_list
                                }
                    app_message_dict[app_name] = app_entry
                    #print "*** app_entry dict: " + str(app_entry)
        app_message_dict = self._scrub_dict(app_message_dict)
        return app_message_dict

    def _create_message_entry(self, message, connection):
        """ Construct message_entry dictionary.
        """
        # Fetch message values_found attribute if it exists.
        pii_items_found = message.get("values_found", "")
        pii_items_list = []
        if pii_items_found:
            pii_items_list = (pii_items_found.replace("[", "")).replace("]", "") \
                .split(",")
        message_entry = {"message_type": message["type"],
                         "connection_id": connection["connection_id"],
                         "date": message["date"],
                         "time": message["time"],
                         "message": message["text"],
                         "pii_items_found": pii_items_list,
                         "handler": connection["handler"]
                        }
        return message_entry

    def _create_connection_entry(self, hostname, message_list):
        """ Construct connection_entry dictionary.
        """
        connection_entry = {}
        connection_entry["hostname"] = hostname
        if (message_list):
            connection_entry["messages"] = message_list
        return connection_entry


class EventReport(DataReport):
    """ Class creates a collection of application events based on
        application and event log information.
    """

    def __init__(self, application_log_info, event_log_info):
        super(EventReport, self) \
            .__init__(application_log_info, event_log_info)
        self._application_messages = {}
        # Populate class dictionary.
        self._report_data = self._parse_logs()

    def _parse_logs(self):
        """ Private method processes ProcessApplicationLog object to create an
            intermediate dictionary that can further processes into a JSON
            report format.
        """
        app_events_dict = {}
        app_log_info = self._application_log_info.log_dict
        event_log_info = self._event_log_info.log_dict
        IGNORE_EVENT_TYPE = ["DEBUG", "INFO"]

        for key, log_item in app_log_info.iteritems():
            """ Fetch application entry fields from application and event log
                object """
            # print "*** Alerts: App item message: " + str(log_item)
            # Fetch message dictionary from application log if it exists
            message = log_item.get("message", {})
            event_type = message.get("type", "")
            # Fetch client dictionary from application log if it exists
            try:
                client = log_item["client"]
                app_name = client["client_application"]
            except KeyError:
                client = {}
                app_name = ""
            # Fetch connection dictionary from application log if it exists
            try:
                connection = log_item["connection"]
                connection_id = connection["connection_id"]
                handler = connection["handler"]
            except KeyError:
                connection = {}
                handler = ""
            """ Fetch hostname value & domain for connection_id from event log """
            try:
                event_log_entry = event_log_info[connection_id]
                hostname = event_log_entry["hostname"].replace("www.", "")
                domain = event_log_entry.get("domain", "")
            except KeyError:
                hostname = ""
                domain = ""
            app_entry = {}
            app_events_list = []
            app_event_entry = {}
            events_list = []
            app_entry_exists = False
            """ If an app entry doesn't exist create an application entry dictionary \
                and sub-entries """
            if (app_name and app_name != "unknown" and
                    event_type not in IGNORE_EVENT_TYPE):
                # print "*** App_name exists - %s" % app_name
                """ Check if an entry already exists in the application event dictionary
                    for current app """
                try:
                    app_entry = app_events_dict[app_name]
                    app_entry_exists = True
                    # If a connection list doesn't exist create one.
                except KeyError:
                    pass
                # Create a new event_entry
                event_entry = self._create_event_entry(message, connection,
                                                       domain)
                """ An entry for app already exists in the application event
                    dictionary """
                if (app_entry):
                    app_events_list = app_events_dict[app_name]["app_events"]
                    # Find app_event_entry entry for current event_type exists.
                    for _app_event_entry in app_events_dict[app_name] \
                            ["app_events"]:
                        # A app_event_entry for event_type exists
                        if (_app_event_entry["event_type"] == event_type):
                            # Fetch connection entry and events_list references
                            app_event_entry = _app_event_entry
                            # Is it possible for the events_list to not exist?
                            events_list = app_event_entry["events"]
                            # Append event_entry to events_list
                            events_list.append(event_entry)
                            break
                    # Where a app_event_entry entry for event_type doesn't exist
                    if not app_event_entry:
                        # print "For app_name '%s' dict entry doesn't yet exist for %s. Adding new event_type entry" % (app_name, event_type)
                        # Create events_list & and add event_entry entry
                        events_list = []
                        events_list.append(event_entry)
                        # Create connection entry
                        event_type_entry =  \
                            self._create_event_type_entry(event_type, events_list)
                        # Append connection entry to app_events_list
                        app_events_list.append(event_type_entry)
                # An entry for app doesn't yet exist in the application event
                # dictionary
                else:
                    # print "*** Add new app entry: app_name - %s" % app_name
                    # Create events_list & and add event_entry
                    events_list = []
                    events_list.append(event_entry)
                    # Create event_type_entry
                    event_type_entry =  \
                        self._create_event_type_entry(event_type, events_list)
                    # Create app_events_list and append event_type_entry entry
                    app_events_list = []
                    app_events_list.append(event_type_entry)
                    # Create app_entry and add app_events_list
                    app_entry = {"app_name": app_name,
                                 "app_version": client["client_version"],
                                 "app_type": client["client_type"],
                                 "app_events": app_events_list
                                }
                    app_events_dict[app_name] = app_entry
                    #print "*** app_entry dict: " + str(app_entry)
        app_events_dict = self._scrub_dict(app_events_dict)
        return app_events_dict

    def _create_event_type_entry(self, event_type, events_list):
        """ Returns an event_type_entry dictionary
        """
        event_type_entry = {"event_type": event_type,
                            "events": events_list
                           }
        return event_type_entry

    def _create_event_entry(self, message, connection, domain):
        """ Returns an event_entry dictionary
        """
        # Fetch message pii_items_found if it exists and convert to list.
        pii_items_found = message.get("values_found", "")
        pii_items_list = []
        if pii_items_found:
            pii_items_list = (pii_items_found.replace("[", "")).replace("]", "") \
                .split(",")
        event_entry = {#"event_type": message["type"],
                       "connection_id": connection["connection_id"],
                       "date": message["date"],
                       "time": message["time"],
                       "message": message["text"],
                       "pii_items_found": pii_items_list,
                       "handler": connection["handler"],
                       "domain": domain
                      }
        return event_entry


class EventSummaryReport(DataReport):
    """ Class creates a summary report of application events based on
        application and event log information.
    """

    def __init__(self, application_log_info, event_log_info):
        super(EventSummaryReport, self) \
            .__init__(application_log_info, event_log_info)
        self._application_messages = {}
        # Populate class dictionary.
        self._report_data = self._parse_logs()

    def _parse_logs(self):
        """ Private method processes ProcessApplicationLog object to create an
            intermediate dictionary that can further processes into a JSON
            report format.
        """
        app_events_dict = {}
        app_log_info = self._application_log_info.log_dict
        event_log_info = self._event_log_info.log_dict
        IGNORE_EVENT_TYPE = ["DEBUG", "INFO"]

        for key, log_item in app_log_info.iteritems():
            """ Fetch application entry fields from application and event log
                object """
            # print "*** Alerts: App item message: " + str(log_item)
            message = log_item.get("message", {})
            message_text = message.get("text", "")
            event_type = message.get("type", "")
            # Fetch client dictionary from application log
            try:
                client = log_item["client"]
                app_name = client["client_application"]
            except KeyError:
                client = {}
                app_name = ""
            try:
                connection = log_item["connection"]
                connection_id = connection["connection_id"]
                handler = connection["handler"]
            except KeyError:
                connection = {}
                handler = ""
            try:
                event_log_entry = event_log_info[connection_id]
                hostname = event_log_entry["hostname"].replace("www.", "")
                domain = event_log_entry.get("domain", "")
            except KeyError:
                hostname = ""
                domain = ""
            app_entry = {}
            app_events_list = []
            app_event_entry = {}
            events_list = []
            app_entry_exists = False
            """ If an app entry doesn't exist create an application entry
                dictionary and sub-entries. """
            if (app_name and app_name != "unknown" and
                    event_type not in IGNORE_EVENT_TYPE):
                """ Check if an entry already exists in the application event
                    dictionary for current app """
                try:
                    app_entry = app_events_dict[app_name]
                    # If a connection list doesn't exist create one.
                except KeyError:
                    pass
                # Create a new event_entry
                event_entry = self._create_event_entry(message, connection,
                                                       domain)
                # An entry for app already exists in the application event dictionary
                if (app_entry):
                    app_events_list = app_events_dict[app_name]["app_events"]
                    # Find app_event_entry entry for current event_type exists.
                    for _app_event_entry in app_events_dict[app_name] \
                            ["app_events"]:
                        # A app_event_entry for event_type exists
                        if (_app_event_entry["event_type"] == event_type):
                            # Fetch connection entry and events_list references
                            app_event_entry = _app_event_entry
                            # Is it possible for the events_list to not exist?
                            events_list = app_event_entry["events"]
                            # Append event_entry to events_list
                            break
                    if app_event_entry:
                        found_event_entry = {}
                        for _event_entry in events_list:
                            # If event_entry not in events_list append it
                            if _event_entry["domain"] == domain and \
                               _event_entry["handler"] == handler and \
                               _event_entry["message"] == message_text:
                                found_event_entry = _event_entry
                                break
                        if not found_event_entry:
                            events_list.append(event_entry)
                    # Where an app_event_entry entry for event_type doesn't exist
                    else:
                        # print "For app_name '%s' dict entry doesn't yet exist for %s. Adding new event_type entry" % (app_name, event_type)
                        # Create events_list & and add event_entry entry
                        events_list = []
                        events_list.append(event_entry)
                        # Create connection entry
                        event_type_entry =  \
                            self._create_event_type_entry(event_type, events_list)
                        # Append connection entry to app_events_list
                        app_events_list.append(event_type_entry)
                    # If an app_events_list doesn't exist for the app_entry
                else:
                    """ An entry for app doesn't yet exist in the application event
                        dictionary """
                    # print "*** Add new app entry: app_name - %s" % app_name
                    # Create events_list & and add event_entry
                    events_list = []
                    events_list.append(event_entry)
                    event_type_entry =  \
                        self._create_event_type_entry(event_type, events_list)
                    # Create app_events_list and append event_type_entry entry
                    app_events_list = []
                    app_events_list.append(event_type_entry)
                    # Create app_entry and add app_events_list
                    app_entry = {"app_name": app_name,
                                 "app_version": client["client_version"],
                                 "app_type": client["client_type"],
                                 "app_events": app_events_list
                                }
                    app_events_dict[app_name] = app_entry
                    #print "*** app_entry dict: " + str(app_entry)
        app_events_dict = self._scrub_dict(app_events_dict)
        return app_events_dict

    def _create_event_type_entry(self, event_type, events_list):
        """ Returns an event_type_entry dictionary
        """
        event_type_entry = {"event_type": event_type,
                            "events": events_list
                           }
        return event_type_entry

    def _create_event_entry(self, message, connection, domain):
        """ Returns an event_entry dictionary
        """
        # Fetch message pii_items_found if it exists and convert to list.
        pii_items_found = message.get("values_found", "")
        pii_items_list = []
        if pii_items_found:
            pii_items_list = (pii_items_found.replace("[", "")).replace("]", "") \
                .split(",")
        event_entry = {#"event_type": message["type"]
                       "message": message["text"],
                       "pii_items_found": pii_items_list,
                       "handler": connection["handler"],
                       "domain": domain
                      }
        return event_entry


class PIIDataReport(DataReport):
    """ Class creates a collection of application data items based on
        application and event log information.
    """
    HTTP_PII_HANDLER = "httppii"
    HTTPS_PII_HANDLER = "httpspii"
    PII_IDENTIFIERS_MESSAGE = ": Personal IDs"
    PII_DETAILS_MESSAGE = ": Personal details"
    PII_LOCATION_MESSAGE = ": Location"

    def __init__(self, application_log_info, event_log_info):
        super(PIIDataReport, self) \
            .__init__(application_log_info, event_log_info)
        self._application_messages = {}
        self._application_events = {}
        self._application_pii_data = {}
        # Populate class dictionary.
        self._report_data = self._parse_logs()

    def _parse_logs(self):
        """ Private method processes log dictionaries to create an
            intermediate dictionary that can further processes into a JSON
            report format.
        """
        app_pii_dict = {}
        app_log_info = self._application_log_info.log_dict
        event_log_info = self._event_log_info.log_dict
        IGNORE_EVENT_TYPE = ["DEBUG"]

        for key, log_item in app_log_info.iteritems():
            # Fetch application entry fields from application and event log
            # object
            # print "*** Alerts: App item message: " + str(log_item)
            # Fetch message dictionary from application log if it exists
            message = log_item.get("message", {})
            # Fetch message text event_type value from message object
            message_text = message.get("text", "")
            event_type = message.get("type", "")
            # Fetch client dictionary from application log if it exists
            client = log_item.get("client", {})
            app_name = client.get("client_application", "")
            app_version = client.get("client_version", "")
            app_type = client.get("client_type", "")
            # Fetch connection dictionary from application log if it exists
            connection = log_item.get("connection", {})
            connection_id = connection.get("connection_id", "")
            handler = connection.get("handler", "").strip()
            # Fetch hostname value for connection_id from event log
            event_log_entry = event_log_info.get(connection_id, {})
            hostname = event_log_entry.get("hostname", "")
            # print "!!! event_log_entry - " + str(event_log_entry)
            # Determine connection domain based on hostname & URL path
            domain = event_log_entry.get("domain", hostname)

            values_found = message.get("values_found", "")
            pii_found_list = []
            if (values_found):
                if (self.PII_LOCATION_MESSAGE in message_text):
                    pii_information_found = "[location]"
                else:
                    pii_information_found = values_found
                pii_found_list = []
                pii_found_list = str(str(str(pii_information_found.replace("[", ""))
                                     .replace("]", "")).replace(" ", "")).split(",")
            # If app_name entry is of interest and is for an unencrypted pii
            # handler
            if ( app_name and app_name != "unknown" and
                 event_type not in IGNORE_EVENT_TYPE and
                 ( self.HTTP_PII_HANDLER in handler or
                   self.HTTPS_PII_HANDLER in handler ) and
                   CAVEAT_PII in message_text ):
                # If app_item with app_name exists in app_pii_dict
                try:
                    app_item = app_pii_dict[app_name]
                    # Fetch app_domain object from app_domains list
                    app_domain_list = app_item["app_domains"]
                    app_domain = {}
                    for _app_domain in app_domain_list:
                        if (_app_domain["domain"] == domain):
                            app_domain = _app_domain
                            break
                    # If app_domain dictionary exists fetch element dictionaries
                    if app_domain:
                        unencrypted_elements = app_domain["unencrypted_elements"]
                        encrypted_elements = app_domain["encrypted_elements"]
                    # if not app_domain:
                    else:
                        unencrypted_elements = self._create_domain_elements()
                        encrypted_elements = self._create_domain_elements()
                    if self.HTTP_PII_HANDLER in handler:
                        item_elements = unencrypted_elements
                    elif self.HTTPS_PII_HANDLER in handler:
                        item_elements = encrypted_elements
                    # If pii were found add the pii items to the encrypted/
                    # unencrypted items for the current app/domain.
                    if (pii_found_list):
                        # If unencrypted_element exists fetch it
                        if (CAVEAT_PII_QRY_STRING in message_text):
                            item_elements["pii_query_string"] = \
                                list(set(item_elements["pii_query_string"]
                                + pii_found_list))
                        elif (CAVEAT_PII_HEADER in message_text):
                            item_elements["pii_http_header"] = \
                                list(set(item_elements["pii_http_header"]
                                + pii_found_list))
                        elif (CAVEAT_PII_MSG_BODY in message_text):
                            item_elements["pii_http_body"] = \
                                list(set(item_elements["pii_http_body"]
                                + pii_found_list))
                    # If app_domain doesn't exist create it and append to
                    # app_domains list
                    if not app_domain:
                        # Fetch list of query_strings by app_name and hostname
                        query_string_count = \
                            self._get_domain_querystring_count(app_name,
                                                               hostname)
                        key_value_count = \
                            self._get_domain_querystring_item_count \
                                                        (query_string_count)
                        app_domain = self._create_app_domain(domain,
                                unencrypted_elements, encrypted_elements, \
                                query_string_count, key_value_count)
                        app_domain_list.append(app_domain)
                except KeyError:
                    # If app_item does not exist in app_pii_dict create it
                    unencrypted_elements = self._create_domain_elements()
                    encrypted_elements = self._create_domain_elements()
                    if self.HTTP_PII_HANDLER in handler:
                        item_elements = unencrypted_elements
                    elif self.HTTPS_PII_HANDLER in handler:
                        item_elements = encrypted_elements
                    # If pii were found add the pii items to the encrypted/
                    # unencrypted items for the current app/domain.
                    if (CAVEAT_PII_QRY_STRING in message_text):
                        item_elements["pii_query_string"] = pii_found_list
                    elif (CAVEAT_PII_HEADER in message_text):
                        item_elements["pii_http_header"] = pii_found_list
                    elif (CAVEAT_PII_MSG_BODY in message_text):
                        item_elements["pii_http_body"] = pii_found_list
                    query_string_count = {}
                    key_value_count = {}
                    # Fetch list of query_strings by app_name and hostname
                    query_string_count = \
                        self._get_domain_querystring_count(app_name, hostname)
                    key_value_count = \
                        self._get_domain_querystring_item_count(query_string_count)
                    # Create app_domain dictionary and append to new
                    # app_domains list
                    app_domain = self._create_app_domain(domain,
                                    unencrypted_elements, encrypted_elements,
                                    query_string_count, key_value_count)
                    app_domain_list = []
                    app_domain_list.append(app_domain)
                    app_item = self._create_app_item(app_name, app_version,
                                                     app_type, app_domain_list)
                    if (domain):
                        app_pii_dict[app_name] = app_item
        app_pii_dict = self._scrub_dict(app_pii_dict)
        return app_pii_dict

    def _create_app_item(self, app_name, app_version, app_type, app_domains):
        """
        """
        app_item = {"app_name": app_name,
                    "app_version": app_version,
                    "app_type": app_type,
                    "app_domains": app_domains
                   }
        return app_item

    def _create_app_domain(self, domain, unencrypted_elements,
                           encrypted_elements, query_string_count,
                           key_value_count):
        """
        """
        app_domain = {"domain": domain,
                      "unencrypted_elements": unencrypted_elements,
                      "encrypted_elements": encrypted_elements,
                      "unencrypted_query_strings": {
                          # "count": query_string_count,
                          "key_value_count": key_value_count
                         }
                     }
        return app_domain

    def _create_domain_elements(self):
        """
        """
        domain_elements = {"pii_query_string": [],
                           "pii_http_header": [],
                           "pii_http_body": []
                          }
        return domain_elements

    def _create_element_item(self, domain, pii_found_list):
        """ Returns a element_item dictionary
        """
        element_item = {"domain": domain,
                        "pii": pii_found_list
                       }
        return element_item

    def _get_domain_querystring_item_count(self, query_strings):
        """ Returns a list of query string parameter/value pairs in
            unencrypted requets and a count
        """
        item_count = {}
        """ For the unique query string found add each param/value pair and
            count to the item_count dictionary """
        for qs_key, qs_value in query_strings.iteritems():
            # print "!!! qs item - " + str(qs)
            qs_key_values = qs_key.split("&")
            qs_count = int(qs_value)
            for key_value in qs_key_values:
                # If qs key value exists in qs parameter list increment count
                try:
                    item_value = int(item_count[key_value])
                    item_count[key_value] = str(item_value + qs_count)
                except KeyError:
                    item_count[key_value] = str(qs_count)
        """ Create a list of (key,value) tuples of duplicate items"""
        item_count_tuples = \
            {k: v for k, v in item_count.iteritems() if int(v) > 1}
        return item_count_tuples

    def _get_domain_querystring_count(self, app_name, hostname):
        """ Returns a list of all the query-strings for
            a given application and domain from the event log dictionary
        """
        query_string_dict = {}
        event_log_dict = self._event_log_info.log_dict
        connection_items = [log_item for key, log_item in event_log_dict.iteritems()
                            if log_item["hostname"] == hostname and
                            log_item["application"]["name"] == app_name]
        for connection_item in connection_items:
            for attack in connection_item["attacks"]:
                query_string = ""
                if (attack["data"]):
                    path_items = attack["data"].split("?")
                    try:
                        query_string = path_items[1]
                        # print "### found qs in count - " + query_string
                    except IndexError:
                        pass
                if (query_string):
                    """ If query_string already in query_string_dict increment count """
                    try:
                        # print "query_string_count: hostname - " + hostname + \
                        #     "; count - " + query_string_dict[query_string]
                        count = int(query_string_dict[query_string])
                        query_string_dict[query_string] = str(count + 1)
                    # Else create new query_string count element in query_string_dict
                    except KeyError:
                        query_string_dict[query_string] = "1"
        # print "### query string count: app_name - " + app_name + "; hostname - " + \
        #      hostname + "; dict - " + str(query_string_dict)
        """ Remove dictionary items which arent duplicated """
        query_string_dict = \
            {k: v for k, v in query_string_dict.iteritems() if int(v) > 1}
        return query_string_dict

    def _get_domain_name(self, hostname, path):
        """ Returns the domain for the current event log message item
            Note. Sometimes requests have no hostname so the domain needs to
            be determine from the URL path
        """
        domain_name = ""
        if (hostname.strip() is not ""):
            domain_name = hostname.replace("www.", "")
        else:
            #print "!!! path extract domain - " + path
            try:
                domain_name = re.search('^([\w\.\?\-\=\&\@\%]+)\/', path) \
                    .group(1).strip()
            except AttributeError:
                domain_name = ""
        return domain_name
