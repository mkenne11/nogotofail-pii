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

""" Classes create data reports based on nogotofail application and event
    logs.
"""
import abc
import json
import re


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
        """ Property returns application alerts reporting data dictionary """
        # return json.dumps(self._report_data)
        return json.dumps(self._report_data, cls=self.MyEncoder, indent=2)


class ApplicationMessageReport(DataReport):
    """ Class creates a collection of application messages based on
        application and event log information.
    """
    def __init__(self, application_log_info, event_log_info):
        super(ApplicationMessageReport, self) \
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
                # Check if an entry already exists in the application alert dictionary
                # for current app
                try:
                    app_entry = app_message_dict[app_name]
                    app_entry_exists = True
                    # If a connection list doesn't exist create one.
                except KeyError:
                    #app_entry_exists = False
                    pass
                # Create new app message entry
                #print "*** message log dictionary - %s" % message
                #print "*** connection log dictionary - %s" % connection
                message_entry = self._create_message_entry(message, connection)
                # An entry for app already exists in the application alert dictionary
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
                # An entry for app doesn't yet exist in the application alert dictionary
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


class ApplicationAlertReport(DataReport):
    """ Class creates a collection of application alerts based on
        application and event log information.
    """

    def __init__(self, application_log_info, event_log_info):
        super(ApplicationAlertReport, self) \
            .__init__(application_log_info, event_log_info)
        self._application_messages = {}
        # Populate class dictionary.
        self._report_data = self._parse_logs()

    def _parse_logs(self):
        """ Private method processes ProcessApplicationLog object to create an
            intermediate dictionary that can further processes into a JSON
            report format.
        """
        app_alerts_dict = {}
        app_log_info = self._application_log_info.log_dict
        event_log_info = self._event_log_info.log_dict
        IGNORE_ALERT_TYPE = ["DEBUG", "INFO"]

        for key, log_item in app_log_info.iteritems():
            """ Fetch application entry fields from application and event log
                object """
            # print "*** Alerts: App item message: " + str(log_item)
            # Fetch message dictionary from application log if it exists
            message = log_item.get("message", {})
            alert_type = message.get("type", "")
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
            app_alerts_list = []
            app_alert_entry = {}
            alerts_list = []
            app_entry_exists = False
            """ If an app entry doesn't exist create an application entry dictionary \
                and sub-entries """
            if (app_name and app_name != "unknown" and
                    alert_type not in IGNORE_ALERT_TYPE):
                # print "*** App_name exists - %s" % app_name
                """ Check if an entry already exists in the application alert dictionary
                    for current app """
                try:
                    app_entry = app_alerts_dict[app_name]
                    app_entry_exists = True
                    # If a connection list doesn't exist create one.
                except KeyError:
                    #app_entry_exists = False
                    pass
                # Create a new alert_entry
                alert_entry = self._create_alert_entry(message, connection,
                                                       domain)
                # An entry for app already exists in the application alert dictionary
                if (app_entry):
                    app_alerts_list = app_alerts_dict[app_name]["app_alerts"]
                    # Find app_alert_entry entry for current alert_type exists.
                    for _app_alert_entry in app_alerts_dict[app_name] \
                            ["app_alerts"]:
                        # A app_alert_entry for alert_type exists
                        if (_app_alert_entry["alert_type"] == alert_type):
                            # Fetch connection entry and alerts_list references
                            app_alert_entry = _app_alert_entry
                            # Is it possible for the alerts_list to not exist?
                            alerts_list = app_alert_entry["alerts"]
                            # Append alert_entry to alerts_list
                            alerts_list.append(alert_entry)
                            break
                    # Where a app_alert_entry entry for alert_type doesn't exist
                    if not app_alert_entry:
                        # print "For app_name '%s' dict entry doesn't yet exist for %s. Adding new alert_type entry" % (app_name, alert_type)
                        # Create alerts_list & and add alert_entry entry
                        alerts_list = []
                        alerts_list.append(alert_entry)
                        # Create connection entry
                        alert_type_entry =  \
                            self._create_alert_type_entry(alert_type, alerts_list)
                        # Append connection entry to app_alerts_list
                        app_alerts_list.append(alert_type_entry)
                # An entry for app doesn't yet exist in the application alert
                # dictionary
                else:
                    # print "*** Add new app entry: app_name - %s" % app_name
                    # Create alerts_list & and add alert_entry
                    alerts_list = []
                    alerts_list.append(alert_entry)
                    # Create alert_type_entry
                    alert_type_entry =  \
                        self._create_alert_type_entry(alert_type, alerts_list)
                    # Create app_alerts_list and append alert_type_entry entry
                    app_alerts_list = []
                    app_alerts_list.append(alert_type_entry)
                    # Create app_entry and add app_alerts_list
                    app_entry = {"app_name": app_name,
                                 "app_version": client["client_version"],
                                 "app_type": client["client_type"],
                                 "app_alerts": app_alerts_list
                                }
                    app_alerts_dict[app_name] = app_entry
                    #print "*** app_entry dict: " + str(app_entry)
        return app_alerts_dict

    def _create_alert_type_entry(self, alert_type, alerts_list):
        """ Returns an alert_type_entry dictionary
        """
        alert_type_entry = {"alert_type": alert_type,
                            "alerts": alerts_list
                           }
        return alert_type_entry

    def _create_alert_entry(self, message, connection, domain):
        """ Returns an alert_entry dictionary
        """
        # Fetch message pii_items_found if it exists and convert to list.
        pii_items_found = message.get("values_found", "")
        pii_items_list = []
        if pii_items_found:
            pii_items_list = (pii_items_found.replace("[", "")).replace("]", "") \
                .split(",")
        alert_entry = {#"alert_type": message["type"],
                       "connection_id": connection["connection_id"],
                       "date": message["date"],
                       "time": message["time"],
                       "message": message["text"],
                       "pii_items_found": pii_items_list,
                       "handler": connection["handler"],
                       "domain": domain
                      }
        return alert_entry


class ApplicationAlertSummaryReport(DataReport):
    """ Class creates a summary report of application alerts based on
        application and event log information.
    """

    def __init__(self, application_log_info, event_log_info):
        super(ApplicationAlertSummaryReport, self) \
            .__init__(application_log_info, event_log_info)
        self._application_messages = {}
        # Populate class dictionary.
        self._report_data = self._parse_logs()

    def _parse_logs(self):
        """ Private method processes ProcessApplicationLog object to create an
            intermediate dictionary that can further processes into a JSON
            report format.
        """
        app_alerts_dict = {}
        app_log_info = self._application_log_info.log_dict
        event_log_info = self._event_log_info.log_dict
        IGNORE_ALERT_TYPE = ["DEBUG", "INFO"]

        for key, log_item in app_log_info.iteritems():
            """ Fetch application entry fields from application and event log
                object """
            # print "*** Alerts: App item message: " + str(log_item)
            # Fetch message dictionary from application log if it exists
            message = log_item.get("message", {})
            message_text = message.get("text", "")
            alert_type = message.get("type", "")
            # Fetch client dictionary from application log
            try:
                client = log_item["client"]
                app_name = client["client_application"]
            except KeyError:
                client = {}
                app_name = ""
            # Fetch connection dictionary from application log
            try:
                connection = log_item["connection"]
                connection_id = connection["connection_id"]
                handler = connection["handler"]
            except KeyError:
                connection = {}
                handler = ""
            # Fetch hostname value & domain for connection_id from event log
            try:
                event_log_entry = event_log_info[connection_id]
                hostname = event_log_entry["hostname"].replace("www.", "")
                domain = event_log_entry.get("domain", "")
            except KeyError:
                hostname = ""
                domain = ""
            app_entry = {}
            app_alerts_list = []
            app_alert_entry = {}
            alerts_list = []
            app_entry_exists = False
            """ If an app entry doesn't exist create an application entry dictionary \
                and sub-entries. """
            if (app_name and app_name != "unknown" and
                    alert_type not in IGNORE_ALERT_TYPE):
                # print "*** App_name exists - %s" % app_name
                """ Check if an entry already exists in the application alert dictionary
                    for current app """
                try:
                    app_entry = app_alerts_dict[app_name]
                    app_entry_exists = True
                    # If a connection list doesn't exist create one.
                except KeyError:
                    #app_entry_exists = False
                    pass
                # Create a new alert_entry
                alert_entry = self._create_alert_entry(message, connection,
                                                       domain)
                # An entry for app already exists in the application alert dictionary
                if (app_entry):
                    app_alerts_list = app_alerts_dict[app_name]["app_alerts"]
                    # Find app_alert_entry entry for current alert_type exists.
                    for _app_alert_entry in app_alerts_dict[app_name] \
                            ["app_alerts"]:
                        # A app_alert_entry for alert_type exists
                        if (_app_alert_entry["alert_type"] == alert_type):
                            # Fetch connection entry and alerts_list references
                            app_alert_entry = _app_alert_entry
                            # Is it possible for the alerts_list to not exist?
                            alerts_list = app_alert_entry["alerts"]
                            # Append alert_entry to alerts_list
                            break

                    if app_alert_entry:
                        found_alert_entry = {}
                        for _alert_entry in alerts_list:
                            # If alert_entry not in alerts_list append it
                            if _alert_entry["domain"] == domain and \
                               _alert_entry["handler"] == handler and \
                               _alert_entry["message"] == message_text:
                                found_alert_entry = _alert_entry
                                break
                        if not found_alert_entry:
                            alerts_list.append(alert_entry)
                    # Where an app_alert_entry entry for alert_type doesn't exist
                    else:
                        # print "For app_name '%s' dict entry doesn't yet exist for %s. Adding new alert_type entry" % (app_name, alert_type)
                        # Create alerts_list & and add alert_entry entry
                        alerts_list = []
                        alerts_list.append(alert_entry)
                        # Create connection entry
                        alert_type_entry =  \
                            self._create_alert_type_entry(alert_type, alerts_list)
                        # Append connection entry to app_alerts_list
                        app_alerts_list.append(alert_type_entry)
                    # If an app_alerts_list doesn't exist for the app_entry

                # An entry for app doesn't yet exist in the application alert
                # dictionary
                else:
                    # print "*** Add new app entry: app_name - %s" % app_name
                    # Create alerts_list & and add alert_entry
                    alerts_list = []
                    alerts_list.append(alert_entry)
                    # Create alert_type_entry
                    alert_type_entry =  \
                        self._create_alert_type_entry(alert_type, alerts_list)
                    # Create app_alerts_list and append alert_type_entry entry
                    app_alerts_list = []
                    app_alerts_list.append(alert_type_entry)
                    # Create app_entry and add app_alerts_list
                    app_entry = {"app_name": app_name,
                                 "app_version": client["client_version"],
                                 "app_type": client["client_type"],
                                 "app_alerts": app_alerts_list
                                }
                    app_alerts_dict[app_name] = app_entry
                    #print "*** app_entry dict: " + str(app_entry)
        return app_alerts_dict

    def _create_alert_type_entry(self, alert_type, alerts_list):
        """ Returns an alert_type_entry dictionary
        """
        alert_type_entry = {"alert_type": alert_type,
                            "alerts": alerts_list
                           }
        return alert_type_entry

    def _create_alert_entry(self, message, connection, domain):
        """ Returns an alert_entry dictionary
        """
        # Fetch message pii_items_found if it exists and convert to list.
        pii_items_found = message.get("values_found", "")
        pii_items_list = []
        if pii_items_found:
            pii_items_list = (pii_items_found.replace("[", "")).replace("]", "") \
                .split(",")
        alert_entry = {#"alert_type": message["type"]
                       "message": message["text"],
                       "pii_items_found": pii_items_list,
                       "handler": connection["handler"],
                       "domain": domain
                      }
        return alert_entry


class ApplicationDataReport(DataReport):
    """ Class creates a collection of application data items based on
        application and event log information.
    """
    CLEARTEXT_PII_HANDLER = "cleartextpii"
    QUERY_STRING_HANDLER = "querystring"
    HTTP_HEADER_HANDLER = "httpheader"
    HTTP_BODY_HANDLER = "httpbody"
    PII_IDENTIFIERS_MESSAGE = "PII: Personal IDs"
    PII_DETAILS_MESSAGE = "PII: Personal details"
    PII_LOCATION_MESSAGE = "PII: Location"

    def __init__(self, application_log_info, event_log_info):
        super(ApplicationDataReport, self) \
            .__init__(application_log_info, event_log_info)
        self._application_messages = {}
        self._application_alerts = {}
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
        # IGNORE_ALERT_TYPE = ["DEBUG", "INFO"]
        IGNORE_ALERT_TYPE = ["DEBUG"]

        for key, log_item in app_log_info.iteritems():
            """ Fetch application entry fields from application and event log
                object """
            # print "*** Alerts: App item message: " + str(log_item)
            # Fetch message dictionary from application log if it exists
            message = log_item.get("message", {})
            # Fetch message text alert_type value from message object
            message_text = message.get("text", "")
            alert_type = message.get("type", "")
            # Fetch client dictionary from application log if it exists
            client = log_item.get("client", {})
            app_name = client.get("client_application", "")
            app_version = client.get("client_version", "")
            app_type = client.get("client_type", "")
            # Fetch connection dictionary from application log if it exists
            connection = log_item.get("connection", {})
            connection_id = connection.get("connection_id", "")
            handler = connection.get("handler", "")
            # Fetch hostname value for connection_id from event log
            event_log_entry = event_log_info.get(connection_id, {})
            hostname = event_log_entry.get("hostname", "")
            # print "!!! event_log_entry - " + str(event_log_entry)
            # Determine connection domain based on hostname & URL path
            domain = event_log_entry.get("domain", "")

            values_found = message.get("values_found", "")
            if (self.PII_LOCATION_MESSAGE in message_text):
                pii_information_found = "[location]"
            else:
                pii_information_found = values_found
            pii_found_list  = []
            pii_found_list = str(str(pii_information_found.replace("[","")) \
                .replace("]","")).split(",")
            """ If app_name entry is of interest and is for an unencrypted pii
                handler """
            if (app_name and app_name != "unknown" and
                    alert_type not in IGNORE_ALERT_TYPE and
                    handler.startswith(self.CLEARTEXT_PII_HANDLER)):
                #TODO: Add encrypted items handler check
                """ Create report dictionary
                """
                # Create element_item dictionary
                # print "*** hostname = %s; element_item created = %s " % \
                #    (hostname, str(element_item))
                """ If app_item with app_name exists in app_pii_dict """
                app_domain_qs_list = ""
                try:
                    app_item = app_pii_dict[app_name]
                    """ Fetch app_domain object from app_domains list """
                    app_domain_list = app_item["app_domains"]
                    app_domain = {}
                    for _app_domain in app_domain_list:
                        if (_app_domain["domain"] == domain):
                            app_domain = _app_domain
                            # print ("*** (Match) app_domain hostname - ", hostname,
                            #       " found")
                            break
                    """ If app_domain dictionary exists fetch unencrypted_elements
                        dictionary """
                    if app_domain:
                        # Get unencrypted_elements from app_domain
                        unencrypted_elements = \
                            app_domain["unencrypted_elements"]
                        # print "!!! app_domain exists : app_name - " + \
                        #       app_name
                        """ Else create new unencrypted_elements dictionary """
                    else:
                        unencrypted_elements = \
                            self._create_domain_elements()
                    if (pii_found_list):
                        # If unencrypted_element exists fetch it
                        if (self.QUERY_STRING_HANDLER in handler):
                            unencrypted_elements["pii_query_string"] = \
                                list(set(unencrypted_elements["pii_query_string"] \
                                + pii_found_list))
                        elif (self.HTTP_HEADER_HANDLER in handler):
                            unencrypted_elements["pii_http_header"] = \
                                list(set(unencrypted_elements["pii_http_header"] \
                                + pii_found_list))
                        elif (self.HTTP_BODY_HANDLER in handler):
                            unencrypted_elements["pii_http_body"] = \
                                list(set(unencrypted_elements["pii_http_body"] \
                                + pii_found_list))
                    """ If app_domain doesn't exist create it and append to
                        app_domains list """
                    if not app_domain:
                        # Fetch list of query_strings by app_name and hostname
                        query_string_count = \
                            self._get_domain_querystring_count \
                                    (app_name, hostname)
                        key_value_count = \
                            self._get_domain_query_string_item_count(query_string_count)
                        app_domain = self._create_app_domain(domain,
                                unencrypted_elements, encrypted_elements, \
                                query_string_count, key_value_count)
                        app_domain_list.append(app_domain)
                except KeyError:
                    """ If app_item does not exist in app_pii_dict create it """
                    # Create unencrypted_elements dictionary
                    unencrypted_elements = self._create_domain_elements()
                    encrypted_elements = self._create_domain_elements()
                    # If handler is for PII in unencrypted traffic
                    if (self.QUERY_STRING_HANDLER in handler):
                        unencrypted_elements["pii_query_string"] = \
                            pii_found_list
                    elif (self.HTTP_HEADER_HANDLER in handler):
                        unencrypted_elements["pii_http_header"] = \
                            pii_found_list
                    elif (self.HTTP_BODY_HANDLER in handler):
                        unencrypted_elements["pii_http_body"] = \
                            pii_found_list
                    # Fetch list of query_strings by app_name and hostname
                    query_string_count = \
                        self._get_domain_querystring_count(app_name, hostname)
                    key_value_count = \
                        self._get_domain_query_string_item_count(query_string_count)

                    """ Create app_domain dictionary and append to new
                        app_domains list """
                    app_domain = self._create_app_domain(domain,
                            unencrypted_elements, encrypted_elements,
                            query_string_count, key_value_count)
                    app_domain_list = []
                    app_domain_list.append(app_domain)
                    app_item = self._create_app_item(app_name, app_version,
                                                     app_type, app_domain_list)
                    if (domain):
                        app_pii_dict[app_name] = app_item
                    else:
                        print "No domain for app_name - " + app_name
        app_pii_dict =  self._scrub_dict(app_pii_dict)
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
                      "query_strings": {
                          "count": query_string_count,
                          "key_value_count": key_value_count
                         }
                     }
        return app_domain

    def _create_domain_elements(self):
        """
        """
        domain_elements = {"pii_query_string": [],
                           "pii_http_header": [],
                           "pii_http_body": [],
                           "query_string_count": {}
                          }
        return domain_elements

    def _create_element_item(self, domain, pii_found_list):
        """ Returns a element_item dictionary
        """
        element_item = {"domain": domain,
                        "pii": pii_found_list
                       }
        return element_item

    def _get_domain_query_string_item_count(self, query_strings):
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
                if (attack["data"]):
                    path_items = attack["data"].split("?")
                    try:
                        query_string = path_items[1]
                        # print "### found qs in count - " + query_string
                    except IndexError:
                        query_string = ""
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
