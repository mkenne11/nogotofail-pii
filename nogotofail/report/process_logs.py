"""
"""
import abc
import re

class ProcessLog(object):
    """ Base class used by log processing objects
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def _process_log(self):
        """ Private method used to process log file. """

    @abc.abstractproperty
    def log_dict(self):
        """ Property returns the application log as a dictionary.
        """

class ProcessApplicationLog(ProcessLog):
    """ Class processes the application log file (default mitm.log) to extract
        meaningful information.
    """
    def __init__(self, log_path):
        # super(, self).__init__()
        self.log_path = log_path
        self._applications = []
        self._application_log_dict = {}
        self._process_log()

    def _process_log(self):
        """ Generator method processes lines from a log file.
        """
        # Define and compile regex patterns.
        re_date_time = re.compile('([0-9]{4}-[0-9]{2}-[0-9]{2})\s([0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3})')
        re_square_brackets = re.compile('(\[([\D]+)\]) (\[([\d\.\:]+\<\=\>[\d\.\:]+[\s\w-]+)\]+\s\B)')
        re_message_type = re.compile('\[([\D]+)\][^/B]')
        re_connection_details = re.compile('\[([\d\.\:]+\<\=\>[\d\.\:]+[\s\w-]+)\][^/B]')
        re_sockets = re.compile('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5})')
        re_connection_id = re.compile('\s\w+[-]\w+[-]\w+[-]\w+[-]\w+\s')
        re_handler = re.compile('\s(\w+)$')
        re_round_backets = re.compile('[(](.+)[)]')
        re_client_details = re.compile('[(](.*?)[)]')
        re_client_type = re.compile('client=(\S+)\s')
        re_application = re.compile('application=\"(\S+)\"')
        re_version = re.compile('version=\"(\d+)\"')
        re_message_text = re.compile('[)]\s(.+)$')
        re_short_message_text = re.compile('\]\s(.+)$')
        re_values_found = re.compile('\[.+\]')

        app_log_dict = {}
        unique_applications_set = set()
        line_index = 0
        with open(self.log_path) as f:
            for log_line in f:
                line_dict = {}
                # print "!!! log_line - " + str(log_line)
                # Extract message timestamp
                _date_time = re_date_time.search(log_line)
                # If date_time isn't line skip line as it's likely to be junk
                if (_date_time is None):
                    continue
                date = _date_time.group(1).strip()
                time = _date_time.group(2).strip()
                short_message = False

                # Extract message details
                message_type = re_message_type.search(log_line).group(1).strip()
                try:
                    message_text = re_message_text.search(log_line).group(1) \
                        .strip()
                except AttributeError:
                    message_text = re_short_message_text.search(log_line) \
                        .group(1).strip()
                    short_message = True
                values_found = ""
                try:
                    values_found = re_values_found.search(message_text) \
                        .group(0).strip()
                except AttributeError:
                    values_found = ""
                #print "message_dict: " + str(message_dict)

                if (short_message is True):
                    line_dict = {
                        "type": message_type,
                        "date": date,
                        "time": time,
                        "text": message_text
                    }
                else:
                    # Extract connection details
                    connection_details = re_connection_details.search(log_line).group(1)
                    #print "connection_details: " + connection_details
                    # Extract source and destination sockets
                    _sockets = re_sockets.findall(connection_details)
                    src_socket = _sockets[0].strip()
                    src_ip, src_port = re.split(':', src_socket)
                    dest_socket = _sockets[1].strip()
                    dest_ip, dest_port = re.split(':', dest_socket)
                    connection_id = re_connection_id.search(connection_details) \
                        .group(0).strip()
                    handler = re_handler.search(connection_details).group(0) \
                        .strip()
                    #print "connection_dict: " + str(connection_dict)

                    # Extract client details
                    client_details = re_client_details.search(log_line) \
                        .group(1).strip()
                    #print "client_details: " + client_details
                    client_dict = {}
                    if ("Unknown" in client_details):
                        client_type = "unknown"
                        client_application = "unknown"
                        client_version = "unknown"
                    else:
                        client_type = re_client_type.search(client_details) \
                            .group(0).strip()
                        client_application = re_application.search(client_details) \
                            .group(1).strip()
                        client_version = re_version.search(client_details) \
                            .group(1).strip()
                        unique_applications_set.add(client_application)

                    line_dict = {
                        "line_num": str(line_index),
                        "message": {
                            "type": message_type,
                            "date": date,
                            "time": time,
                            "text": message_text.replace('\'', '')
                        },
                        "connection": {
                            "source_socket": src_socket,
                            "source_ip": src_ip,
                            "source_port": src_port,
                            "destination_socket:": dest_socket,
                            "destination_ip": dest_ip,
                            "destination_port": dest_port,
                            "connection_id": connection_id,
                            "handler": handler
                        },
                        "client": {
                            "client_type": client_type,
                            "client_application": client_application,
                            "client_version": client_version
                        }
                    }
                    """ If values were found in message string add them to the
                        message dictionary"""
                    if (values_found):
                        line_dict["message"]["values_found"] = values_found.replace('\'', '')
                    #print "client_dict:" + str(client_dict)
                #print "line_dict:" + str(line_dict)
                app_log_dict[str(line_index)] = line_dict
                line_index += 1
        self._applications = list(unique_applications_set)
        self._application_log_dict = app_log_dict

    @property
    def log_dict(self):
        """ Returns the application log entries in the form of a dictionary.
        """
        return self._application_log_dict

    @property
    def applications(self):
        """ Returns a list of applications present in the application log file.
        """
        return self._applications


class ProcessEventLog(ProcessLog):
    """ Class processes the event log file (default mitm.log) to extract
        meaningful information.
    """
    def __init__(self, log_path):
        #super(, self).__init__()
        self.log_path = log_path
        self._event_log_dict = {}
        self._event_log_dict = self._process_log()

    def _process_log(self):
        """ Generator method processes lines from a log file.
            Based on http://stackoverflow.com/questions/30627810/how-to-parse-this-custom-log-file-in-python
        """
        re_attack_status = re.compile('\"success\"\:\s*\"*([\w\.]+)\"*\,')
        # re_data = re.compile('\"data\"\:\s*\"*([\w\.\?\/\-\=\&\@\%]+)\"*\,')
        re_data_1 = re.compile('\"data\"\:\s*\"*([\w\.\?\/\-\_\,\=\&\@\+\:\%\~\!\;\*\#\$]+)\"\,')
        re_data_2 = re.compile('\"data\"\:\s*([null]+)\,')
        re_client_addr = re.compile('\"client_addr\"\:\s*\"([\d.]+)\"')
        re_hostname = re.compile('\"hostname\"\:\s*\"([\w._-]+)\"')
        re_connection_id = re.compile('\"connection_id\"\:\s*\"([\w.-]+)\"')
        re_application_details = re.compile('\"applications\"\:\s*\[\[\"([\w\.]+)\"\,\s*\"([\w\.]+)')
        re_application_name = re.compile('\"applications\"\:\s*\[\[\"([\w\.]+)\"\,')
        re_application_version = re.compile('applications\"\:\s*\[\[\"[\w.]+\"\,\s\"([\d.]+)\"')
        re_client_port = re.compile('\"client_port\"\:\s*(\d+)')
        re_handler = re.compile('\"handler\"\:\s*\"*([\w_-]+)\"*')
        re_server_port = re.compile('\"server_port\"\:\s*\"*(\d+)\"*')
        re_time = re.compile('\"time\"\:\s*([\d.]+)')
        re_type = re.compile('\"type\"\:\s*\"*([\w]+)\"*')
        re_platform_info = re.compile('\"platform_info\"\:\s*\"([\w.:/?&=-]+)\"')
        re_server_addr = re.compile('\"server_addr\"\:\s*\"([\d.]+)\"')
        re_installation_id = re.compile('\"installation_id\"\:\s*\"([\w.-]+)\"')

        event_log_dict = {}
        line_index = 0
        with open(self.log_path) as f:
            for log_line in f:
                line_dict = {}
                # Remove square brackets from log line.
                # log_line = log_line.translate("[", "[[")
                #print "--- log_line: " + log_line
                attack_success = re_attack_status.search(log_line).group(1) \
                    .strip()
                try:
                    data = re_data_1.search(log_line).group(1).strip()
                except AttributeError:
                    data = re_data_2.search(log_line).group(1).strip()
                client_addr = re_client_addr.search(log_line).group(1).strip()
                # If hostname attribute doesn't exist assign an empty string.
                try:
                    hostname = re_hostname.search(log_line).group(1).strip()
                except AttributeError, e:
                    hostname = ""
                # Get request domain name
                domain = self._get_domain_name(hostname, data)
                connection_id = str(re_connection_id.search(log_line) \
                    .group(1)).strip()
                application_details = re_application_details.findall(log_line)
                try:
                    application_name = re_application_name.search(log_line) \
                        .group(1).strip()
                except AttributeError, e:
                    application_name = ""
                try:
                    application_version = re_application_version.search(log_line) \
                        .group(1).strip()
                except AttributeError, e:
                    application_version = ""
                client_port = re_client_port.search(log_line).group(1).strip()
                handler = re_handler.search(log_line).group(1).strip()
                server_port = re_server_port.search(log_line).group(1).strip()
                entry_time = re_time.search(log_line).group(1).strip()
                entry_type = re_type.search(log_line).group(1).strip()
                try:
                    platform_info = re_platform_info.search(log_line).group(1) \
                        .strip()
                except AttributeError, e:
                    platform_info = ""
                server_addr = re_server_addr.search(log_line).group(1).strip()
                try:
                    installation_id = re_installation_id.search(log_line).group(1) \
                        .strip()
                except AttributeError, e:
                    installation_id = ""
                attack_entry_dict = {
                                "handler": str(handler),
                                "attack_type": str(handler),
                                "attack_success": attack_success,
                                "time": str(entry_time),
                                "data": data,
                               }
                # If connection item already in event_log dictionary add new
                # attack details.
                try:
                    connection_dict = event_log_dict[connection_id]
                    connection_dict["attacks"].append(attack_entry_dict)
                # If connection item doesn't exist add to event_log dictionary
                except KeyError, e:
                    line_dict = {"source_ip": client_addr,
                                 "source_port": str(client_port),
                                 "connection_id": connection_id,
                                 "application": {"name": application_name,
                                                 "version": application_version},
                                 "destination_ip": server_addr,
                                 "destination_port": str(server_port),
                                 "hostname": hostname,
                                 "domain": domain,
                                 "type": entry_type,
                                 "platform_info": platform_info,
                                 "installation_id": installation_id}
                    line_dict["attacks"] = []
                    line_dict["attacks"].append(attack_entry_dict)
                    event_log_dict[connection_id] = line_dict
                line_index += 1
        return event_log_dict

    def _get_domain_name(self, hostname, path):
        """ Returns the domain for the current event log message item
            Note. Sometimes requests have no hostname so the domain needs to
            be determine from the URL path
        """
        domain_name = ""
        if (hostname.strip() is not ""):
            domain_name = hostname.replace("www.", "")
        # elif (path is not ""):
        else:
            #print "!!! path extract domain - " + path
            try:
                domain_name = re.search('^([\w\.\?\-\=\&\@\%]+)\/', path) \
                    .group(1).strip()
            except AttributeError:
                domain_name = ""
        return domain_name

    @property
    def log_dict(self):
        """ Returns the event log entries in the form of a dictionary.
        """
        return self._event_log_dict
