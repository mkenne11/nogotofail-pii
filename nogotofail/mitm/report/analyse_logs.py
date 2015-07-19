#!/usr/bin/python2.7

import json
from process_logs import *
from report_data import *


""" Constants for log file paths.
"""
APPLICATION_LOG_PATH = "/var/log/nogotofail/mitm.log"
EVENT_LOG_PATH = "/var/log/nogotofail/mitm.event"


if __name__ == "__main__":
    application_log = ProcessApplicationLog(APPLICATION_LOG_PATH)
    #print "*** Application Dictionary:" + str(application_log.log_dict)
    #print "\n\n"
    event_log = ProcessEventLog(EVENT_LOG_PATH)
    #print "*** Event Dictionary:" + str(event_log.log_dict)
    #print "\n\n"
    #print "*** Application List:" + str(application_log.applications)
    #print "\n\n"
    app_message_report = MessageReport(application_log, event_log)
    app_messages = app_message_report.json_report
    app_event_report = EventReport(application_log, event_log)
    app_events = app_event_report.json_report
    app_event_summary_report = EventSummaryReport(application_log, event_log)
    app_event_summary = app_event_summary_report.json_report
    print "*** Application Messages: %s" % app_messages
    print "\n\n"
    # print "*** Application Events : %s" % app_events
    # print "\n\n"
    # print "*** Application Event Summary: %s" % app_event_summary
    # print "\n\n\n\n"
    # app_pii_data_report = PIIDataReport(application_log, event_log)
    # print "*** Application PII Data: %s" % app_pii_data_report.json_report
