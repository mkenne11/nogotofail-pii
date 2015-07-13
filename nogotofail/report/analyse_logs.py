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
    app_message_report = ApplicationMessageReport(application_log, event_log)
    app_messages = app_message_report.json_report
    app_alert_report = ApplicationAlertReport(application_log, event_log)
    app_alerts = app_alert_report.json_report
    app_alert_summary_report = ApplicationAlertSummaryReport(application_log, event_log)
    app_alert_summary = app_alert_summary_report.json_report
    # print "*** Application Messages List: %s" % app_messages
    # print "\n\n"
    # print "*** Application Alert List: %s" % app_alerts
    # print "\n\n"
    # print "*** Application Alert Summary: %s" % app_alert_summary
    # print "\n\n\n\n"
    app_data_report = ApplicationDataReport(application_log, event_log)
    print "*** Application PII Data: %s" % app_data_report.json_report
