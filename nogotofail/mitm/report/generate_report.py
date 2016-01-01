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

#!/usr/bin/python2.7

import optparse
import sys
from process_logs import *
from report_data import *


""" Method used to generate JSON summary reports from the command line
"""
if __name__ == "__main__":
    # Configure command line reporting options
    parser = optparse.OptionParser(prog='analyse_logs.py')
    parser.add_option("-r", "--report", dest="report",
                      default="pii_data_report",
                      choices=["pii_data_report", "event_summary_report"],
                      help="Specifies json report to generate. Available " +
                           "reports are pii_data_report & event_summary_report")
    parser.add_option("-o", "--output", dest="output_folder",
                      type="string",
                      help="Folder where reports are generated")
    parser.add_option("-l", "--log", dest="verbose_log",
                      type="string",
                      help="Path of verbose log to be read")
    parser.add_option("-e", "--event", dest="event_log",
                      default="", type="string",
                      help="Path of machine parseable event log to be read")

    (options, args) = parser.parse_args()
    arg_report = options.report
    arg_output_folder = options.output_folder
    arg_verbose_log = options.verbose_log
    arg_event_log = options.event_log

    if (not arg_report or not arg_output_folder or not arg_verbose_log or
        not arg_event_log):
        sys.exit("All 4 input parameters are needed to generate a report.")

    application_log = ProcessApplicationLog(arg_verbose_log)
    # print "*** Application Dictionary:" + str(application_log.log_dict)
    event_log = ProcessEventLog(arg_event_log)

    # print "*** Event Dictionary:" + str(event_log.log_dict)
    # print "*** Application List:" + str(application_log.applications)
    app_message_report = MessageReport(application_log, event_log)
    app_event_report = EventReport(application_log, event_log)
    app_event_summary_report = EventSummaryReport(application_log, event_log)
    app_pii_data_report = PIIDataReport(application_log, event_log)

    # Generates JSON report specified
    if arg_report == "event_summary_report":
        Event_Summary_Report_Path = arg_output_folder + "/event_summary_report.json"
        with open(Event_Summary_Report_Path, "w") as json_file:
            json_file.write(app_event_summary_report.json_report)
        print "Report " + arg_report + " generated"

    elif arg_report == "pii_data_report":
        PII_Data_Report_Path = arg_output_folder + "/pii_data_report.json"
        with open(PII_Data_Report_Path, "w") as json_file:
            json_file.write(app_pii_data_report.json_report)
        print "Report " + arg_report + " generated"

    else:
        print "Invalid report name was specified."
