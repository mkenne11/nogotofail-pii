# Event Summary Reporting

### 1.a. Generating Event Summary Report

The summary report provides a consolidated view of log information across both event and verbose output logs and removes duplicate event entries. The event log contains the raw events list with each event (potentially) raised multiple times, also and some important information (such as message text) is contained in the verbose output log.

The report can be run manually using the following command:
```
nogotofail/mitm/report/generate_report.py -r event_summary_report -o /etc/nogotofail/reports -l /var/log/nogotofail/mitm.log -e /var/log/nogotofail/mitm.event
```
```
-r - Specifies the json report to generate. Event summary report is event_summary_report
-o - Folder where reports are generated
-l - Path of verbose log to be read
-e - Path of machine parseable event log to be read
```

### 1.b. Event Summary Report Format

The format of the Event Summary Report is shown in the sample report below. The events raised are grouped by  the application and the domain they occurred for.
```
/* Android app identifier */
"com.fitnesstracking.app": {
"app_events": [
  {
    /* Event details */
    "event_type": "ERROR",
    "events": [
      {
        "pii_items_found": [
          "99.44",
          "2.33"
        ],
        "message": "PII: Location found in request query string (longitude, latitude) - [99.11, 2.44]",
        "handler": "piiquerystringdetection",
        "domain": "maps.tracking.com"
      }
    ]
  }
],
/* Android app details */
"app_version": "23573",
"app_type": "client=google/galaxytab/flo:5.1.1/LMY48G/2225112:user/release-keys",
"app_name": "com.fitnesstracking.app"
},

"com.ringtone.app": {
"app_events": [
  {
    "event_type": "ERROR",
    "events": [
      {
        "pii_items_found": [
          "google_advertising_id"
        ],
        "message": "PII: Personal IDs found in request query string [google_advertising_id]",
        "handler": "piiquerystringdetection",
        "domain": "ads.mopub.com"
      }
    ]
  }
],
"app_version": "8",
"app_type": "client=google/galaxytab/flo:5.1.1/LMY223/2225121:user/release-keys",
"app_name": "com.hypester.mtp"
},
```
