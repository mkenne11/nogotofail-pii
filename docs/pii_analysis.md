# PII Analysis

nogotofail-pii can detect PII sent in traffic (for both HTTP and HTTPS protocols) between mobile applications and online services.

This page is broken into two sections:
- a description of how to use the [PII detection handlers](#pii_detection_handlers), and
- summary [PII reporting](#pii_reporting).

## 1. <a name="pii_detection_handlers"></a>PII Detection Handlers

There are 2 handlers (attacks) available that inspect mobile application traffic for personally identifiable information (PII):
- **httppii** - parses unencrypted (HTTP) traffic
- **httpspii** - parses encrypted (HTTPS) traffic

The **httpspii** handler acts as a man-in-the-middle (MitM) TLS proxy, intercepting and terminating requests between the client and MitM daemon, and later handling encryption of traffic between the MitM daemon and online service.

For the **httpspii** handler to perform a man-in-the-middle attack a certificate is required that is trusted by the client. There are two options available - a. purchasing a TLS certificate from a trusted commercial CA; or b. generating your own CA and trusted certificate. Instructions for generating your own CA and trusted certificate (option b) can be found [here](create_tls_proxy_cert.md).

### 1.a. Specifying PII Detection Handlers

nogotofail-pii can be configured to use the PII detection handlers by adding the handler arguments in the configuration (`*.mitm`) file. A snippet of an example configuration file is shown below:
```
[nogotofail.mitm]
attacks=httpspii
data=httppii

probability=0.2
debug=True

serverssl=/etc/nogotofail/mitm_controller_cert_and_key.pem
logfile=/var/log/nogotofail/mitm.log
eventlogfile=/var/log/nogotofail/mitm.event
trafficfile=/var/log/nogotofail/mitm.traffic
```
The **httppii** handler is a "data" handler and analyses the http data stream for PII information. The **httpspii** is an "attack" handler and manipulates the TLS connection.
Note. Tampering of the TLS connection by the **httpspii** handler adds latency to requests, so it is recommended that you choose an attack "probability" value which minimizes the chance of request timeouts. Trial and error is required to find the correct probability for your setup.

### 1.b. Configuring PII Items

nogotofail-pii has two categories of PII that can be detected - pii-identifiers and pii-details.

pii-identifiers are identifiers that uniquely identify a device or user. Suggested examples are phone number, Facebook user ID, email. These identifiers can be defined in the '[nogotofail.identifiers.pii]' section of the configuration file.

pii-details describe data about the individual that may by themselves do not uniquely identify them, but could identify the individual if combined with other data. Suggested examples are first name, last name, postal address. These identifiers can be defined in the '[nogotofail.details.pii]' section of the configuration file.

An example configuration file is shown below.
```
[nogotofail.identifiers.pii]
facebook_id=abc@facebook.com
ip_address=55.66.77.88
email = joe.blogs@gmail.com

[nogotofail.details.pii]
first_name = joe
last_name = blogs
postal_address = "1 Long Road, Towns-ville"
```

Custom PII items to check can be specified in the configuration (`*.mitm`) file.

There are reserved PII names used for personal information collected from the device by the Android client, which cannot be used for custom PII values. The reserved PII names are listed below.

| Reserved PII | Description |
|--------------|---|
| android_id | The Android ID used by the device  |
| imei | The devices IMEI number (for SIM devices only) |
| mac_address | The devices MAC address  |
| google_ad_id | The Google Advertising ID currently assigned to the device  |
| ip_address | The devices IP address  |

## 2. <a name="pii_reporting"></a>PII Reporting

### 2.a. Generating PII Reports

The PII data report summarizes PII issues alerted in the application verbose output and event logs. It can be run manually using the following command:
```
nogotofail/mitm/report/generate_report.py -r pii_data_report -o /etc/nogotofail/reports -l /var/log/nogotofail/mitm.log -e /var/log/nogotofail/mitm.event
```
```
-r - Specifies the json report to generate. PII JSON report is pii_data_report
-o - Folder where reports are generated
-l - Path of verbose log to be read
-e - Path of machine parseable event log to be read
```

### 2.b. PII Report Format

An example PII summary report is shown below.
```
// Android app identifier
"com.ringtones.app": {
    // Domains used by application for which PII is transmitted between the app
    // and online services
    "app_domains": [
      {
        // Domain PII items were found in.
        "domain": "ads.mopub.com",
        // Accumulated PII sent over unencrypted channel (non-HTTPS) for domain
        "unencrypted_elements": {
          "pii_query_string": [
            "google_advertising_id"
          ]
        },
        // Accumulated PII sent over encrypted channel (HTTPS)
        "encrypted_elements": {
          "pii_http_body": [
            "android_id",
            "mac_address"
          ]
        },
        // Accumulated query-string parameter/value pairs sent over unencrypted
        // channel (HTTPS) and number of requests they appeared. Even non-PII items
        // could allow tracking if persistent over multiple requests
        "unencrypted_query_strings": {
            "key_value_count": {
              "req=a54235ff7ea124387b33b590cdd3eb098": "4",
              "dn=samsun%2CGalaxy%207%2CTab": "11",
              "osv=5.1.1": "4",
              "city=Mountain%20View": "4",
              "id=f02df4fda83db32e147efec753e947b7c": "11",
              "country_code=US": "4",
              "cid=47799eaf1afe4cd81bf39ca62d54d5e7": "4",
              "os=Android": "4",
          }
        }
      }
    ],
    "app_version": "321",
    "app_type": "client=google/galaxytab/flo:5.1.1/LMR22F/1365102:user/release-keys",
    "app_name": "com.ringtones.app"
  },
```
For each application the domains found where PII is transmitted between the application and online services is shown in the **app_domains > domain** nodes.

Under the **app_domains > domain** node sud-nodes display the PII information transferred between the application and online services:
- **unencrypted_elements** list PII items disclosed by the application in unencrypted (HTTP) traffic. It is indicated if PII is disclosed via HTTP query string (pii_query_string), header (pii_http_header) or message body (pii_http_body).
- **encrypted_elements** list PII items disclosed by the application in encrypted (HTTPS) traffic. It is indicated if PII is disclosed via HTTP query string (pii_query_string), header (pii_http_header) or message body (pii_http_body).
- **unencrypted_query_strings > key_value_count** displays the key/value pairs listed in unencrypted HTTP query strings and the number of HTTP requests in which the key/value pair has occured. Although key/value pairs may not contain PII data, if they occur in multiple HTTP requests they could allow user tracking.
