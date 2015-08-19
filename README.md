# nogotofail-pii

nogotofail-pii (aka noseyparker) is a fork of the nogotofail tool and it's primary aim is to test Android mobile applications for network based privacy issues. Privacy threats this project aims to highlight are:
- Excessive collection of personally identifiable information (PII) by mobile applications
- Inappropriate disclosure of PII by mobile applications to online service providers e.g. advertising & analytics services
- "Leakage" of PII on the network path in unencrypted traffic

Key features added are:
- Detection of PII in encrypted and unencrypted traffic, including accumulated PII across  application sessions
- Detection of TLS encryption not implementing forward secrecy
- Reporting of PII issues by domain (JSON format)
- Auto-collection of PII test data from Android device
- Ability to define custom PII test data
- Summary nogotofail application message and event reporting (JSON format)

Other miscellaneous privacy and security features including:
- Detection of certificates using SHA-1 signatures with expiry dates during or after the  [Chrome](http://blog.chromium.org/2014/09/gradually-sunsetting-sha-1.html) sunset period

Detailed information on the features provided, configuring PII detection handlers and reporting can be found on the [PII analysis page](docs/pii_analysis.md).

Application event summary reporting has also been added which provides a summarized view of alerts raised by mobile applications. Please read the [Event Summary Reporting](docs/event_summary_reporting.md) page for more information.

Where appropriate pull requests may be raised in the (parent) nogotofail project for features relevant to the parent project.

This project is sponsored by the Google Summer of Code 2015.

More about the parent [nogotofail](https://github.com/google/nogotofail) project ...

# nogotofail

Nogotofail is a network security testing tool designed to help developers and
security researchers spot and fix weak TLS/SSL connections and sensitive
cleartext traffic on devices and applications in a flexible, scalable, powerful way.
It includes testing for common SSL certificate verification issues, HTTPS and TLS/SSL
library bugs, SSL and STARTTLS stripping issues, cleartext issues, and more.

##Design
Nogotofail is composed of an on-path network MiTM and optional clients for the devices being tested.
See [docs/design.md](docs/design.md) for the overview and design goals of nogotofail.

##Dependencies
Nogotofail depends only on Python 2.7 and pyOpenSSL>=0.13. The MiTM is designed to work on Linux
machines and the transparent traffic capture modes are Linux specific and require iptables as well.

Additionally the Linux client depends on [psutil](https://pypi.python.org/pypi/psutil).

##Getting started
See [docs/getting_started.md](docs/getting_started.md) for setup and a walkthrough of nogotofail.

##Discussion
For discussion please use our [nogotofail Google Group](https://groups.google.com/forum/#!forum/nogotofail).
