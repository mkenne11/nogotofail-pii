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
import logging
from nogotofail.mitm.connection.handlers.connection import handlers
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
from nogotofail.mitm.connection.handlers.connection import LoggingHandler
from nogotofail.mitm import util
from datetime import datetime


@handler(handlers, default=True)
class SunsetSHA1(LoggingHandler):

    name = "sunsetsha1"
    description = (
        "Detects TLS certificates using SHA-1 hashing and compares to Google "
        " sunset dates. Alerts will raised depending on the expiry date")

    ca = util.CertificateAuthority()
    certificate = None

    def on_ssl(self, client_hello):
        self.ssl = True
        return True

    def on_certificate(self, server_cert):
        CRT_DATE_FORMAT = "%Y%m%d%H%M%SZ"
        subject = server_cert.get_subject()
        crt_signature_algorithm = server_cert.get_signature_algorithm()

        if ("sha1" in crt_signature_algorithm):
            """ SHA-1 sunset dates based on Google Chrome dates published dates. See
                http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html
            """
            sunset_warning_date = datetime.strptime("31-12-2015", "%d-%m-%Y")
            sunset_error_date = datetime.strptime("30-06-2016", "%d-%m-%Y")
            sunset_critical_date = datetime.strptime("31-12-2016", "%d-%m-%Y")
            crt_CN = subject.CN
            crt_not_before = server_cert.get_notBefore()
            crt_not_after = server_cert.get_notAfter()
            debug_message = "Cert attribute: " + crt_CN + \
                "; notBefore " + crt_not_before + \
                "; notAfter " + crt_not_after + \
                "; signature_algorithm " + crt_signature_algorithm
            self.log(logging.DEBUG, debug_message)

            crt_not_after = datetime.strptime(crt_not_after, CRT_DATE_FORMAT)
            """ Raise notification if certificate expires after a Chrome sunset
                date """
            if (crt_not_after > sunset_critical_date):
                log_message = "Certificate uses SHA-1 and expires after 31 " + \
                    "Dec 2016"
                self.log(logging.CRITICAL, log_message)
                self.log_event(logging.CRITICAL, connection.AttackEvent(
                               self.connection, self.name, True, ""))
                self.connection.vuln_notify(util.vuln.VULN_SUNSET_SHA1)
            elif (crt_not_after > sunset_error_date):
                log_message = "Certificate uses SHA-1 and expires after 30 " + \
                    "Jun 2016"
                self.log(logging.ERROR, log_message)
                self.log_event(logging.ERROR, connection.AttackEvent(
                               self.connection, self.name, True, ""))
                self.connection.vuln_notify(util.vuln.VULN_SUNSET_SHA1)
            elif (crt_not_after > sunset_warning_date):
                log_message = "Certificate uses SHA-1 and expires after 31 " + \
                    "Dec 2015"
                self.log(logging.WARNING, log_message)
                self.log_event(logging.WARNING, connection.AttackEvent(
                               self.connection, self.name, True, ""))
                self.connection.vuln_notify(util.vuln.VULN_SUNSET_SHA1)
        """ Fetch and return certificate """
        for k, v in subject.get_components():
            if k == "CN":
                cn = v
        extensions = [server_cert.get_extension(i)
                      for i in range(server_cert.get_extension_count())]
        altnames = [extension for extension in extensions
                    if extension.get_short_name() == "subjectAltName"]
        san = altnames[0] if len(altnames) > 0 else None
        self.certificate = self.ca.get_cert(cn, san)
        return self.certificate
