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
from nogotofail.mitm.util import tls
from nogotofail.mitm.util.tls.types import Alert, Extension, HandshakeMessage, TlsRecord


@handler(handlers, default=True)
class NoForwardSecrecy(LoggingHandler):
    """ Class detect negotiated TLS cipher suites which don't use key exchange
        techniques supporting forward secrecy i.e. DHE, ECDHE """
    name = "noforwardsecrecy"
    description = (
        "Detects server cipher suites which don't support Diffie-Hellman "
        "key exchange")

    buffer = ""

    def on_ssl(self, client_hello):
        self.ssl = True
        self.client_session_id = client_hello.session_id
        return False

    def on_response(self, response):
        if not self.ssl:
            return response
        response = self.buffer + response
        self.buffer = ""
        try:
            index = 0
            while index < len(response):
                record, size = TlsRecord.from_stream(response[index:])
                version = record.version
                for i, message in enumerate(record.messages):
                    # Check if Server Hello message
                    if (isinstance(message, tls.types.HandshakeMessage)
                           and message.type == HandshakeMessage.TYPE.SERVER_HELLO):
                        server_hello = message.obj
                        selected_cipher = str(server_hello.cipher)
                        # self.log(logging.DEBUG, "!!! NoForwardSecrecy: on_response > " +
                        # "cipher - " + selected_cipher)
                        """ Check if Ephemeral Diffie-Hellman key exchange is used """
                        fs_key_strings = ["DHE", "ECDHE"]
                        if not [fs_string for fs_string in fs_key_strings
                                if fs_string in selected_cipher]:
                            # self.log(logging.DEBUG, "!!! NoForwardSecrecy: on_response > " +
                            #          "No forward secrecy DHE used!!!")
                            error_message = \
                                ["Cipher suite key exhange technqiue doesn't ",
                                 "support forward secrecy. ",
                                 "Cipher suite - [", selected_cipher, "]"]
                            self.log(logging.WARNING, "".join(error_message))
                            self.log_event(logging.WARNING, connection.AttackEvent(
                                           self.connection, self.name, True, ""))
                            self.connection.vuln_notify(
                                util.vuln.VULN_NO_FORWARD_SECRECY)
                        return response
                index += size

        except ValueError:
            # Failed to parse TLS, this is probably due to a short read of a TLS
            # record. Buffer the response to try and get more data.
            self.buffer = response
            # But don't buffer too much, give up after 16k.
            if len(self.buffer) > 2**14:
                response = self.buffer
                self.buffer = ""
                return self.buffer
            return ""
        return response
