"""
OpenDrop: an open source AirDrop implementation
Copyright (C) 2018  Milan Stute
Copyright (C) 2018  Alexander Heinrich

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import os
import random
import socket
import ssl
import subprocess

from pkg_resources import resource_filename

logger = logging.getLogger(__name__)


class AirDropReceiverFlags:
    """
    Recovered from sharingd`receiverSupportsX methods.
    A valid node needs to either have SUPPORTS_PIPELINING or SUPPORTS_MIXED_TYPES
    according to sharingd`[SDBonjourBrowser removeInvalidNodes:].
    Default flags on macOS: 0x3fb according to sharingd`[SDRapportBrowser defaultSFNodeFlags]
    """

    SUPPORTS_URL = 0x01
    SUPPORTS_DVZIP = 0x02
    SUPPORTS_PIPELINING = 0x04
    SUPPORTS_MIXED_TYPES = 0x08
    SUPPORTS_UNKNOWN1 = 0x10
    SUPPORTS_UNKNOWN2 = 0x20
    SUPPORTS_IRIS = 0x40
    SUPPORTS_DISCOVER_MAYBE = (
        0x80  # Probably indicates that server supports /Discover URL
    )
    SUPPORTS_UNKNOWN3 = 0x100
    SUPPORTS_ASSET_BUNDLE = 0x200


class AirDropConfig:
    def __init__(
        self,
        host_name=None,
        computer_name=None,
        computer_model=None,
        server_port=8771,
        airdrop_dir="~/.opendrop",
        service_id=None,
        email=None,
        phone=None,
        debug=False,
        interface=None,
    ):
        self.airdrop_dir = os.path.expanduser(airdrop_dir)

        self.discovery_report = os.path.join(self.airdrop_dir, "discover.last.json")

        if host_name is None:
            host_name = socket.gethostname()
        self.host_name = host_name
        if computer_name is None:
            computer_name = host_name
        self.computer_name = computer_name
        if computer_model is None:
            computer_model = "OpenDrop"
        self.computer_model = computer_model
        self.port = server_port

        if service_id is None:
            service_id = f"{random.randint(0, 0xFFFFFFFFFFFF):012x}"  # random 6-byte string in base16
        self.service_id = service_id

        self.debug = debug
        self.debug_dir = os.path.join(self.airdrop_dir, "debug")

        if interface is None:
            interface = "awdl0"
        self.interface = interface

        if email is None:
            email = []
        self.email = email
        if phone is None:
            phone = []
        self.phone = phone

        # Bare minimum, we currently do not support anything else
        self.flags = (
            AirDropReceiverFlags.SUPPORTS_MIXED_TYPES
            | AirDropReceiverFlags.SUPPORTS_DISCOVER_MAYBE
        )

        self.root_ca_file = resource_filename("opendrop", "certs/apple_root_ca.pem")
        if not os.path.exists(self.root_ca_file):
            raise FileNotFoundError(
                f"Need Apple root CA certificate: {self.root_ca_file}"
            )

        self.key_dir = os.path.join(self.airdrop_dir, "keys")
        self.cert_file = os.path.join(self.key_dir, "certificate.pem")
        self.key_file = os.path.join(self.key_dir, "key.pem")

        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            logger.info("Key file or certificate does not exist")
            self.create_default_key()

        self.record_file = os.path.join(self.key_dir, "validation_record.cms")
        self.record_data = None
        if os.path.exists(self.record_file):
            logger.debug("Using provided Apple ID Validation Record")
            with open(self.record_file, "rb") as f:
                self.record_data = f.read()
        else:
            logger.debug("No Apple ID Validation Record found")

    def create_default_key(self):
        logger.info(f"Create new self-signed certificate in {self.key_dir}")
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir)
        subprocess.run(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "key.pem",
                "-x509",
                "-days",
                "365",
                "-out",
                "certificate.pem",
                "-subj",
                f"/CN={self.computer_name}",
            ],
            cwd=self.key_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

    def get_ssl_context(self):

        ctx = ssl.SSLContext(  # lgtm[py/insecure-protocol], TODO see https://github.com/Semmle/ql/issues/2554
            ssl.PROTOCOL_TLS
        )
        ctx.options |= ssl.OP_NO_TLSv1  # TLSv1.0 is insecure
        ctx.load_cert_chain(self.cert_file, keyfile=self.key_file)
        ctx.load_verify_locations(cafile=self.root_ca_file)
        ctx.verify_mode = (
            ssl.CERT_NONE
        )  # we accept self-signed certificates as does Apple
        return ctx
