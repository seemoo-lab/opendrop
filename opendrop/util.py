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

import base64
import datetime
import hashlib
import io
import ipaddress
import os
import plistlib

import ifaddr
from PIL import Image, ExifTags
from ctypescrypto import cms, x509, pkey, oid
from libarchive import ffi
from libarchive.entry import new_archive_entry, ArchiveEntry
from libarchive.ffi import (
    ARCHIVE_EOF,
    entry_sourcepath,
    entry_clear,
    read_next_header2,
    read_disk_descend,
    write_header,
    write_data,
    write_finish_entry,
)
from libarchive.write import ArchiveWrite, new_archive_read_disk


class AirDropUtil:
    """
    This class contains a set of utility functions that support the opendrop implementation
    They have been moved, because the opendrop files tend to get too long
    """
    @staticmethod
    def get_uti_type(flp) -> str:
        """
        Get the Apple conform UTI Type from a flp instance which has been used on the data which should be sent

        :param flp: fleep object
        """

        # Default UTI Type
        uti_type = 'public.content'
        if len(flp.mime) == 0 or len(flp.type) == 0:
            return uti_type

        mime = flp.mime[0]
        f_type = flp.type[0]
        if 'image' in mime:
            uti_type = 'public.image'

            if 'jpg' in mime:
                uti_type = 'public.jpeg'
            elif 'jp2' in mime:
                uti_type = 'public.jpeg-2000'
            elif 'gif' in mime:
                uti_type = 'com.compuserve.gif'
            elif 'png' in mime:
                uti_type = 'public.png'
            elif 'raw' in mime or 'raw' in f_type:
                uti_type = 'public.camera-raw-image'
        elif 'audio' in f_type:
            uti_type = 'public.audio'
        elif 'video' in f_type:
            uti_type = 'public.video'
        elif 'archive' in f_type:
            uti_type = 'public.data'

            if 'gzip' in mime:
                uti_type = 'org.gnu.gnu-zip-archive'
            if 'zip' in mime:
                uti_type = 'public.zip-archive'

        return uti_type

    @staticmethod
    def record_data(config, tls_cert, sign_cert, key):
        """
        This method generates the sender record data and will sign it using the CMS format.

        This code serves documentation purposes only and is UNTESTED. To be accepted by Apple clients, we would need the
        Apple-owned private key of the signing certificate.

        :param tls_cert: path to certificate used for AirDrop TLS connections
        :param sign_cert: path to signing certificate
        :param key: path to private key to the signing certificate
        """

        valid_date = datetime.datetime.now() - datetime.timedelta(days=3)
        valid_date_string = valid_date.strftime('%Y-%m-%dT%H:%M:%SZ')

        emails_hashed = [hashlib.sha256(email.encode('utf-8')).hexdigest() for email in config.email]
        phone_numbers_hashed = [hashlib.sha256(phone_number.encode('utf-8')).hexdigest() for phone_number in config.phone]

        # Get the common name of the TLS certificate
        with open(tls_cert, 'rb') as cert_file:
            cert = x509.X509(cert_file.read())
            cn = cert.subject[oid.Oid('2.5.4.3')]
            encDsID = cn.replace('com.apple.idms.appleid.prd.', '')

        # Construct record data
        record_data = {
            'Version': 2,
            'encDsID': encDsID,  # Common name suffix of the certificate
            'altDsID': encDsID,  # Same as encDsID
            'SuggestValidDuration': 30 * 24 * 60 * 60,  # in seconds
            'ValidAsOf': valid_date_string,  # 3 days before now
            'ValidatedEmailHashes': emails_hashed,
            'ValidatedPhoneHashes': phone_numbers_hashed,
        }
        record_data_plist = plistlib.dumps(record_data, fmt=plistlib.FMT_XML)

        with open(sign_cert, 'rb') as sign_cert_file:
            with open(key, 'rb') as key_file:
                cert = x509.X509(sign_cert_file.read())
                key = pkey.PKey(privkey=key_file.read())
                # possibly need to add intermediate certs
                cms_signed = cms.SignedData.create(record_data_plist, cert=cert, pkey=key, certs=None, flags=cms.Flags.PARTIAL)
                signed_data = AirDropUtil.pem2der(cms_signed.pem())

        return signed_data

    @staticmethod
    def pem2der(s):
        """
        Create DER Formatted bytes from a PEM Base64 String

        :param s: PEM formatted string
        """
        start = s.find('-----\n')
        finish = s.rfind('\n-----END')
        data = s[start + 6:finish]
        return base64.b64decode(data)

    @staticmethod
    def generate_file_icon(file_path):
        """
        Generates a small and a big thumbnail of an image
        This will make it possible to preview the sent file

        :param file_path: The path to the image
        """
        im = Image.open(file_path)

        # rotate according to EXIF tags
        try:
            exif = dict((ExifTags.TAGS[k], v) for k, v in im._getexif().items() if k in ExifTags.TAGS)
            angles = {3: 180, 6: 270, 8: 90}
            orientation = exif['Orientation']
            if orientation in angles.keys():
                im = im.rotate(angles[orientation], expand=True)
        except (AttributeError, KeyError):
            pass  # no EXIF data available

        # Big image
        im.thumbnail((540, 540), Image.ANTIALIAS)
        imgByteArr = io.BytesIO()
        im.save(imgByteArr, format='JPEG2000')
        file_icon = imgByteArr.getvalue()

        # Small image
        # im.thumbnail((64, 64), Image.ANTIALIAS)
        # imgByteArr = io.BytesIO()
        # im.save(imgByteArr, format='JPEG2000')
        # small_file_icon = imgByteArr.getvalue()

        return file_icon

    @staticmethod
    def get_ip_for_interface(interface_name, ipv6=False):
        """
        Get the ip address in IPv4 or IPv6 for a specific network interface

        :param str interface_name: declares the network interface name for which the ip should be accessed
        :param bool ipv6: Boolean indicating if the ipv6 address should be retrieved
        :return: IPv4Address or IPv6Address object or None
        """
        def get_interface_by_name(name):
            for interface in ifaddr.get_adapters():
                if interface.name == name:
                    return interface
            return None

        interface = get_interface_by_name(interface_name)
        if interface is None:
            return None

        for ip in interface.ips:
            if ip.is_IPv6 and ipv6:
                return ipaddress.IPv6Address(ip.ip[0])  # first of (ip, flowinfo, scope_id) tuple
            if ip.is_IPv4 and not ipv6:
                return ipaddress.IPv4Address(ip.ip)

        return None

    @staticmethod
    def write_debug(config, data, file_name):
        if not config.debug:
            return
        if not os.path.exists(config.debug_dir):
            os.makedirs(config.debug_dir)
        debug_file_path = os.path.join(config.debug_dir, file_name)
        with open(debug_file_path, 'wb') as file:
            if hasattr(data, 'read'):
                file.write(data.read())
                data.seek(0)  # reset cursor position
            else:  # assume bytes-like
                file.write(data)


class AbsArchiveWrite(ArchiveWrite):
    def add_abs_file(self, path, store_path):
        """
        Read the given paths from disk and add them to the archive.
        """
        write_p = self._pointer

        block_size = ffi.write_get_bytes_per_block(write_p)
        if block_size <= 0:
            block_size = 10240  # pragma: no cover

        with new_archive_entry() as entry_p:
            entry = ArchiveEntry(None, entry_p)
            with new_archive_read_disk(path) as read_p:
                while True:
                    r = read_next_header2(read_p, entry_p)
                    if r == ARCHIVE_EOF:
                        break
                    entry.pathname = store_path
                    read_disk_descend(read_p)
                    write_header(write_p, entry_p)
                    try:
                        with open(entry_sourcepath(entry_p), 'rb') as f:
                            while True:
                                data = f.read(block_size)
                                if not data:
                                    break
                                write_data(write_p, data, len(data))
                    except IOError as e:
                        if e.errno != 21:
                            raise  # pragma: no cover
                    write_finish_entry(write_p)
                    entry_clear(entry_p)
                    if os.path.isdir(path):
                        break
