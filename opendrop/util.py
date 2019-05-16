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

import netifaces

import base64
import datetime
import io
import ipaddress
import os
import platform
import plistlib
import socket
from Crypto.Hash import SHA, SHA256
from PIL import Image, ExifTags
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
if platform.system() == 'Darwin' and os.getenv('LIBCRYPTO') is not None:
    import ctypescrypto
    from ctypes import CDLL, c_uint64, c_void_p
    ctypescrypto.__libname__ = os.environ['LIBCRYPTO']
    ctypescrypto.libcrypto = CDLL(ctypescrypto.__libname__)
    if hasattr(ctypescrypto.libcrypto,'OPENSSL_init_crypto'):
        ctypescrypto.libcrypto.OPENSSL_init_crypto.argtypes = (c_uint64,c_void_p)
        ctypescrypto.libcrypto.OPENSSL_init_crypto(2+4+8+0x40,None)
        strings_loaded = True
    else:
        ctypescrypto.libcrypto.OPENSSL_add_all_algorithms_conf()
        strings_loaded = False
from ctypescrypto import cms, x509, pkey, oid


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

        emails_hashed = [SHA256.new(email.encode('utf-8')).hexdigest() for email in config.email]
        phone_numbers_hashed = [SHA256.new(phone_number.encode('utf-8')).hexdigest() for phone_number in config.phone]

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
                cms_signed = cms.SignedData.create(record_data_plist, cert=cert, pkey=key, certs=None,
                                                   flags=cms.Flags.PARTIAL)
                signed_data = AirDropUtil.pem2der(cms_signed.pem())

        return signed_data

    @staticmethod
    def doubleSHA1Hash(toHash):
        """
        This method gets an array of strings as input and creates a double SHA-1 Hash formatted in BASE64 from it. 
        It will return a comma seperated list of SHA-1 hashes in BASE64

        :param toHash: An iterable which contains one or many str 
        """

        single_hashed = [SHA.new(to_hash.encode('utf-8')).digest() for to_hash in toHash]
        double_hashed = [SHA.new(single).digest() for single in single_hashed]

        double_hashed_base64 = [base64.b64encode(h).decode('utf-8') for h in double_hashed]
        hash_string = ','.join(double_hashed_base64)

        return hash_string

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
        except AttributeError:
            pass  # no EXIF data available

        # Big image
        im.thumbnail((540, 540), Image.ANTIALIAS)
        imgByteArr = io.BytesIO()
        im.save(imgByteArr, format='JPEG2000')
        file_icon = imgByteArr.getvalue()

        # Small image
        #im.thumbnail((64, 64), Image.ANTIALIAS)
        #imgByteArr = io.BytesIO()
        #im.save(imgByteArr, format='JPEG2000')
        #small_file_icon = imgByteArr.getvalue()

        return file_icon


    @staticmethod
    def get_ip_for_interface(interface_name, ipv6=False):
        """
        Get the ip address in IPv4 or IPv6 for a specific network interface

        :param str interace_name: declares the network interface name for which the ip should be accessed
        :param bool ipv6: Boolean indicating if the ipv6 address should be rertrieved
        :return: (str ipaddress, byte ipaddress_bytes) returns a tuple with the ip address as a string and in bytes
        """
        addresses = netifaces.ifaddresses(interface_name)

        if netifaces.AF_INET6 in addresses and ipv6:
            # Use the normal ipv6 address
            addr = addresses[netifaces.AF_INET6][0]['addr'].split('%')[0]
            bytes_addr = ipaddress.IPv6Address(addr).packed
        elif netifaces.AF_INET in addresses and not ipv6:
            addr = addresses[netifaces.AF_INET][0]['addr']
            bytes_addr = socket.inet_aton(addr)
        else:
            addr = None
            bytes_addr = None

        return addr, bytes_addr

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
                while 1:
                    r = read_next_header2(read_p, entry_p)
                    if r == ARCHIVE_EOF:
                        break
                    entry.pathname = store_path
                    read_disk_descend(read_p)
                    write_header(write_p, entry_p)
                    try:
                        with open(entry_sourcepath(entry_p), 'rb') as f:
                            while 1:
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
