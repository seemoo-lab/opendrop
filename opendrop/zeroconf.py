""" Multicast DNS Service Discovery for Python, v0.14-wmcbrine
    Copyright 2003 Paul Scott-Murphy, 2014 William McBrine

    This module provides a framework for the use of DNS Service Discovery
    using IP multicast.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
    USA
"""

import enum
import errno
import logging
import re
import select
import socket
import struct
import sys
import platform
import threading
import time
from functools import reduce

import netifaces

__author__ = 'Paul Scott-Murphy, William McBrine'
__maintainer__ = 'Jakub Stasiak <jakub@stasiak.at>'
__version__ = '0.20.0'
__license__ = 'LGPL'


__all__ = [
    "__version__",
    "Zeroconf", "ServiceInfo", "ServiceBrowser",
    "Error", "InterfaceChoice", "ServiceStateChange",
]


consoleHandler = logging.StreamHandler()
log = logging.getLogger(__name__)
log.addHandler(consoleHandler)

if log.level == logging.NOTSET:
    log.setLevel(logging.INFO)

# Some timing constants

_UNREGISTER_TIME = 125
_CHECK_TIME = 175
_REGISTER_TIME = 225
_LISTENER_TIME = 200
_BROWSER_TIME = 500

# Some DNS constants

_MDNS_ADDR = '224.0.0.251'
_MDNS_ADDR_IPV6 = 'ff02::fb'
_MDNS_PORT = 5353
_DNS_PORT = 53
_DNS_TTL = 65536 #60 * 60  # one hour default TTL

_MAX_MSG_TYPICAL = 1460  # unused
_MAX_MSG_ABSOLUTE = 8966

_FLAGS_QR_MASK = 0x8000  # query response mask
_FLAGS_QR_QUERY = 0x0000  # query
_FLAGS_QR_RESPONSE = 0x8000  # response

_FLAGS_AA = 0x0400  # Authoritative answer
_FLAGS_TC = 0x0200  # Truncated
_FLAGS_RD = 0x0100  # Recursion desired
_FLAGS_RA = 0x8000  # Recursion available

_FLAGS_Z = 0x0040  # Zero
_FLAGS_AD = 0x0020  # Authentic data
_FLAGS_CD = 0x0010  # Checking disabled

_CLASS_IN = 1
_CLASS_CS = 2
_CLASS_CH = 3
_CLASS_HS = 4
_CLASS_NONE = 254
_CLASS_ANY = 255
_CLASS_MASK = 0x7FFF
_CLASS_UNIQUE = 0x8000

_TYPE_A = 1
_TYPE_NS = 2
_TYPE_MD = 3
_TYPE_MF = 4
_TYPE_CNAME = 5
_TYPE_SOA = 6
_TYPE_MB = 7
_TYPE_MG = 8
_TYPE_MR = 9
_TYPE_NULL = 10
_TYPE_WKS = 11
_TYPE_PTR = 12
_TYPE_HINFO = 13
_TYPE_MINFO = 14
_TYPE_MX = 15
_TYPE_TXT = 16
_TYPE_AAAA = 28
_TYPE_SRV = 33
_TYPE_ANY = 255
_TYPE_NSEC = 47

# Mapping constants to names

_CLASSES = {_CLASS_IN: "in",
            _CLASS_CS: "cs",
            _CLASS_CH: "ch",
            _CLASS_HS: "hs",
            _CLASS_NONE: "none",
            _CLASS_ANY: "any"}

_TYPES = {_TYPE_A: "a",
          _TYPE_NS: "ns",
          _TYPE_MD: "md",
          _TYPE_MF: "mf",
          _TYPE_CNAME: "cname",
          _TYPE_SOA: "soa",
          _TYPE_MB: "mb",
          _TYPE_MG: "mg",
          _TYPE_MR: "mr",
          _TYPE_NULL: "null",
          _TYPE_WKS: "wks",
          _TYPE_PTR: "ptr",
          _TYPE_HINFO: "hinfo",
          _TYPE_MINFO: "minfo",
          _TYPE_MX: "mx",
          _TYPE_TXT: "txt",
          _TYPE_AAAA: "quada",
          _TYPE_SRV: "srv",
          _TYPE_ANY: "any"}

_HAS_A_TO_Z = re.compile(r'[A-Za-z]')
_HAS_ONLY_A_TO_Z_NUM_HYPHEN = re.compile(r'^[A-Za-z0-9\-]+$')
_HAS_ASCII_CONTROL_CHARS = re.compile(r'[\x00-\x1f\x7f]')

int2byte = struct.Struct(">B").pack


@enum.unique
class InterfaceChoice(enum.Enum):
    Default = 1
    All = 2


@enum.unique
class ServiceStateChange(enum.Enum):
    Added = 1
    Removed = 2


HOST_ONLY_NETWORK_MASK = '255.255.255.255'


# utility functions


def current_time_millis():
    """Current system time in milliseconds"""
    return time.time() * 1000


def service_type_name(type_):
    """
    Validate a fully qualified service name, instance or subtype. [rfc6763]

    Returns fully qualified service name.

    Domain names used by mDNS-SD take the following forms:

                   <sn> . <_tcp|_udp> . local.
      <Instance> . <sn> . <_tcp|_udp> . local.
      <sub>._sub . <sn> . <_tcp|_udp> . local.

    1) must end with 'local.'

      This is true because we are implementing mDNS and since the 'm' means
      multi-cast, the 'local.' domain is mandatory.

    2) local is preceded with either '_udp.' or '_tcp.'

    3) service name <sn> precedes <_tcp|_udp>

      The rules for Service Names [RFC6335] state that they may be no more
      than fifteen characters long (not counting the mandatory underscore),
      consisting of only letters, digits, and hyphens, must begin and end
      with a letter or digit, must not contain consecutive hyphens, and
      must contain at least one letter.

    The instance name <Instance> and sub type <sub> may be up to 63 bytes.

    The portion of the Service Instance Name is a user-
    friendly name consisting of arbitrary Net-Unicode text [RFC5198]. It
    MUST NOT contain ASCII control characters (byte values 0x00-0x1F and
    0x7F) [RFC20] but otherwise is allowed to contain any characters,
    without restriction, including spaces, uppercase, lowercase,
    punctuation -- including dots -- accented characters, non-Roman text,
    and anything else that may be represented using Net-Unicode.

    :param type_: Type, SubType or service name to validate
    :return: fully qualified service name (eg: _http._tcp.local.)
    """
    if not (type_.endswith('._tcp.local.') or type_.endswith('._udp.local.')):
        raise BadTypeInNameException(
            "Type '%s' must end with '._tcp.local.' or '._udp.local.'" %
            type_)

    remaining = type_[:-len('._tcp.local.')].split('.')
    name = remaining.pop()
    if not name:
        raise BadTypeInNameException("No Service name found")

    if len(remaining) == 1 and len(remaining[0]) == 0:
        raise BadTypeInNameException(
            "Type '%s' must not start with '.'" % type_)

    if name[0] != '_':
        raise BadTypeInNameException(
            "Service name (%s) must start with '_'" % name)

    # remove leading underscore
    name = name[1:]

    if len(name) > 15:
        raise BadTypeInNameException(
            "Service name (%s) must be <= 15 bytes" % name)

    if '--' in name:
        raise BadTypeInNameException(
            "Service name (%s) must not contain '--'" % name)

    if '-' in (name[0], name[-1]):
        raise BadTypeInNameException(
            "Service name (%s) may not start or end with '-'" % name)

    if not _HAS_A_TO_Z.search(name):
        raise BadTypeInNameException(
            "Service name (%s) must contain at least one letter (eg: 'A-Z')" %
            name)

    if not _HAS_ONLY_A_TO_Z_NUM_HYPHEN.search(name):
        raise BadTypeInNameException(
            "Service name (%s) must contain only these characters: "
            "A-Z, a-z, 0-9, hyphen ('-')" % name)

    if remaining and remaining[-1] == '_sub':
        remaining.pop()
        if len(remaining) == 0 or len(remaining[0]) == 0:
            raise BadTypeInNameException(
                "_sub requires a subtype name")

    if len(remaining) > 1:
        remaining = ['.'.join(remaining)]

    if remaining:
        length = len(remaining[0].encode('utf-8'))
        if length > 63:
            raise BadTypeInNameException("Too long: '%s'" % remaining[0])

        if _HAS_ASCII_CONTROL_CHARS.search(remaining[0]):
            raise BadTypeInNameException(
                "Ascii control character 0x00-0x1F and 0x7F illegal in '%s'" %
                remaining[0])

    return '_' + name + type_[-len('._tcp.local.'):]


# Exceptions


class Error(Exception):
    pass


class IncomingDecodeError(Error):
    pass


class NonUniqueNameException(Error):
    pass


class NamePartTooLongException(Error):
    pass


class AbstractMethodException(Error):
    pass


class BadTypeInNameException(Error):
    pass

# implementation classes


class QuietLogger:
    _seen_logs = {}

    @classmethod
    def log_exception_warning(cls, logger_data=None):
        exc_info = sys.exc_info()
        exc_str = str(exc_info[1])
        if exc_str not in cls._seen_logs:
            # log at warning level the first time this is seen
            cls._seen_logs[exc_str] = exc_info
            logger = log.warning
        else:
            logger = log.debug
        if logger_data is not None:
            logger(*logger_data)
        logger('Exception occurred:', exc_info=exc_info)

    @classmethod
    def log_warning_once(cls, *args):
        msg_str = args[0]
        if msg_str not in cls._seen_logs:
            cls._seen_logs[msg_str] = 0
            logger = log.warning
        else:
            logger = log.debug
        cls._seen_logs[msg_str] += 1
        logger(*args)


class DNSEntry:

    """A DNS entry"""

    def __init__(self, name, type_, class_):
        self.key = name.lower()
        self.name = name
        self.type = type_
        self.class_ = class_ & _CLASS_MASK
        self.unique = (class_ & _CLASS_UNIQUE) != 0

    def __eq__(self, other):
        """Equality test on name, type, and class"""
        return (isinstance(other, DNSEntry) and
                self.name.lower() == other.name.lower() and
                self.type == other.type and
                self.class_ == other.class_)

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    @staticmethod
    def get_class_(class_):
        """Class accessor"""
        return _CLASSES.get(class_, "?(%s)" % class_)

    @staticmethod
    def get_type(t):
        """Type accessor"""
        return _TYPES.get(t, "?(%s)" % t)

    def to_string(self, hdr, other):
        """String representation with additional information"""
        result = "%s[%s,%s" % (hdr, self.get_type(self.type),
                               self.get_class_(self.class_))
        if self.unique:
            result += "-unique,"
        else:
            result += ","
        result += self.name
        if other is not None:
            result += ",%s]" % other
        else:
            result += "]"
        return result


class DNSQuestion(DNSEntry):

    """A DNS question entry"""

    def __init__(self, name, type_, class_):
        DNSEntry.__init__(self, name, type_, class_)

    def answered_by(self, rec):
        """Returns true if the question is answered by the record"""
        return (self.class_ == rec.class_ and
                (self.type == rec.type or self.type == _TYPE_ANY) and
                self.name == rec.name)

    def __repr__(self):
        """String representation"""
        return DNSEntry.to_string(self, "question", None)


class DNSRecord(DNSEntry):

    """A DNS record - like a DNS entry, but has a TTL"""

    def __init__(self, name, type_, class_, ttl):
        DNSEntry.__init__(self, name, type_, class_)
        self.ttl = ttl
        self.created = current_time_millis()

    def __eq__(self, other):
        """Abstract method"""
        raise AbstractMethodException

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    def suppressed_by(self, msg):
        """Returns true if any answer in a message can suffice for the
        information held in this record."""
        for record in msg.answers:
            if self.suppressed_by_answer(record):
                return True
        return False

    def suppressed_by_answer(self, other):
        """Returns true if another record has same name, type and class,
        and if its TTL is at least half of this record's."""
        return self == other and other.ttl > (self.ttl / 2)

    def get_expiration_time(self, percent):
        """Returns the time at which this record will have expired
        by a certain percentage."""
        return self.created + (percent * self.ttl * 10)

    def get_remaining_ttl(self, now):
        """Returns the remaining TTL in seconds."""
        return max(0, (self.get_expiration_time(100) - now) / 1000.0)

    def is_expired(self, now):
        """Returns true if this record has expired."""
        return self.get_expiration_time(100) <= now

    def is_stale(self, now):
        """Returns true if this record is at least half way expired."""
        return self.get_expiration_time(50) <= now

    def reset_ttl(self, other):
        """Sets this record's TTL and created time to that of
        another record."""
        self.created = other.created
        self.ttl = other.ttl

    def write(self, out):
        """Abstract method"""
        raise AbstractMethodException

    def to_string(self, other):
        """String representation with additional information"""
        arg = "%s/%s,%s" % (
            self.ttl, self.get_remaining_ttl(current_time_millis()), other)
        return DNSEntry.to_string(self, "record", arg)


class DNSAddress(DNSRecord):

    """A DNS address record"""

    def __init__(self, name, type_, class_, ttl, address):
        DNSRecord.__init__(self, name, type_, class_, ttl)
        self.address = address

    def write(self, out):
        """Used in constructing an outgoing packet"""
        out.write_string(self.address)

    def __eq__(self, other):
        """Tests equality on address"""
        return (isinstance(other, DNSAddress) and DNSEntry.__eq__(self, other) and
                self.address == other.address)

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self):
        """String representation"""
        try:
            return str(socket.inet_ntoa(self.address))
        except Exception:  # TODO stop catching all Exceptions
            return str(self.address)


class DNSHinfo(DNSRecord):

    """A DNS host information record"""

    def __init__(self, name, type_, class_, ttl, cpu, os):
        DNSRecord.__init__(self, name, type_, class_, ttl)
        try:
            self.cpu = cpu.decode('utf-8')
        except AttributeError:
            self.cpu = cpu
        try:
            self.os = os.decode('utf-8')
        except AttributeError:
            self.os = os

    def write(self, out):
        """Used in constructing an outgoing packet"""
        out.write_character_string(self.cpu.encode('utf-8'))
        out.write_character_string(self.os.encode('utf-8'))

    def __eq__(self, other):
        """Tests equality on cpu and os"""
        return (isinstance(other, DNSHinfo) and DNSEntry.__eq__(self, other) and
                self.cpu == other.cpu and self.os == other.os)

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self):
        """String representation"""
        return self.cpu + " " + self.os


class DNSPointer(DNSRecord):

    """A DNS pointer record"""

    def __init__(self, name, type_, class_, ttl, alias):
        DNSRecord.__init__(self, name, type_, class_, ttl)
        self.alias = alias

    def write(self, out):
        """Used in constructing an outgoing packet"""
        out.write_name(self.alias)

    def __eq__(self, other):
        """Tests equality on alias"""
        return (isinstance(other, DNSPointer) and DNSEntry.__eq__(self, other) and
                self.alias == other.alias)

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self):
        """String representation"""
        return self.to_string(self.alias)


class DNSText(DNSRecord):

    """A DNS text record"""

    def __init__(self, name, type_, class_, ttl, text):
        assert isinstance(text, (bytes, type(None)))
        DNSRecord.__init__(self, name, type_, class_, ttl)
        self.text = text

    def write(self, out):
        """Used in constructing an outgoing packet"""
        out.write_string(self.text)

    def __eq__(self, other):
        """Tests equality on text"""
        return (isinstance(other, DNSText) and DNSEntry.__eq__(self, other) and
                self.text == other.text)

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self):
        """String representation"""
        if len(self.text) > 10:
            return self.to_string(self.text[:7]) + "..."
        else:
            return self.to_string(self.text)


class DNSService(DNSRecord):

    """A DNS service record"""

    def __init__(self, name, type_, class_, ttl,
                 priority, weight, port, server):
        DNSRecord.__init__(self, name, type_, class_, ttl)
        self.priority = priority
        self.weight = weight
        self.port = port
        self.server = server

    def write(self, out):
        """Used in constructing an outgoing packet"""
        out.write_short(self.priority)
        out.write_short(self.weight)
        out.write_short(self.port)
        out.write_name(self.server)

    def __eq__(self, other):
        """Tests equality on priority, weight, port and server"""
        return (isinstance(other, DNSService) and
                DNSEntry.__eq__(self, other) and
                self.priority == other.priority and
                self.weight == other.weight and
                self.port == other.port and
                self.server == other.server)

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self):
        """String representation"""
        return self.to_string("%s:%s" % (self.server, self.port))


class DNSIncoming(QuietLogger):

    """Object representation of an incoming DNS packet"""

    def __init__(self, data):
        """Constructor from string holding bytes of packet"""
        self.offset = 0
        self.data = data
        self.questions = []
        self.answers = []
        self.id = 0
        self.flags = 0
        self.num_questions = 0
        self.num_answers = 0
        self.num_authorities = 0
        self.num_additionals = 0
        self.valid = False

        try:
            self.read_header()
            self.read_questions()
            self.read_others()
            self.valid = True

        except (IndexError, struct.error, IncomingDecodeError):
            self.log_exception_warning((
                'Choked at offset %d while unpacking %r', self.offset, data))

    def unpack(self, format_):
        length = struct.calcsize(format_)
        info = struct.unpack(
            format_, self.data[self.offset:self.offset + length])
        self.offset += length
        return info

    def read_header(self):
        """Reads header portion of packet"""
        (self.id, self.flags, self.num_questions, self.num_answers,
         self.num_authorities, self.num_additionals) = self.unpack(b'!6H')

    def read_questions(self):
        """Reads questions section of packet"""
        for i in range(self.num_questions):
            name = self.read_name()
            type_, class_ = self.unpack(b'!HH')

            question = DNSQuestion(name, type_, class_)
            self.questions.append(question)

    # def read_int(self):
    #     """Reads an integer from the packet"""
    #     return self.unpack(b'!I')[0]

    def read_character_string(self):
        """Reads a character string from the packet"""
        length = self.data[self.offset]
        self.offset += 1
        return self.read_string(length)

    def read_string(self, length):
        """Reads a string of a given length from the packet"""
        info = self.data[self.offset:self.offset + length]
        self.offset += length
        return info

    def read_unsigned_short(self):
        """Reads an unsigned short from the packet"""
        return self.unpack(b'!H')[0]

    def read_others(self):
        """Reads the answers, authorities and additionals section of the
        packet"""
        n = self.num_answers + self.num_authorities + self.num_additionals
        for i in range(n):
            domain = self.read_name()
            type_, class_, ttl, length = self.unpack(b'!HHiH')

            rec = None
            if type_ == _TYPE_A:
                rec = DNSAddress(
                    domain, type_, class_, ttl, self.read_string(4))
            elif type_ == _TYPE_CNAME or type_ == _TYPE_PTR:
                rec = DNSPointer(
                    domain, type_, class_, ttl, self.read_name())
            elif type_ == _TYPE_TXT:
                rec = DNSText(
                    domain, type_, class_, ttl, self.read_string(length))
            elif type_ == _TYPE_SRV:
                rec = DNSService(
                    domain, type_, class_, ttl,
                    self.read_unsigned_short(), self.read_unsigned_short(),
                    self.read_unsigned_short(), self.read_name())
            elif type_ == _TYPE_HINFO:
                rec = DNSHinfo(
                    domain, type_, class_, ttl,
                    self.read_character_string(), self.read_character_string())
            elif type_ == _TYPE_AAAA:
                rec = DNSAddress(
                    domain, type_, class_, ttl, self.read_string(16))
            else:
                # Try to ignore types we don't know about
                # Skip the payload for the resource record so the next
                # records can be parsed correctly
                self.offset += length

            if rec is not None:
                self.answers.append(rec)

    def is_query(self):
        """Returns true if this is a query"""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_QUERY

    def is_response(self):
        """Returns true if this is a response"""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_RESPONSE

    def read_utf(self, offset, length):
        """Reads a UTF-8 string of a given length from the packet"""
        return str(self.data[offset:offset + length], 'utf-8', 'replace')

    def read_name(self):
        """Reads a domain name from the packet"""
        result = ''
        off = self.offset
        next_ = -1
        first = off

        while True:
            length = self.data[off]
            off += 1
            if length == 0:
                break
            t = length & 0xC0
            if t == 0x00:
                result = ''.join((result, self.read_utf(off, length) + '.'))
                off += length
            elif t == 0xC0:
                if next_ < 0:
                    next_ = off + 1
                off = ((length & 0x3F) << 8) | self.data[off]
                if off >= first:
                    raise IncomingDecodeError(
                        "Bad domain name (circular) at %s" % (off,))
                first = off
            else:
                raise IncomingDecodeError("Bad domain name at %s" % (off,))

        if next_ >= 0:
            self.offset = next_
        else:
            self.offset = off

        return result


class DNSOutgoing:

    """Object representation of an outgoing packet"""

    def __init__(self, flags, multicast=True):
        self.finished = False
        self.id = 0
        self.multicast = multicast
        self.flags = flags
        self.names = {}
        self.data = []
        self.size = 12
        self.state = self.State.init

        self.questions = []
        self.answers = []
        self.authorities = []
        self.additionals = []

    def __repr__(self):
        return '<DNSOutgoing:{%s}>' % ', '.join([
            'multicast=%s' % self.multicast,
            'flags=%s' % self.flags,
            'questions=%s' % self.questions,
            'answers=%s' % self.answers,
            'authorities=%s' % self.authorities,
            'additionals=%s' % self.additionals,
        ])

    class State(enum.Enum):
        init = 0
        finished = 1

    def add_question(self, record):
        """Adds a question"""
        self.questions.append(record)

    def add_answer(self, inp, record):
        """Adds an answer"""
        if not record.suppressed_by(inp):
            self.add_answer_at_time(record, 0)

    def add_answer_at_time(self, record, now):
        """Adds an answer if it does not expire by a certain time"""
        if record is not None:
            if now == 0 or not record.is_expired(now):
                self.answers.append((record, now))

    def add_authorative_answer(self, record):
        """Adds an authoritative answer"""
        self.authorities.append(record)

    def add_additional_answer(self, record):
        """ Adds an additional answer

        From: RFC 6763, DNS-Based Service Discovery, February 2013

        12.  DNS Additional Record Generation

           DNS has an efficiency feature whereby a DNS server may place
           additional records in the additional section of the DNS message.
           These additional records are records that the client did not
           explicitly request, but the server has reasonable grounds to expect
           that the client might request them shortly, so including them can
           save the client from having to issue additional queries.

           This section recommends which additional records SHOULD be generated
           to improve network efficiency, for both Unicast and Multicast DNS-SD
           responses.

        12.1.  PTR Records

           When including a DNS-SD Service Instance Enumeration or Selective
           Instance Enumeration (subtype) PTR record in a response packet, the
           server/responder SHOULD include the following additional records:

           o  The SRV record(s) named in the PTR rdata.
           o  The TXT record(s) named in the PTR rdata.
           o  All address records (type "A" and "AAAA") named in the SRV rdata.

        12.2.  SRV Records

           When including an SRV record in a response packet, the
           server/responder SHOULD include the following additional records:

           o  All address records (type "A" and "AAAA") named in the SRV rdata.

        """
        self.additionals.append(record)

    def pack(self, format_, value):
        self.data.append(struct.pack(format_, value))
        self.size += struct.calcsize(format_)

    def write_byte(self, value):
        """Writes a single byte to the packet"""
        self.pack(b'!c', int2byte(value))

    def insert_short(self, index, value):
        """Inserts an unsigned short in a certain position in the packet"""
        self.data.insert(index, struct.pack(b'!H', value))
        self.size += 2

    def write_short(self, value):
        """Writes an unsigned short to the packet"""
        self.pack(b'!H', value)

    def write_int(self, value):
        """Writes an unsigned integer to the packet"""
        self.pack(b'!I', int(value))

    def write_string(self, value):
        """Writes a string to the packet"""
        assert isinstance(value, bytes)
        self.data.append(value)
        self.size += len(value)

    def write_utf(self, s):
        """Writes a UTF-8 string of a given length to the packet"""
        utfstr = s.encode('utf-8')
        length = len(utfstr)
        if length > 64:
            raise NamePartTooLongException
        self.write_byte(length)
        self.write_string(utfstr)

    def write_character_string(self, value):
        assert isinstance(value, bytes)
        length = len(value)
        if length > 256:
            raise NamePartTooLongException
        self.write_byte(length)
        self.write_string(value)

    def write_name(self, name):
        """
        Write names to packet

        18.14. Name Compression

        When generating Multicast DNS messages, implementations SHOULD use
        name compression wherever possible to compress the names of resource
        records, by replacing some or all of the resource record name with a
        compact two-byte reference to an appearance of that data somewhere
        earlier in the message [RFC1035].
        """

        # split name into each label
        parts = name.split('.')
        if not parts[-1]:
            parts.pop()

        # construct each suffix
        name_suffices = ['.'.join(parts[i:]) for i in range(len(parts))]

        # look for an existing name or suffix
        for count, sub_name in enumerate(name_suffices):
            if sub_name in self.names:
                break
        else:
            count += 1

        # note the new names we are saving into the packet
        for suffix in name_suffices[:count]:
            self.names[suffix] = self.size + len(name) - len(suffix) - 1

        # write the new names out.
        for part in parts[:count]:
            self.write_utf(part)

        # if we wrote part of the name, create a pointer to the rest
        if count != len(name_suffices):
            # Found substring in packet, create pointer
            index = self.names[name_suffices[count]]
            self.write_byte((index >> 8) | 0xC0)
            self.write_byte(index & 0xFF)
        else:
            # this is the end of a name
            self.write_byte(0)

    def write_question(self, question):
        """Writes a question to the packet"""
        self.write_name(question.name)
        self.write_short(question.type)
        self.write_short(question.class_)

    def write_record(self, record, now):
        """Writes a record (answer, authoritative answer, additional) to
        the packet"""
        if self.state == self.State.finished:
            return 1

        start_data_length, start_size = len(self.data), self.size
        self.write_name(record.name)
        self.write_short(record.type)
        if record.unique and self.multicast:
            self.write_short(record.class_ | _CLASS_UNIQUE)
        else:
            self.write_short(record.class_)
        if now == 0:
            self.write_int(record.ttl)
        else:
            self.write_int(record.get_remaining_ttl(now))
        index = len(self.data)

        # Adjust size for the short we will write before this record
        self.size += 2
        record.write(self)
        self.size -= 2

        length = sum((len(d) for d in self.data[index:]))
        # Here is the short we adjusted for
        self.insert_short(index, length)

        # if we go over, then rollback and quit
        if self.size > _MAX_MSG_ABSOLUTE:
            while len(self.data) > start_data_length:
                self.data.pop()
            self.size = start_size
            self.state = self.State.finished
            return 1
        return 0

    def packet(self):
        """Returns a string containing the packet's bytes

        No further parts should be added to the packet once this
        is done."""

        overrun_answers, overrun_authorities, overrun_additionals = 0, 0, 0

        if self.state != self.State.finished:
            for question in self.questions:
                self.write_question(question)
            for answer, time_ in self.answers:
                overrun_answers += self.write_record(answer, time_)
            for authority in self.authorities:
                overrun_authorities += self.write_record(authority, 0)
            for additional in self.additionals:
                overrun_additionals += self.write_record(additional, 0)
            self.state = self.State.finished

            self.insert_short(0, len(self.additionals) - overrun_additionals)
            self.insert_short(0, len(self.authorities) - overrun_authorities)
            self.insert_short(0, len(self.answers) - overrun_answers)
            self.insert_short(0, len(self.questions))
            self.insert_short(0, self.flags)
            if self.multicast:
                self.insert_short(0, 0)
            else:
                self.insert_short(0, self.id)
        return b''.join(self.data)


class DNSCache:

    """A cache of DNS entries"""

    def __init__(self):
        self.cache = {}

    def add(self, entry):
        """Adds an entry"""
        # Insert first in list so get returns newest entry
        self.cache.setdefault(entry.key, []).insert(0, entry)

    def remove(self, entry):
        """Removes an entry"""
        try:
            list_ = self.cache[entry.key]
            list_.remove(entry)
        except (KeyError, ValueError):
            pass

    def get(self, entry):
        """Gets an entry by key.  Will return None if there is no
        matching entry."""
        try:
            list_ = self.cache[entry.key]
            for cached_entry in list_:
                if entry.__eq__(cached_entry):
                    return cached_entry
        except (KeyError, ValueError):
            return None

    def get_by_details(self, name, type_, class_):
        """Gets an entry by details.  Will return None if there is
        no matching entry."""
        entry = DNSEntry(name, type_, class_)
        return self.get(entry)

    def entries_with_name(self, name):
        """Returns a list of entries whose key matches the name."""
        try:
            return self.cache[name.lower()]
        except KeyError:
            return []

    def current_entry_with_name_and_alias(self, name, alias):
        now = current_time_millis()
        for record in self.entries_with_name(name):
            if (record.type == _TYPE_PTR and
                    not record.is_expired(now) and
                    record.alias == alias):
                return record

    def entries(self):
        """Returns a list of all entries"""
        if not self.cache:
            return []
        else:
            # avoid size change during iteration by copying the cache
            values = list(self.cache.values())
            return reduce(lambda a, b: a + b, values)


class Engine(threading.Thread):

    """An engine wraps read access to sockets, allowing objects that
    need to receive data from sockets to be called back when the
    sockets are ready.

    A reader needs a handle_read() method, which is called when the socket
    it is interested in is ready for reading.

    Writers are not implemented here, because we only send short
    packets.
    """

    def __init__(self, zc):
        threading.Thread.__init__(self, name='zeroconf-Engine')
        self.daemon = True
        self.zc = zc
        self.readers = {}  # maps socket to reader
        self.timeout = 5
        self.condition = threading.Condition()
        self.start()

    def run(self):
        while not self.zc.done:
            with self.condition:
                rs = self.readers.keys()
                if len(rs) == 0:
                    # No sockets to manage, but we wait for the timeout
                    # or addition of a socket
                    self.condition.wait(self.timeout)

            if len(rs) != 0:
                try:
                    rr, wr, er = select.select(rs, [], [], self.timeout)
                    if not self.zc.done:
                        for socket_ in rr:
                            reader = self.readers.get(socket_)
                            if reader:
                                reader.handle_read(socket_)

                except (select.error, socket.error) as e:
                    # If the socket was closed by another thread, during
                    # shutdown, ignore it and exit
                    if e.args[0] != socket.EBADF or not self.zc.done:
                        raise

    def add_reader(self, reader, socket_):
        with self.condition:
            self.readers[socket_] = reader
            self.condition.notify()

    def del_reader(self, socket_):
        with self.condition:
            del self.readers[socket_]
            self.condition.notify()


class Listener(QuietLogger):

    """A Listener is used by this module to listen on the multicast
    group to which DNS messages are sent, allowing the implementation
    to cache information as it arrives.

    It requires registration with an Engine object in order to have
    the read() method called when a socket is available for reading."""

    def __init__(self, zc):
        self.zc = zc
        self.data = None

    def handle_read(self, socket_):
        try:
            data, addr = socket_.recvfrom(_MAX_MSG_ABSOLUTE)
            port = addr[1]
            addr = addr[0]
        except Exception as exc:
            self.log_exception_warning()
            print("Exception raised", exc)
            return

        log.debug('Received from %r:%r: %r ', addr, port, data)

        self.data = data
        msg = DNSIncoming(data)
        if not msg.valid:
            pass

        elif msg.is_query():
            # Always multicast responses
            if port == _MDNS_PORT:
                if self.zc.address_family is socket.AF_INET6: 
                    self.zc.handle_query(msg, _MDNS_ADDR_IPV6, _MDNS_PORT)
                else: 
                    self.zc.handle_query(msg, _MDNS_ADDR, _MDNS_PORT)

            # If it's not a multicast query, reply via unicast
            # and multicast
            elif port == _DNS_PORT:
                if self.zc.address_family is socket.AF_INET6: 
                    self.zc.handle_query(msg, addr, port)
                    self.zc.handle_query(msg, _MDNS_ADDR_IPV6, _MDNS_PORT)
                else: 
                    self.zc.handle_query(msg, addr, port)
                    self.zc.handle_query(msg, _MDNS_ADDR, _MDNS_PORT)

        else:
            self.zc.handle_response(msg)


class Reaper(threading.Thread):

    """A Reaper is used by this module to remove cache entries that
    have expired."""

    def __init__(self, zc):
        threading.Thread.__init__(self, name='zeroconf-Reaper')
        self.daemon = True
        self.zc = zc
        self.start()

    def run(self):
        while True:
            self.zc.wait(10 * 1000)
            if self.zc.done:
                return
            now = current_time_millis()
            for record in self.zc.cache.entries():
                if record.is_expired(now):
                    self.zc.update_record(now, record)
                    self.zc.cache.remove(record)


class Signal:
    def __init__(self):
        self._handlers = []

    def fire(self, **kwargs):
        for h in list(self._handlers):
            h(**kwargs)

    @property
    def registration_interface(self):
        return SignalRegistrationInterface(self._handlers)


class SignalRegistrationInterface:

    def __init__(self, handlers):
        self._handlers = handlers

    def register_handler(self, handler):
        self._handlers.append(handler)
        return self

    def unregister_handler(self, handler):
        self._handlers.remove(handler)
        return self


class ServiceBrowser(threading.Thread):

    """Used to browse for a service of a specific type.

    The listener object will have its add_service() and
    remove_service() methods called when this browser
    discovers changes in the services availability."""

    def __init__(self, zc, type_, handlers=None, listener=None):
        """Creates a browser for a specific type"""
        assert handlers or listener, 'You need to specify at least one handler'
        if not type_.endswith(service_type_name(type_)):
            raise BadTypeInNameException
        threading.Thread.__init__(
            self, name='zeroconf-ServiceBrowser_' + type_)
        self.daemon = True
        self.zc = zc
        self.type = type_
        self.services = {}
        self.next_time = current_time_millis()
        self.delay = _BROWSER_TIME
        self._handlers_to_call = []

        self._service_state_changed = Signal()

        self.done = False

        if hasattr(handlers, 'add_service'):
            listener = handlers
            handlers = None

        handlers = handlers or []

        if listener:
            def on_change(zeroconf, service_type, name, state_change):
                args = (zeroconf, service_type, name)
                if state_change is ServiceStateChange.Added:
                    listener.add_service(*args)
                elif state_change is ServiceStateChange.Removed:
                    listener.remove_service(*args)
                else:
                    raise NotImplementedError(state_change)
            handlers.append(on_change)

        for h in handlers:
            self.service_state_changed.register_handler(h)

        self.start()

    @property
    def service_state_changed(self):
        return self._service_state_changed.registration_interface

    def update_record(self, zc, now, record):
        """Callback invoked by Zeroconf when new information arrives.

        Updates information required by browser in the Zeroconf cache."""

        def enqueue_callback(state_change, name):
            self._handlers_to_call.append(
                lambda zeroconf: self._service_state_changed.fire(
                    zeroconf=zeroconf,
                    service_type=self.type,
                    name=name,
                    state_change=state_change,
                ))

        if record.type == _TYPE_PTR and record.name == self.type:
            expired = record.is_expired(now)
            service_key = record.alias.lower()
            try:
                old_record = self.services[service_key]
            except KeyError:
                if not expired:
                    self.services[service_key] = record
                    enqueue_callback(ServiceStateChange.Added, record.alias)
            else:
                if not expired:
                    old_record.reset_ttl(record)
                else:
                    del self.services[service_key]
                    enqueue_callback(ServiceStateChange.Removed, record.alias)
                    return

            expires = record.get_expiration_time(75)
            if expires < self.next_time:
                self.next_time = expires

    def cancel(self):
        self.done = True
        self.zc.remove_listener(self)
        self.join()

    def run(self):
        self.zc.add_listener(self, DNSQuestion(self.type, _TYPE_PTR, _CLASS_IN))

        while True:
            now = current_time_millis()
            if len(self._handlers_to_call) == 0 and self.next_time > now:
                self.zc.wait(self.next_time - now)
            if self.zc.done or self.done:
                return
            now = current_time_millis()
            if self.next_time <= now:
                out = DNSOutgoing(_FLAGS_QR_QUERY)
                out.add_question(DNSQuestion(self.type, _TYPE_PTR, _CLASS_IN))
                for record in self.services.values():
                    if not record.is_stale(now):
                        out.add_answer_at_time(record, now)

                self.zc.send(out)
                self.next_time = now + self.delay
                self.delay = min(20 * 1000, self.delay * 2)

            if len(self._handlers_to_call) > 0 and not self.zc.done:
                handler = self._handlers_to_call.pop(0)
                handler(self.zc)


class ServiceInfo:

    """Service information"""

    def __init__(self, type_, name, address=None, port=None, weight=0,
                 priority=0, properties=None, server=None):
        """Create a service description.

        type_: fully qualified service type name
        name: fully qualified service name
        address: IP address as unsigned short, network byte order
        port: port that the service runs on
        weight: weight of the service
        priority: priority of the service
        properties: dictionary of properties (or a string holding the
                    bytes for the text field)
        server: fully qualified name for service host (defaults to name)"""

        if not type_.endswith(service_type_name(name)):
            raise BadTypeInNameException
        self.type = type_
        self.name = name
        self.address = address
        self.port = port
        self.weight = weight
        self.priority = priority
        if server:
            self.server = server
        else:
            self.server = name
        self._properties = {}
        self._set_properties(properties)

    @property
    def properties(self):
        return self._properties

    def _set_properties(self, properties):
        """Sets properties and text of this info from a dictionary"""
        if isinstance(properties, dict):
            self._properties = properties
            list_ = []
            result = b''
            for key, value in properties.items():
                if isinstance(key, str):
                    key = key.encode('utf-8')

                if value is None:
                    suffix = b''
                elif isinstance(value, str):
                    suffix = value.encode('utf-8')
                elif isinstance(value, bytes):
                    suffix = value
                elif isinstance(value, int):
                    if value:
                        suffix = b'true'
                    else:
                        suffix = b'false'
                else:
                    suffix = b''
                list_.append(b'='.join((key, suffix)))
            for item in list_:
                result = b''.join((result, int2byte(len(item)), item))
            self.text = result
        else:
            self.text = properties

    def _set_text(self, text):
        """Sets properties and text given a text field"""
        self.text = text
        result = {}
        end = len(text)
        index = 0
        strs = []
        while index < end:
            length = text[index]
            index += 1
            strs.append(text[index:index + length])
            index += length

        for s in strs:
            parts = s.split(b'=', 1)
            try:
                key, value = parts
            except ValueError:
                # No equals sign at all
                key = s
                value = False
            else:
                if value == b'true':
                    value = True
                elif value == b'false' or not value:
                    value = False

            # Only update non-existent properties
            if key and result.get(key) is None:
                result[key] = value

        self._properties = result

    def get_name(self):
        """Name accessor"""
        if self.type is not None and self.name.endswith("." + self.type):
            return self.name[:len(self.name) - len(self.type) - 1]
        return self.name

    def update_record(self, zc, now, record):
        """Updates service information from a DNS record"""
        if record is not None and not record.is_expired(now):
            if record.type == _TYPE_A or record.type == _TYPE_AAAA:
                # if record.name == self.name:
                if record.name == self.server:
                    self.address = record.address
            elif record.type == _TYPE_SRV:
                if record.name == self.name:
                    self.server = record.server
                    self.port = record.port
                    self.weight = record.weight
                    self.priority = record.priority
                    # self.address = None
                    update_type = _TYPE_A
                    if zc.address_family == socket.AF_INET6: 
                        update_type = _TYPE_AAAA

                    self.update_record(
                        zc, now, zc.cache.get_by_details(
                            self.server, update_type, _CLASS_IN))
            elif record.type == _TYPE_TXT:
                if record.name == self.name:
                    self._set_text(record.text)

    def request(self, zc, timeout):
        """Returns true if the service could be discovered on the
        network, and updates this object with details discovered.
        """
        now = current_time_millis()
        delay = _LISTENER_TIME
        next_ = now + delay
        last = now + timeout

        record_types_for_check_cache = [
            (_TYPE_SRV, _CLASS_IN),
            (_TYPE_TXT, _CLASS_IN),
        ]
        if self.server is not None:
            if zc.address_family is socket.AF_INET:
                record_types_for_check_cache.append((_TYPE_A, _CLASS_IN))
            else: #IPv6
                record_types_for_check_cache.append((_TYPE_AAAA, _CLASS_IN))
        for record_type in record_types_for_check_cache:
            cached = zc.cache.get_by_details(self.name, *record_type)
            cached_server = zc.cache.get_by_details(self.server.lower(), *record_type)
            if cached:
                self.update_record(zc, now, cached)
            if cached_server: 
                self.update_record(zc, now, cached_server)

        if None not in (self.server, self.address, self.text):
            return True

        try:
            zc.add_listener(self, DNSQuestion(self.name, _TYPE_ANY, _CLASS_IN))
            while None in (self.server, self.address, self.text):
                if last <= now:
                    return False
                if next_ <= now:
                    out = DNSOutgoing(_FLAGS_QR_QUERY)
                    out.add_question(
                        DNSQuestion(self.name, _TYPE_SRV, _CLASS_IN))
                    out.add_answer_at_time(
                        zc.cache.get_by_details(
                            self.name, _TYPE_SRV, _CLASS_IN), now)

                    out.add_question(
                        DNSQuestion(self.name, _TYPE_TXT, _CLASS_IN))
                    out.add_answer_at_time(
                        zc.cache.get_by_details(
                            self.name, _TYPE_TXT, _CLASS_IN), now)

                    if self.server is not None:
                        out_type = _TYPE_A
                        if zc.address_family == socket.AF_INET6: #IPv6
                            out_type = _TYPE_AAAA
                        
                        out.add_question(
                            DNSQuestion(self.server, out_type, _CLASS_IN))
                        out.add_answer_at_time(
                            zc.cache.get_by_details(
                                self.server, out_type, _CLASS_IN), now)
                    zc.send(out)
                    next_ = now + delay
                    delay *= 2

                zc.wait(min(next_, last) - now)
                now = current_time_millis()
        finally:
            zc.remove_listener(self)

        return True

    def __eq__(self, other):
        """Tests equality of service name"""
        return isinstance(other, ServiceInfo) and other.name == self.name

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self):
        """String representation"""
        return '%s(%s)' % (
            type(self).__name__,
            ', '.join(
                '%s=%r' % (name, getattr(self, name))
                for name in (
                    'type', 'name', 'address', 'port', 'weight', 'priority',
                    'server', 'properties',
                )
            )
        )


class ZeroconfServiceTypes:
    """
    Return all of the advertised services on any local networks
    """
    def __init__(self):
        self.found_services = set()

    def add_service(self, zc, type_, name):
        self.found_services.add(name)

    def remove_service(self, zc, type_, name):
        pass

    @classmethod
    def find(cls, zc=None, timeout=5, interfaces=InterfaceChoice.All):
        """
        Return all of the advertised services on any local networks.

        :param zc: Zeroconf() instance.  Pass in if already have an
                instance running or if non-default interfaces are needed
        :param timeout: seconds to wait for any responses
        :return: tuple of service type strings
        """
        local_zc = zc or Zeroconf(interfaces=interfaces)
        listener = cls()
        browser = ServiceBrowser(
            local_zc, '_services._dns-sd._udp.local.', listener=listener)

        # wait for responses
        time.sleep(timeout)

        # close down anything we opened
        if zc is None:
            local_zc.close()
        else:
            browser.cancel()

        return tuple(sorted(listener.found_services))


def get_all_addresses(address_family):
    return list(set(
        addr['addr']
        for iface in netifaces.interfaces()
        for addr in netifaces.ifaddresses(iface).get(address_family, [])
        if addr.get('netmask') != HOST_ONLY_NETWORK_MASK
    ))


def normalize_interface_choice(choice, address_family, interface_name):
    if choice is InterfaceChoice.Default and address_family is socket.AF_INET:
        choice = ['0.0.0.0']
    elif choice is InterfaceChoice.All and address_family is socket.AF_INET:
        choice = get_all_addresses(address_family)
    elif address_family is socket.AF_INET6: #IPv6 
        if choice is InterfaceChoice.Default or choice is InterfaceChoice.All:
            #Get the ip of the interface 
            ip6_addr =  netifaces.ifaddresses(interface_name)[address_family][0]['addr']
            ip6_addr = ip6_addr.split("%")[0]
            return [ip6_addr]
        else: 
            return choice
    return choice


def new_socket(interface_number=None, interface_name=None):
    """
    Create a new socket for a given interface_number. 
    interface_name and interface_number have to be for the same interface 

    """
    #Default is IPv4
    address_family = socket.AF_INET

    intf = None #The interface used to transmit data

    if interface_number is None: 
        #No ipv6 interface given. Stay in ipv4 
        intf = socket.gethostbyname(socket.gethostname())
    else: #IPv6 
        intf = int(interface_number)
        address_family = socket.AF_INET6

    #Create socket 
    s = socket.socket(address_family, socket.SOCK_DGRAM)

    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # SO_REUSEADDR should be equivalent to SO_REUSEPORT for
    # multicast UDP sockets (p 731, "TCP/IP Illustrated,
    # Volume 2"), but some BSD-derived systems require
    # SO_REUSEPORT to be specified explicity.  Also, not all
    # versions of Python have SO_REUSEPORT available.
    # Catch OSError and socket.error for kernel versions <3.9 because lacking
    # SO_REUSEPORT support.
    try:
        reuseport = socket.SO_REUSEPORT
    except AttributeError:
        pass
    else:
        try:
            s.setsockopt(socket.SOL_SOCKET, reuseport, 1)
        except (OSError, socket.error) as err:
            # OSError on python 3, socket.error on python 2
            if not err.errno == errno.ENOPROTOOPT:
                raise


    # OpenBSD needs the ttl and loop values for the IP_MULTICAST_TTL and
    # IP_MULTICAST_LOOP socket options as an unsigned char.
    if address_family is socket.AF_INET: 
        ttl = struct.pack(b'B', 255)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        loop = struct.pack(b'B', 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
    
    else: #IPv6
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)

    if interface_name is "awdl0" and platform.system() == 'Darwin':
        s.setsockopt(socket.SOL_SOCKET, 0x1104, 1)

    #Bind the Socket
    s.bind(('', _MDNS_PORT))
    return s


def get_errno(e):
    assert isinstance(e, socket.error)
    return e.args[0]


class Zeroconf(QuietLogger):

    """Implementation of Zeroconf Multicast DNS Service Discovery

    Supports registration, unregistration, queries and browsing.
    """

    def __init__(
        self,
        interfaces=InterfaceChoice.All,
        ipv6_interface_name=None,
        apple_mdns=False,
    ):
        """Creates an instance of the Zeroconf class, establishing
        multicast communications, listening and reaping threads.

        :type interfaces: :class:`InterfaceChoice` or sequence of ip addresses
        :param ipv6_interface_name: string defining the name of the IPv6 interface that should be used. None if IPv4 should be used
        :param apple_mdns: For Apple's mdns services._dns-sd._udp.local. has to be included in an answer
        """
        # hook for threads
        self._GLOBAL_DONE = False

        if ipv6_interface_name is None: #IPv4
            self._listen_socket = new_socket()
            self.address_family = socket.AF_INET
        else: #IPv6
            self.if_index = socket.if_nametoindex(ipv6_interface_name)
            self._listen_socket = new_socket(interface_number=self.if_index, interface_name=ipv6_interface_name)
            self.address_family = socket.AF_INET6

        self.apple_mdns = apple_mdns
            
        interfaces = normalize_interface_choice(interfaces, self.address_family, ipv6_interface_name)

        # print("Interfaces", interfaces)

        self._respond_sockets = []

        for i in interfaces:
            log.debug('Adding %r to multicast group', i)
            try:
                if self.address_family is socket.AF_INET:
                    self._listen_socket.setsockopt(
                        socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        socket.inet_aton(_MDNS_ADDR) + socket.inet_aton(i))
                else: #IPv6 
                    self.ifn = struct.pack("I", self.if_index)
                    group = socket.inet_pton(socket.AF_INET6,_MDNS_ADDR_IPV6) + self.ifn
                    self._listen_socket.setsockopt(
                        socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group
                    )

            except socket.error as e:
                if get_errno(e) == errno.EADDRINUSE:
                    log.info(
                        'Address in use when adding %s to multicast group, '
                        'it is expected to happen on some systems', i,
                    )
                elif get_errno(e) == errno.EADDRNOTAVAIL:
                    log.info(
                        'Address not available when adding %s to multicast '
                        'group, it is expected to happen on some systems', i,
                    )
                    continue
                else:
                    raise

            respond_socket = None
            if self.address_family is socket.AF_INET:  #IPv4
                respond_socket = new_socket()
                respond_socket.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(i))
            else: #IPv6 
                respond_socket = new_socket(self.if_index)
                respond_socket.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, self.ifn
                )

            self._respond_sockets.append(respond_socket)

        self.listeners = []
        self.browsers = {}
        self.services = {}
        self.servicetypes = {}

        self.cache = DNSCache()

        self.condition = threading.Condition()

        self.engine = Engine(self)
        self.listener = Listener(self)
        self.engine.add_reader(self.listener, self._listen_socket)
        self.reaper = Reaper(self)

        self.debug = None

    @property
    def done(self):
        return self._GLOBAL_DONE

    def wait(self, timeout):
        """Calling thread waits for a given number of milliseconds or
        until notified."""
        with self.condition:
            self.condition.wait(timeout / 1000.0)

    def notify_all(self):
        """Notifies all waiting threads"""
        with self.condition:
            self.condition.notify_all()

    def get_service_info(self, type_, name, timeout=3000):
        """Returns network's service information for a particular
        name and type, or None if no service matches by the timeout,
        which defaults to 3 seconds."""
        info = ServiceInfo(type_, name)
        if info.request(self, timeout):
            return info

    def add_service_listener(self, type_, listener):
        """Adds a listener for a particular service type.  This object
        will then have its update_record method called when information
        arrives for that type."""
        self.remove_service_listener(listener)
        self.browsers[listener] = ServiceBrowser(self, type_, listener)

    def remove_service_listener(self, listener):
        """Removes a listener from the set that is currently listening."""
        if listener in self.browsers:
            self.browsers[listener].cancel()
            del self.browsers[listener]

    def remove_all_service_listeners(self):
        """Removes a listener from the set that is currently listening."""
        for listener in [k for k in self.browsers]:
            self.remove_service_listener(listener)

    def register_service(self, info, ttl=_DNS_TTL, allow_name_change=False):
        """Registers service information to the network with a default TTL
        of 60 seconds.  Zeroconf will then respond to requests for
        information for that service.  The name of the service may be
        changed if needed to make it unique on the network."""
        self.check_service(info, allow_name_change)
        self.services[info.name.lower()] = info
        if info.type in self.servicetypes:
            self.servicetypes[info.type] += 1
        else:
            self.servicetypes[info.type] = 1
        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
            out.add_answer_at_time(
                DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, ttl, info.name), 0)
            out.add_answer_at_time(
                DNSService(info.name, _TYPE_SRV, _CLASS_IN,
                           ttl, info.priority, info.weight, info.port,
                           info.server), 0)

            out.add_answer_at_time(
                DNSText(info.name, _TYPE_TXT, _CLASS_IN, ttl, info.text), 0)
            if info.address:
                if self.address_family == socket.AF_INET:
                    out.add_answer_at_time(
                        DNSAddress(info.server, _TYPE_A, _CLASS_IN,
                                   ttl, info.address), 0)
                else: #IPv6 
                    out.add_answer_at_time(
                        DNSAddress(info.server, _TYPE_AAAA, _CLASS_IN,
                                   ttl, info.address), 0)

            self.send(out)
            i += 1
            next_time += _REGISTER_TIME

    def unregister_service(self, info):
        """Unregister a service."""
        try:
            del self.services[info.name.lower()]
            if self.servicetypes[info.type] > 1:
                self.servicetypes[info.type] -= 1
            else:
                del self.servicetypes[info.type]
        except Exception as e:  # TODO stop catching all Exceptions
            log.exception('Unknown error, possibly benign: %r', e)
        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
            out.add_answer_at_time(
                DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, 0, info.name), 0)
            out.add_answer_at_time(
                DNSService(info.name, _TYPE_SRV, _CLASS_IN, 0,
                           info.priority, info.weight, info.port, info.name), 0)
            out.add_answer_at_time(
                DNSText(info.name, _TYPE_TXT, _CLASS_IN, 0, info.text), 0)

            if info.address:
                out_type = _TYPE_A
                if self.address_family == socket.AF_INET6: #IPv6
                    out_type = _TYPE_AAAA

                out.add_answer_at_time(
                    DNSAddress(info.server, out_type, _CLASS_IN, 0,
                               info.address), 0)
            self.send(out)
            i += 1
            next_time += _UNREGISTER_TIME

    def unregister_all_services(self):
        """Unregister all registered services."""
        if len(self.services) > 0:
            now = current_time_millis()
            next_time = now
            i = 0
            while i < 3:
                if now < next_time:
                    self.wait(next_time - now)
                    now = current_time_millis()
                    continue
                out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
                for info in self.services.values():
                    out.add_answer_at_time(DNSPointer(
                        info.type, _TYPE_PTR, _CLASS_IN, 0, info.name), 0)
                    out.add_answer_at_time(DNSService(
                        info.name, _TYPE_SRV, _CLASS_IN, 0,
                        info.priority, info.weight, info.port, info.server), 0)
                    out.add_answer_at_time(DNSText(
                        info.name, _TYPE_TXT, _CLASS_IN, 0, info.text), 0)
                    if info.address:
                        out_type = _TYPE_A
                        if self.address_family == socket.AF_INET6: #IPv6
                            out_type = _TYPE_AAAA
                            
                        out.add_answer_at_time(DNSAddress(
                            info.server, out_type, _CLASS_IN, 0,
                            info.address), 0)
                self.send(out)
                i += 1
                next_time += _UNREGISTER_TIME

    def check_service(self, info, allow_name_change):
        """Checks the network for a unique service name, modifying the
        ServiceInfo passed in if it is not unique."""

        # This is kind of funky because of the subtype based tests
        # need to make subtypes a first class citizen
        service_name = service_type_name(info.name)
        if not info.type.endswith(service_name):
            raise BadTypeInNameException

        instance_name = info.name[:-len(service_name) - 1]
        next_instance_number = 2

        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            # check for a name conflict
            while self.cache.current_entry_with_name_and_alias(
                    info.type, info.name):
                if not allow_name_change:
                    raise NonUniqueNameException

                # change the name and look for a conflict
                info.name = '%s-%s.%s' % (
                    instance_name, next_instance_number, info.type)
                next_instance_number += 1
                service_type_name(info.name)
                next_time = now
                i = 0

            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue

            out = DNSOutgoing(_FLAGS_QR_QUERY | _FLAGS_AA)
            self.debug = out
            out.add_question(DNSQuestion(info.type, _TYPE_PTR, _CLASS_IN))
            out.add_authorative_answer(DNSPointer(
                info.type, _TYPE_PTR, _CLASS_IN, _DNS_TTL, info.name))
            self.send(out)
            i += 1
            next_time += _CHECK_TIME

    def add_listener(self, listener, question):
        """Adds a listener for a given question.  The listener will have
        its update_record method called when information is available to
        answer the question."""
        now = current_time_millis()
        self.listeners.append(listener)
        if question is not None:
            for record in self.cache.entries_with_name(question.name):
                if question.answered_by(record) and not record.is_expired(now):
                    listener.update_record(self, now, record)
        self.notify_all()

    def remove_listener(self, listener):
        """Removes a listener."""
        try:
            self.listeners.remove(listener)
            self.notify_all()
        except Exception as e:  # TODO stop catching all Exceptions
            log.exception('Unknown error, possibly benign: %r', e)

    def update_record(self, now, rec):
        """Used to notify listeners of new information that has updated
        a record."""
        for listener in self.listeners:
            listener.update_record(self, now, rec)
        self.notify_all()

    def handle_response(self, msg):
        """Deal with incoming response packets.  All answers
        are held in the cache, and listeners are notified."""
        now = current_time_millis()
        for record in msg.answers:
            expired = record.is_expired(now)
            if record in self.cache.entries():
                if expired:
                    self.cache.remove(record)
                else:
                    entry = self.cache.get(record)
                    if entry is not None:
                        entry.reset_ttl(record)
            else:
                self.cache.add(record)

        for record in msg.answers:
            self.update_record(now, record)

    def handle_query(self, msg, addr, port):
        """Deal with incoming query packets.  Provides a response if
        possible."""
        out = None

        # Support unicast client responses
        #
        if port != _MDNS_PORT:
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA, multicast=False)
            for question in msg.questions:
                out.add_question(question)

        for question in msg.questions:
            if question.type == _TYPE_PTR:
                if question.name == "_services._dns-sd._udp.local.":
                    for stype in self.servicetypes.keys():
                        if out is None:
                            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
                        out.add_answer(msg, DNSPointer(
                            "_services._dns-sd._udp.local.", _TYPE_PTR,
                            _CLASS_IN, _DNS_TTL, stype))
                for service in self.services.values():
                    if question.name == service.type:
                        if out is None:
                            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
                        out.add_answer(msg, DNSPointer(
                            service.type, _TYPE_PTR,
                            _CLASS_IN, _DNS_TTL, service.name))
                    
                    if self.apple_mdns and not out is None: 
                        for stype in self.servicetypes.keys():
                            out.add_answer(msg, DNSPointer(
                                "_services._dns-sd._udp.local.", _TYPE_PTR,
                                _CLASS_IN, _DNS_TTL, stype))
            else:
                try:
                    if out is None:
                        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)

                    # Answer A record queries for any service addresses we know
                    # Used in IPv4 
                    if question.type in (_TYPE_A, _TYPE_ANY) and self.address_family == socket.AF_INET:
                        for service in self.services.values():
                            if service.server.lower() == question.name.lower():
                                out.add_answer(msg, DNSAddress(
                                    question.name, _TYPE_A,
                                    _CLASS_IN | _CLASS_UNIQUE,
                                    _DNS_TTL, service.address))
                    
                    #React on query for AAAA record 
                    # In IPv6 
                    elif question.type in (_TYPE_AAAA, _TYPE_ANY) and self.address_family == socket.AF_INET6: #IPv6
                        for service in self.services.values(): 
                            if service.server == question.name.lower(): 
                                out.add_answer(msg, DNSAddress(
                                    question.name, _TYPE_AAAA,
                                    _CLASS_IN | _CLASS_UNIQUE,
                                    _DNS_TTL, service.address))

                    service = self.services.get(question.name.lower(), None)
                    if not service:
                        continue

                    if question.type in (_TYPE_SRV, _TYPE_ANY):
                        out.add_answer(msg, DNSService(
                            question.name, _TYPE_SRV, _CLASS_IN | _CLASS_UNIQUE,
                            _DNS_TTL, service.priority, service.weight,
                            service.port, service.server))
                    if question.type in (_TYPE_TXT, _TYPE_ANY):
                        out.add_answer(msg, DNSText(
                            question.name, _TYPE_TXT, _CLASS_IN | _CLASS_UNIQUE,
                            _DNS_TTL, service.text))
                    if question.type == _TYPE_SRV:
                        address_type = _TYPE_A
                        if self.address_family == socket.AF_INET6:
                            address_type = _TYPE_AAAA
                        out.add_additional_answer(DNSAddress(
                            service.server, address_type, _CLASS_IN | _CLASS_UNIQUE,
                            _DNS_TTL, service.address))

                except Exception:  # TODO stop catching all Exceptions
                    self.log_exception_warning()

        if out is not None and out.answers:
            out.id = msg.id
            self.send(out, addr, port)

    def send(self, out, addr=None, port=_MDNS_PORT):
        """Sends an outgoing packet."""

        if self.address_family is socket.AF_INET6: 
            #Wrong address set. Change to ipv6 mdns 
            addr = (addr or _MDNS_ADDR_IPV6, port, 0, 0,)
        else: 
            addr = (addr or _MDNS_ADDR, port,)


        packet = out.packet()
        if len(packet) > _MAX_MSG_ABSOLUTE:
            self.log_warning_once("Dropping %r over-sized packet (%d bytes) %r",
                                  out, len(packet), packet)
            return
        log.debug('Sending %r (%d bytes) as %r...', out, len(packet), packet)
        for s in self._respond_sockets:
            if self._GLOBAL_DONE:
                return
            try:
                bytes_sent = s.sendto(packet, 0, addr)
            except Exception:   # TODO stop catching all Exceptions
                # on send errors, log the exception and keep going
                self.log_exception_warning()
            else:
                if bytes_sent != len(packet):
                    self.log_warning_once(
                        '!!! sent %d out of %d bytes to %r' % (
                            bytes_sent, len(packet)), s)

    def close(self):
        """Ends the background threads, and prevent this instance from
        servicing further queries."""
        if not self._GLOBAL_DONE:
            self._GLOBAL_DONE = True
            # remove service listeners
            self.remove_all_service_listeners()
            self.unregister_all_services()

            # shutdown recv socket and thread
            self.engine.del_reader(self._listen_socket)

            if self.address_family == socket.AF_INET:
                self._listen_socket.setsockopt(socket.SOL_IP, socket.IP_DROP_MEMBERSHIP,
                    socket.inet_aton(_MDNS_ADDR) + socket.inet_aton('0.0.0.0'))
            else:
                group = socket.inet_pton(socket.AF_INET6,_MDNS_ADDR_IPV6) + self.ifn
                self._listen_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP,group)
            
            self._listen_socket.close()
            self.engine.join()

            # shutdown the rest
            self.notify_all()
            self.reaper.join()
            for s in self._respond_sockets:
                s.close()
