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
import ipaddress
import itertools
import logging
import os
import platform
import re
import select
import socket
import struct
import sys
import threading
import time
import warnings
from typing import AnyStr, Dict, List, Optional, Sequence, Union, cast
from typing import Any, Callable, Set, Tuple  # noqa # used in type hints

import ifaddr

__author__ = 'Paul Scott-Murphy, William McBrine'
__maintainer__ = 'Jakub Stasiak <jakub@stasiak.at>'
__version__ = '0.24.1'
__license__ = 'LGPL'


__all__ = [
    "__version__",
    "Zeroconf",
    "ServiceInfo",
    "ServiceBrowser",
    "Error",
    "InterfaceChoice",
    "ServiceStateChange",
    "IPVersion",
]

if sys.version_info <= (3, 3):
    raise ImportError(
        '''
Python version > 3.3 required for python-zeroconf.
If you need support for Python 2 or Python 3.3 please use version 19.1
    '''
    )

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

if log.level == logging.NOTSET:
    log.setLevel(logging.WARN)

# Some timing constants

_UNREGISTER_TIME = 125  # ms
_CHECK_TIME = 175  # ms
_REGISTER_TIME = 225  # ms
_LISTENER_TIME = 200  # ms
_BROWSER_TIME = 1000  # ms
_BROWSER_BACKOFF_LIMIT = 3600  # s

# Some DNS constants

_MDNS_ADDR = '224.0.0.251'
_MDNS_ADDR_BYTES = socket.inet_aton(_MDNS_ADDR)
_MDNS_ADDR6 = 'ff02::fb'
_MDNS_ADDR6_BYTES = socket.inet_pton(socket.AF_INET6, _MDNS_ADDR6)
_MDNS_PORT = 5353
_DNS_PORT = 53
_DNS_HOST_TTL = 120  # two minute for host records (A, SRV etc) as-per RFC6762
_DNS_OTHER_TTL = 4500  # 75 minutes for non-host records (PTR, TXT etc) as-per RFC6762

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

# Mapping constants to names

_CLASSES = {
    _CLASS_IN: "in",
    _CLASS_CS: "cs",
    _CLASS_CH: "ch",
    _CLASS_HS: "hs",
    _CLASS_NONE: "none",
    _CLASS_ANY: "any",
}

_TYPES = {
    _TYPE_A: "a",
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
    _TYPE_ANY: "any",
}

_HAS_A_TO_Z = re.compile(r'[A-Za-z]')
_HAS_ONLY_A_TO_Z_NUM_HYPHEN = re.compile(r'^[A-Za-z0-9\-]+$')
_HAS_ONLY_A_TO_Z_NUM_HYPHEN_UNDERSCORE = re.compile(r'^[A-Za-z0-9\-\_]+$')
_HAS_ASCII_CONTROL_CHARS = re.compile(r'[\x00-\x1f\x7f]')

try:
    _IPPROTO_IPV6 = socket.IPPROTO_IPV6
except AttributeError:
    # Sigh: https://bugs.python.org/issue29515
    _IPPROTO_IPV6 = 41

int2byte = struct.Struct(">B").pack


@enum.unique
class InterfaceChoice(enum.Enum):
    Default = 1
    All = 2


InterfacesType = Union[List[Union[str, int]], InterfaceChoice]


@enum.unique
class ServiceStateChange(enum.Enum):
    Added = 1
    Removed = 2
    Updated = 3


@enum.unique
class IPVersion(enum.Enum):
    V4Only = 1
    V6Only = 2
    All = 3


# utility functions


def current_time_millis() -> float:
    """Current system time in milliseconds"""
    return time.time() * 1000


def _is_v6_address(addr):
    return len(addr) == 16


def service_type_name(type_, *, allow_underscores: bool = False):
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
        raise BadTypeInNameException("Type '%s' must end with '._tcp.local.' or '._udp.local.'" % type_)

    remaining = type_[: -len('._tcp.local.')].split('.')
    name = remaining.pop()
    if not name:
        raise BadTypeInNameException("No Service name found")

    if len(remaining) == 1 and len(remaining[0]) == 0:
        raise BadTypeInNameException("Type '%s' must not start with '.'" % type_)

    if name[0] != '_':
        raise BadTypeInNameException("Service name (%s) must start with '_'" % name)

    # remove leading underscore
    name = name[1:]

    if len(name) > 15:
        raise BadTypeInNameException("Service name (%s) must be <= 15 bytes" % name)

    if '--' in name:
        raise BadTypeInNameException("Service name (%s) must not contain '--'" % name)

    if '-' in (name[0], name[-1]):
        raise BadTypeInNameException("Service name (%s) may not start or end with '-'" % name)

    if not _HAS_A_TO_Z.search(name):
        raise BadTypeInNameException("Service name (%s) must contain at least one letter (eg: 'A-Z')" % name)

    allowed_characters_re = (
        _HAS_ONLY_A_TO_Z_NUM_HYPHEN_UNDERSCORE if allow_underscores else _HAS_ONLY_A_TO_Z_NUM_HYPHEN
    )

    if not allowed_characters_re.search(name):
        raise BadTypeInNameException(
            "Service name (%s) must contain only these characters: "
            "A-Z, a-z, 0-9, hyphen ('-')%s" % (name, ", underscore ('_')" if allow_underscores else "")
        )

    if remaining and remaining[-1] == '_sub':
        remaining.pop()
        if len(remaining) == 0 or len(remaining[0]) == 0:
            raise BadTypeInNameException("_sub requires a subtype name")

    if len(remaining) > 1:
        remaining = ['.'.join(remaining)]

    if remaining:
        length = len(remaining[0].encode('utf-8'))
        if length > 63:
            raise BadTypeInNameException("Too long: '%s'" % remaining[0])

        if _HAS_ASCII_CONTROL_CHARS.search(remaining[0]):
            raise BadTypeInNameException(
                "Ascii control character 0x00-0x1F and 0x7F illegal in '%s'" % remaining[0]
            )

    return '_' + name + type_[-len('._tcp.local.') :]


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
    _seen_logs = {}  # type: Dict[str, Union[int, tuple]]

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
        logger('Exception occurred:', exc_info=True)

    @classmethod
    def log_warning_once(cls, *args):
        msg_str = args[0]
        if msg_str not in cls._seen_logs:
            cls._seen_logs[msg_str] = 0
            logger = log.warning
        else:
            logger = log.debug
        cls._seen_logs[msg_str] = cast(int, cls._seen_logs[msg_str]) + 1
        logger(*args)


class DNSEntry:

    """A DNS entry"""

    def __init__(self, name: str, type_: int, class_):
        self.key = name.lower()
        self.name = name
        self.type = type_
        self.class_ = class_ & _CLASS_MASK
        self.unique = (class_ & _CLASS_UNIQUE) != 0

    def __eq__(self, other):
        """Equality test on name, type, and class"""
        return (
            self.name == other.name
            and self.type == other.type
            and self.class_ == other.class_
            and isinstance(other, DNSEntry)
        )

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

    def to_string(self, hdr, other) -> str:
        """String representation with additional information"""
        result = "%s[%s,%s" % (hdr, self.get_type(self.type), self.get_class_(self.class_))
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

    def __init__(self, name: str, type_: int, class_: int) -> None:
        DNSEntry.__init__(self, name, type_, class_)

    def answered_by(self, rec: 'DNSRecord') -> bool:
        """Returns true if the question is answered by the record"""
        return (
            self.class_ == rec.class_
            and (self.type == rec.type or self.type == _TYPE_ANY)
            and self.name == rec.name
        )

    def __repr__(self) -> str:
        """String representation"""
        return DNSEntry.to_string(self, "question", None)


class DNSRecord(DNSEntry):

    """A DNS record - like a DNS entry, but has a TTL"""

    def __init__(self, name, type_, class_, ttl: float):
        DNSEntry.__init__(self, name, type_, class_)
        self.ttl = ttl
        self.created = current_time_millis()
        self._expiration_time = self.get_expiration_time(100)
        self._stale_time = self.get_expiration_time(50)

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

    def get_expiration_time(self, percent: float) -> float:
        """Returns the time at which this record will have expired
        by a certain percentage."""
        return self.created + (percent * self.ttl * 10)

    def get_remaining_ttl(self, now):
        """Returns the remaining TTL in seconds."""
        return max(0, (self._expiration_time - now) / 1000.0)

    def is_expired(self, now: float) -> bool:
        """Returns true if this record has expired."""
        return self._expiration_time <= now

    def is_stale(self, now):
        """Returns true if this record is at least half way expired."""
        return self._stale_time <= now

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
        arg = "%s/%s,%s" % (self.ttl, self.get_remaining_ttl(current_time_millis()), other)
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
        return (
            isinstance(other, DNSAddress) and DNSEntry.__eq__(self, other) and self.address == other.address
        )

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
        return (
            isinstance(other, DNSHinfo)
            and DNSEntry.__eq__(self, other)
            and self.cpu == other.cpu
            and self.os == other.os
        )

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
        return isinstance(other, DNSPointer) and self.alias == other.alias and DNSEntry.__eq__(self, other)

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self):
        """String representation"""
        return self.to_string(self.alias)


class DNSText(DNSRecord):

    """A DNS text record"""

    def __init__(self, name: str, type_: Optional[int], class_: int, ttl: int, text: bytes) -> None:
        assert isinstance(text, (bytes, type(None)))
        DNSRecord.__init__(self, name, type_, class_, ttl)
        self.text = text

    def write(self, out):
        """Used in constructing an outgoing packet"""
        out.write_string(self.text)

    def __eq__(self, other):
        """Tests equality on text"""
        return isinstance(other, DNSText) and self.text == other.text and DNSEntry.__eq__(self, other)

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

    def __init__(self, name, type_, class_, ttl, priority, weight, port, server):
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
        return (
            isinstance(other, DNSService)
            and self.priority == other.priority
            and self.weight == other.weight
            and self.port == other.port
            and self.server == other.server
            and DNSEntry.__eq__(self, other)
        )

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self):
        """String representation"""
        return self.to_string("%s:%s" % (self.server, self.port))


class DNSIncoming(QuietLogger):

    """Object representation of an incoming DNS packet"""

    def __init__(self, data: bytes) -> None:
        """Constructor from string holding bytes of packet"""
        self.offset = 0
        self.data = data
        self.questions = []  # type: List[DNSQuestion]
        self.answers = []  # type: List[DNSRecord]
        self.id = 0
        self.flags = 0  # type: int
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
            self.log_exception_warning(('Choked at offset %d while unpacking %r', self.offset, data))

    def unpack(self, format_: bytes) -> tuple:
        length = struct.calcsize(format_)
        info = struct.unpack(format_, self.data[self.offset : self.offset + length])
        self.offset += length
        return info

    def read_header(self) -> None:
        """Reads header portion of packet"""
        (
            self.id,
            self.flags,
            self.num_questions,
            self.num_answers,
            self.num_authorities,
            self.num_additionals,
        ) = self.unpack(b'!6H')

    def read_questions(self) -> None:
        """Reads questions section of packet"""
        for i in range(self.num_questions):
            name = self.read_name()
            type_, class_ = self.unpack(b'!HH')

            question = DNSQuestion(name, type_, class_)
            self.questions.append(question)

    # def read_int(self):
    #     """Reads an integer from the packet"""
    #     return self.unpack(b'!I')[0]

    def read_character_string(self) -> bytes:
        """Reads a character string from the packet"""
        length = self.data[self.offset]
        self.offset += 1
        return self.read_string(length)

    def read_string(self, length) -> bytes:
        """Reads a string of a given length from the packet"""
        info = self.data[self.offset : self.offset + length]
        self.offset += length
        return info

    def read_unsigned_short(self) -> int:
        """Reads an unsigned short from the packet"""
        return cast(int, self.unpack(b'!H')[0])

    def read_others(self) -> None:
        """Reads the answers, authorities and additionals section of the
        packet"""
        n = self.num_answers + self.num_authorities + self.num_additionals
        for i in range(n):
            domain = self.read_name()
            type_, class_, ttl, length = self.unpack(b'!HHiH')

            rec = None  # type: Optional[DNSRecord]
            if type_ == _TYPE_A:
                rec = DNSAddress(domain, type_, class_, ttl, self.read_string(4))
            elif type_ == _TYPE_CNAME or type_ == _TYPE_PTR:
                rec = DNSPointer(domain, type_, class_, ttl, self.read_name())
            elif type_ == _TYPE_TXT:
                rec = DNSText(domain, type_, class_, ttl, self.read_string(length))
            elif type_ == _TYPE_SRV:
                rec = DNSService(
                    domain,
                    type_,
                    class_,
                    ttl,
                    self.read_unsigned_short(),
                    self.read_unsigned_short(),
                    self.read_unsigned_short(),
                    self.read_name(),
                )
            elif type_ == _TYPE_HINFO:
                rec = DNSHinfo(
                    domain, type_, class_, ttl, self.read_character_string(), self.read_character_string()
                )
            elif type_ == _TYPE_AAAA:
                rec = DNSAddress(domain, type_, class_, ttl, self.read_string(16))
            else:
                # Try to ignore types we don't know about
                # Skip the payload for the resource record so the next
                # records can be parsed correctly
                self.offset += length

            if rec is not None:
                self.answers.append(rec)

    def is_query(self) -> bool:
        """Returns true if this is a query"""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_QUERY

    def is_response(self) -> bool:
        """Returns true if this is a response"""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_RESPONSE

    def read_utf(self, offset: int, length: int) -> str:
        """Reads a UTF-8 string of a given length from the packet"""
        return str(self.data[offset : offset + length], 'utf-8', 'replace')

    def read_name(self) -> str:
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
                    raise IncomingDecodeError("Bad domain name (circular) at %s" % (off,))
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
        self.names = {}  # type: Dict[str, int]
        self.data = []  # type: List[bytes]
        self.size = 12
        self.state = self.State.init

        self.questions = []  # type: List[DNSQuestion]
        self.answers = []  # type: List[Tuple[DNSEntry, float]]
        self.authorities = []  # type: List[DNSPointer]
        self.additionals = []  # type: List[DNSAddress]

    def __repr__(self):
        return '<DNSOutgoing:{%s}>' % ', '.join(
            [
                'multicast=%s' % self.multicast,
                'flags=%s' % self.flags,
                'questions=%s' % self.questions,
                'answers=%s' % self.answers,
                'authorities=%s' % self.authorities,
                'additionals=%s' % self.additionals,
            ]
        )

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
            count = len(name_suffices)

        # note the new names we are saving into the packet
        name_length = len(name.encode('utf-8'))
        for suffix in name_suffices[:count]:
            self.names[suffix] = self.size + name_length - len(suffix.encode('utf-8')) - 1

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

    def packet(self) -> bytes:
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
        self.cache = {}  # type: Dict[str, List[DNSEntry]]

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
            if record.type == _TYPE_PTR and not record.is_expired(now) and record.alias == alias:
                return record

    def entries(self):
        """Returns a list of all entries"""
        if not self.cache:
            return []
        else:
            # avoid size change during iteration by copying the cache
            values = list(self.cache.values())
            return list(itertools.chain.from_iterable(values))


class Engine(threading.Thread):

    """An engine wraps read access to sockets, allowing objects that
    need to receive data from sockets to be called back when the
    sockets are ready.

    A reader needs a handle_read() method, which is called when the socket
    it is interested in is ready for reading.

    Writers are not implemented here, because we only send short
    packets.
    """

    def __init__(self, zc: 'Zeroconf') -> None:
        threading.Thread.__init__(self, name='zeroconf-Engine')
        self.daemon = True
        self.zc = zc
        self.readers = {}  # type: Dict[socket.socket, Listener]
        self.timeout = 5
        self.condition = threading.Condition()
        self.start()

    def run(self) -> None:
        while not self.zc.done:
            with self.condition:
                rs = self.readers.keys()
                if len(rs) == 0:
                    # No sockets to manage, but we wait for the timeout
                    # or addition of a socket
                    self.condition.wait(self.timeout)

            if len(rs) != 0:
                try:
                    rr, wr, er = select.select(cast(Sequence[Any], rs), [], [], self.timeout)
                    if not self.zc.done:
                        for socket_ in rr:
                            reader = self.readers.get(socket_)
                            if reader:
                                reader.handle_read(socket_)

                except (select.error, socket.error) as e:
                    # If the socket was closed by another thread, during
                    # shutdown, ignore it and exit
                    if e.args[0] not in (errno.EBADF, errno.ENOTCONN) or not self.zc.done:
                        raise

    def add_reader(self, reader: 'Listener', socket_: socket.socket) -> None:
        with self.condition:
            self.readers[socket_] = reader
            self.condition.notify()

    def del_reader(self, socket_: socket.socket) -> None:
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
            data, (addr, port, *_v6) = socket_.recvfrom(_MAX_MSG_ABSOLUTE)
        except Exception:
            self.log_exception_warning()
            return

        log.debug('Received from %r:%r: %r ', addr, port, data)

        self.data = data
        msg = DNSIncoming(data)
        if not msg.valid:
            pass

        elif msg.is_query():
            # Always multicast responses
            if port == _MDNS_PORT:
                self.zc.handle_query(msg, None, _MDNS_PORT)

            # If it's not a multicast query, reply via unicast
            # and multicast
            elif port == _DNS_PORT:
                self.zc.handle_query(msg, addr, port)
                self.zc.handle_query(msg, None, _MDNS_PORT)

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
        self._handlers = []  # type: List[Callable[..., None]]

    def fire(self, **kwargs) -> None:
        for h in list(self._handlers):
            h(**kwargs)

    @property
    def registration_interface(self) -> 'SignalRegistrationInterface':
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


class RecordUpdateListener:
    def update_record(self, zc: 'Zeroconf', now: float, record: DNSRecord) -> None:
        raise NotImplementedError()


class ServiceListener:
    def add_service(self, zc, type_, name) -> None:
        raise NotImplementedError()

    def remove_service(self, zc, type_, name) -> None:
        raise NotImplementedError()

    def update_service(self, zc, type_, name) -> None:
        raise NotImplementedError()


class ServiceBrowser(RecordUpdateListener, threading.Thread):

    """Used to browse for a service of a specific type.

    The listener object will have its add_service() and
    remove_service() methods called when this browser
    discovers changes in the services availability."""

    def __init__(
        self,
        zc: 'Zeroconf',
        type_: str,
        handlers=None,
        listener=None,
        addr: Optional[str] = None,
        port: int = _MDNS_PORT,
        delay: int = _BROWSER_TIME,
    ) -> None:
        """Creates a browser for a specific type"""
        assert handlers or listener, 'You need to specify at least one handler'
        if not type_.endswith(service_type_name(type_, allow_underscores=True)):
            raise BadTypeInNameException
        threading.Thread.__init__(self, name='zeroconf-ServiceBrowser_' + type_)
        self.daemon = True
        self.zc = zc
        self.type = type_
        self.addr = addr
        self.port = port
        self.multicast = self.addr in (None, _MDNS_ADDR, _MDNS_ADDR6)
        self.services = {}  # type: Dict[str, DNSRecord]
        self.next_time = current_time_millis()
        self.delay = delay
        self._handlers_to_call = []  # type: List[Callable[[Zeroconf], None]]

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
                elif state_change is ServiceStateChange.Updated:
                    if hasattr(listener, 'update_service'):
                        listener.update_service(*args)
                else:
                    raise NotImplementedError(state_change)

            handlers.append(on_change)

        for h in handlers:
            self.service_state_changed.register_handler(h)

        self.start()

    @property
    def service_state_changed(self) -> SignalRegistrationInterface:
        return self._service_state_changed.registration_interface

    def update_record(self, zc: 'Zeroconf', now: float, record: DNSRecord) -> None:
        """Callback invoked by Zeroconf when new information arrives.

        Updates information required by browser in the Zeroconf cache."""

        def enqueue_callback(state_change: ServiceStateChange, name: str) -> None:
            self._handlers_to_call.append(
                lambda zeroconf: self._service_state_changed.fire(
                    zeroconf=zeroconf, service_type=self.type, name=name, state_change=state_change
                )
            )

        if record.type == _TYPE_PTR and record.name == self.type:
            assert isinstance(record, DNSPointer)
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

        elif record.type == _TYPE_TXT and record.name.endswith(self.type):
            assert isinstance(record, DNSText)
            expired = record.is_expired(now)
            if not expired:
                enqueue_callback(ServiceStateChange.Updated, record.name)

    def cancel(self) -> None:
        self.done = True
        self.zc.remove_listener(self)
        self.join()

    def run(self) -> None:
        self.zc.add_listener(self, DNSQuestion(self.type, _TYPE_PTR, _CLASS_IN))

        while True:
            now = current_time_millis()
            if len(self._handlers_to_call) == 0 and self.next_time > now:
                self.zc.wait(self.next_time - now)
            if self.zc.done or self.done:
                return
            now = current_time_millis()
            if self.next_time <= now:
                out = DNSOutgoing(_FLAGS_QR_QUERY, multicast=self.multicast)
                out.add_question(DNSQuestion(self.type, _TYPE_PTR, _CLASS_IN))
                for record in self.services.values():
                    if not record.is_stale(now):
                        out.add_answer_at_time(record, now)

                self.zc.send(out, addr=self.addr, port=self.port)
                self.next_time = now + self.delay
                self.delay = min(_BROWSER_BACKOFF_LIMIT * 1000, self.delay * 2)

            if len(self._handlers_to_call) > 0 and not self.zc.done:
                handler = self._handlers_to_call.pop(0)
                handler(self.zc)


ServicePropertiesType = Dict[AnyStr, Union[None, bool, AnyStr, float]]


class ServiceInfo(RecordUpdateListener):
    text = b''

    """Service information"""

    # FIXME(dtantsur): black 19.3b0 produces code that is not valid syntax on
    # Python 3.5: https://github.com/python/black/issues/759
    # fmt: off
    def __init__(
        self,
        type_: str,
        name: str,
        address: Optional[Union[bytes, List[bytes]]] = None,
        port: Optional[int] = None,
        weight: int = 0,
        priority: int = 0,
        properties=b'',
        server: Optional[str] = None,
        host_ttl: int = _DNS_HOST_TTL,
        other_ttl: int = _DNS_OTHER_TTL,
        *,
        addresses: Optional[List[bytes]] = None
    ) -> None:
        """Create a service description.

        type_: fully qualified service type name
        name: fully qualified service name
        address: IP address as unsigned short, network byte order (deprecated, use addresses)
        port: port that the service runs on
        weight: weight of the service
        priority: priority of the service
        properties: dictionary of properties (or a string holding the
                    bytes for the text field)
        server: fully qualified name for service host (defaults to name)
        host_ttl: ttl used for A/SRV records
        other_ttl: ttl used for PTR/TXT records
        addresses: List of IP addresses as unsigned short (IPv4) or unsigned
                   128 bit number (IPv6), network byte order
        """

        # Accept both none, or one, but not both.
        if address is not None and addresses is not None:
            raise TypeError("address and addresses cannot be provided together")

        if not type_.endswith(service_type_name(name, allow_underscores=True)):
            raise BadTypeInNameException
        self.type = type_
        self.name = name
        if addresses is not None:
            self._addresses = addresses
        elif address is not None:
            warnings.warn("address is deprecated, use addresses instead", DeprecationWarning)
            if isinstance(address, list):
                self._addresses = address
            else:
                self._addresses = [address]
        else:
            self._addresses = []
        # This results in an ugly error when registering, better check now
        invalid = [a for a in self._addresses
                   if not isinstance(a, bytes) or len(a) not in (4, 16)]
        if invalid:
            raise TypeError('Addresses must be bytes, got %s. Hint: convert string addresses '
                            'with socket.inet_pton' % invalid)
        self.port = port
        self.weight = weight
        self.priority = priority
        if server:
            self.server = server
        else:
            self.server = name
        self._properties = {}  # type: ServicePropertiesType
        self._set_properties(properties)
        self.host_ttl = host_ttl
        self.other_ttl = other_ttl
    # fmt: on

    @property
    def address(self):
        warnings.warn("ServiceInfo.address is deprecated, use addresses instead", DeprecationWarning)
        try:
            # Return the first V4 address for compatibility
            return self.addresses[0]
        except IndexError:
            return None

    @address.setter
    def address(self, value):
        warnings.warn("ServiceInfo.address is deprecated, use addresses instead", DeprecationWarning)
        if value is None:
            self._addresses = []
        else:
            self._addresses = [value]

    @property
    def addresses(self):
        """IPv4 addresses of this service.

        Only IPv4 addresses are returned for backward compatibility.
        Use :meth:`addresses_by_version` or :meth:`parsed_addresses` to
        include IPv6 addresses as well.
        """
        return self.addresses_by_version(IPVersion.V4Only)

    @addresses.setter
    def addresses(self, value):
        """Replace the addresses list.

        This replaces all currently stored addresses, both IPv4 and IPv6.
        """
        self._addresses = value

    @property
    def properties(self) -> ServicePropertiesType:
        return self._properties

    def addresses_by_version(self, version: IPVersion) -> List[bytes]:
        """List addresses matching IP version."""
        if version == IPVersion.V4Only:
            return [addr for addr in self._addresses if not _is_v6_address(addr)]
        elif version == IPVersion.V6Only:
            return list(filter(_is_v6_address, self._addresses))
        else:
            return self._addresses

    def parsed_addresses(self, version: IPVersion = IPVersion.All) -> List[str]:
        """List addresses in their parsed string form."""
        result = self.addresses_by_version(version)
        return [
            socket.inet_ntop(socket.AF_INET6 if _is_v6_address(addr) else socket.AF_INET, addr)
            for addr in result
        ]

    def _set_properties(self, properties: Union[bytes, ServicePropertiesType]) -> None:
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

    def _set_text(self, text: bytes) -> None:
        """Sets properties and text given a text field"""
        self.text = text
        result = {}  # type: ServicePropertiesType
        end = len(text)
        index = 0
        strs = []
        while index < end:
            length = text[index]
            index += 1
            strs.append(text[index : index + length])
            index += length

        for s in strs:
            parts = s.split(b'=', 1)
            try:
                key, value = parts  # type: Tuple[bytes, Union[bool, bytes]]
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

    def get_name(self) -> str:
        """Name accessor"""
        if self.type is not None and self.name.endswith("." + self.type):
            return self.name[: len(self.name) - len(self.type) - 1]
        return self.name

    def update_record(self, zc: 'Zeroconf', now: float, record: DNSRecord) -> None:
        """Updates service information from a DNS record"""
        if record is not None and not record.is_expired(now):
            if record.type in [_TYPE_A, _TYPE_AAAA]:
                assert isinstance(record, DNSAddress)
                # if record.name == self.name:
                if record.name == self.server:
                    if record.address not in self._addresses:
                        self._addresses.append(record.address)
            elif record.type == _TYPE_SRV:
                assert isinstance(record, DNSService)
                if record.name == self.name:
                    self.server = record.server
                    self.port = record.port
                    self.weight = record.weight
                    self.priority = record.priority
                    # self.address = None
                    self.update_record(zc, now, zc.cache.get_by_details(self.server, _TYPE_A, _CLASS_IN))
                    self.update_record(zc, now, zc.cache.get_by_details(self.server, _TYPE_AAAA, _CLASS_IN))
            elif record.type == _TYPE_TXT:
                assert isinstance(record, DNSText)
                if record.name == self.name:
                    self._set_text(record.text)

    def request(self, zc: 'Zeroconf', timeout: float) -> bool:
        """Returns true if the service could be discovered on the
        network, and updates this object with details discovered.
        """
        now = current_time_millis()
        delay = _LISTENER_TIME
        next_ = now + delay
        last = now + timeout

        record_types_for_check_cache = [(_TYPE_SRV, _CLASS_IN), (_TYPE_TXT, _CLASS_IN)]
        if self.server is not None:
            record_types_for_check_cache.append((_TYPE_A, _CLASS_IN))
            record_types_for_check_cache.append((_TYPE_AAAA, _CLASS_IN))
        for record_type in record_types_for_check_cache:
            cached = zc.cache.get_by_details(self.name, *record_type)
            if cached:
                self.update_record(zc, now, cached)

        if self.server is not None and self.text is not None and self._addresses:
            return True

        try:
            zc.add_listener(self, DNSQuestion(self.name, _TYPE_ANY, _CLASS_IN))
            while self.server is None or self.text is None or not self._addresses:
                if last <= now:
                    return False
                if next_ <= now:
                    out = DNSOutgoing(_FLAGS_QR_QUERY)
                    out.add_question(DNSQuestion(self.name, _TYPE_SRV, _CLASS_IN))
                    out.add_answer_at_time(zc.cache.get_by_details(self.name, _TYPE_SRV, _CLASS_IN), now)

                    out.add_question(DNSQuestion(self.name, _TYPE_TXT, _CLASS_IN))
                    out.add_answer_at_time(zc.cache.get_by_details(self.name, _TYPE_TXT, _CLASS_IN), now)

                    if self.server is not None:
                        out.add_question(DNSQuestion(self.server, _TYPE_A, _CLASS_IN))
                        out.add_answer_at_time(zc.cache.get_by_details(self.server, _TYPE_A, _CLASS_IN), now)
                        out.add_question(DNSQuestion(self.server, _TYPE_AAAA, _CLASS_IN))
                        out.add_answer_at_time(
                            zc.cache.get_by_details(self.server, _TYPE_AAAA, _CLASS_IN), now
                        )
                    zc.send(out)
                    next_ = now + delay
                    delay *= 2

                zc.wait(min(next_, last) - now)
                now = current_time_millis()
        finally:
            zc.remove_listener(self)

        return True

    def __eq__(self, other: object) -> bool:
        """Tests equality of service name"""
        return isinstance(other, ServiceInfo) and other.name == self.name

    def __ne__(self, other: object) -> bool:
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self) -> str:
        """String representation"""
        return '%s(%s)' % (
            type(self).__name__,
            ', '.join(
                '%s=%r' % (name, getattr(self, name))
                for name in (
                    'type',
                    'name',
                    'addresses',
                    'port',
                    'weight',
                    'priority',
                    'server',
                    'properties',
                )
            ),
        )


class ZeroconfServiceTypes(ServiceListener):
    """
    Return all of the advertised services on any local networks
    """

    def __init__(self) -> None:
        self.found_services = set()  # type: Set[str]

    def add_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        self.found_services.add(name)

    def remove_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        pass

    @classmethod
    def find(
        cls,
        zc: Optional['Zeroconf'] = None,
        timeout: Union[int, float] = 5,
        interfaces: InterfacesType = InterfaceChoice.All,
        ip_version: Optional[IPVersion] = None,
    ) -> Tuple[str, ...]:
        """
        Return all of the advertised services on any local networks.

        :param zc: Zeroconf() instance.  Pass in if already have an
                instance running or if non-default interfaces are needed
        :param timeout: seconds to wait for any responses
        :param interfaces: interfaces to listen on.
        :param ip_version: IP protocol version to use.
        :return: tuple of service type strings
        """
        local_zc = zc or Zeroconf(interfaces=interfaces, ip_version=ip_version)
        listener = cls()
        browser = ServiceBrowser(local_zc, '_services._dns-sd._udp.local.', listener=listener)

        # wait for responses
        time.sleep(timeout)

        # close down anything we opened
        if zc is None:
            local_zc.close()
        else:
            browser.cancel()

        return tuple(sorted(listener.found_services))


def get_all_addresses() -> List[str]:
    return list(
        set(
            addr.ip
            for iface in ifaddr.get_adapters()
            for addr in iface.ips
            if addr.is_IPv4 and addr.network_prefix != 32  # Host only netmask 255.255.255.255
        )
    )


def get_all_addresses_v6() -> List[int]:
    # IPv6 multicast uses positive indexes for interfaces
    try:
        nameindex = socket.if_nameindex
    except AttributeError:
        # Requires Python 3.8 on Windows. Fall back to Default.
        QuietLogger.log_warning_once(
            'if_nameindex is not available, falling back to using the default IPv6 interface'
        )
        return [0]

    return [tpl[0] for tpl in nameindex()]


def ip_to_index(adapters: List[Any], ip: str) -> int:
    if os.name != 'posix':
        # Adapter names that ifaddr reports are not compatible with what if_nametoindex expects on Windows.
        # We need https://github.com/pydron/ifaddr/pull/21 but it seems stuck on review.
        raise RuntimeError('Converting from IP addresses to indexes is not supported on non-POSIX systems')

    ipaddr = ipaddress.ip_address(ip)
    for adapter in adapters:
        for adapter_ip in adapter.ips:
            # IPv6 addresses are represented as tuples
            if isinstance(adapter_ip.ip, tuple) and ipaddress.ip_address(adapter_ip.ip[0]) == ipaddr:
                return socket.if_nametoindex(adapter.name)

    raise RuntimeError('No adapter found for IP address %s' % ip)


def ip6_addresses_to_indexes(interfaces: List[Union[str, int]]) -> List[int]:
    """Convert IPv6 interface addresses to interface indexes.

    IPv4 addresses are ignored. The conversion currently only works on POSIX
    systems.

    :param interfaces: List of IP addresses and indexes.
    :returns: List of indexes.
    """
    result = []
    adapters = ifaddr.get_adapters()

    for iface in interfaces:
        if isinstance(iface, int):
            result.append(iface)
        elif isinstance(iface, str) and ipaddress.ip_address(iface).version == 6:
            result.append(ip_to_index(adapters, iface))

    return result


def normalize_interface_choice(
    choice: InterfacesType, ip_version: IPVersion = IPVersion.V4Only
) -> List[Union[str, int]]:
    """Convert the interfaces choice into internal representation.

    :param choice: `InterfaceChoice` or list of interface addresses or indexes (IPv6 only).
    :param ip_address: IP version to use (ignored if `choice` is a list).
    :returns: List of IP addresses (for IPv4) and indexes (for IPv6).
    """
    result = []  # type: List[Union[str, int]]
    if choice is InterfaceChoice.Default:
        if ip_version != IPVersion.V4Only:
            # IPv6 multicast uses interface 0 to mean the default
            result.append(0)
        if ip_version != IPVersion.V6Only:
            result.append('0.0.0.0')
    elif choice is InterfaceChoice.All:
        if ip_version != IPVersion.V4Only:
            result.extend(get_all_addresses_v6())
        if ip_version != IPVersion.V6Only:
            result.extend(get_all_addresses())
        if not result:
            raise RuntimeError(
                'No interfaces to listen on, check that any interfaces have IP version %s' % ip_version
            )
    elif isinstance(choice, list):
        # First, take IPv4 addresses.
        result = [i for i in choice if isinstance(i, str) and ipaddress.ip_address(i).version == 4]
        # Unlike IP_ADD_MEMBERSHIP, IPV6_JOIN_GROUP requires interface indexes.
        result += ip6_addresses_to_indexes(choice)
    else:
        raise TypeError("choice must be a list or InterfaceChoice, got %r" % choice)
    return result


def new_socket(
    port: int = _MDNS_PORT, ip_version: IPVersion = IPVersion.V4Only, apple_p2p: bool = False
) -> socket.socket:
    if ip_version == IPVersion.V4Only:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    if ip_version == IPVersion.All:
        # make V6 sockets work for both V4 and V6 (required for Windows)
        try:
            s.setsockopt(_IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
        except OSError:
            log.error('Support for dual V4-V6 sockets is not present, use IPVersion.V4 or IPVersion.V6')
            raise

    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # SO_REUSEADDR should be equivalent to SO_REUSEPORT for
    # multicast UDP sockets (p 731, "TCP/IP Illustrated,
    # Volume 2"), but some BSD-derived systems require
    # SO_REUSEPORT to be specified explicitly.  Also, not all
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

    if port is _MDNS_PORT:
        ttl = struct.pack(b'B', 255)
        loop = struct.pack(b'B', 1)
        if ip_version != IPVersion.V6Only:
            # OpenBSD needs the ttl and loop values for the IP_MULTICAST_TTL and
            # IP_MULTICAST_LOOP socket options as an unsigned char.
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
        if ip_version != IPVersion.V4Only:
            # However, char doesn't work here (at least on Linux)
            s.setsockopt(_IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            s.setsockopt(_IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, True)

    if apple_p2p:
        # SO_RECV_ANYIF = 0x1104
        # https://opensource.apple.com/source/xnu/xnu-4570.41.2/bsd/sys/socket.h
        s.setsockopt(socket.SOL_SOCKET, 0x1104, 1)

    s.bind(('', port))
    return s


def add_multicast_member(
    listen_socket: socket.socket, interface: Union[str, int], apple_p2p: bool = False
) -> Optional[socket.socket]:
    # This is based on assumptions in normalize_interface_choice
    is_v6 = isinstance(interface, int)
    log.debug('Adding %r to multicast group', interface)
    try:
        if is_v6:
            iface_bin = struct.pack('@I', cast(int, interface))
            _value = _MDNS_ADDR6_BYTES + iface_bin
            listen_socket.setsockopt(_IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, _value)
        else:
            _value = _MDNS_ADDR_BYTES + socket.inet_aton(cast(str, interface))
            listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, _value)
    except socket.error as e:
        _errno = get_errno(e)
        if _errno == errno.EADDRINUSE:
            log.info(
                'Address in use when adding %s to multicast group, '
                'it is expected to happen on some systems',
                interface,
            )
            return None
        elif _errno == errno.EADDRNOTAVAIL:
            log.info(
                'Address not available when adding %s to multicast '
                'group, it is expected to happen on some systems',
                interface,
            )
            return None
        elif _errno == errno.EINVAL:
            log.info('Interface of %s does not support multicast, ' 'it is expected in WSL', interface)
            return None
        else:
            raise

    respond_socket = new_socket(
        ip_version=(IPVersion.V6Only if is_v6 else IPVersion.V4Only), apple_p2p=apple_p2p
    )
    log.debug('Configuring %s with multicast interface %s', respond_socket, interface)
    if is_v6:
        respond_socket.setsockopt(_IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, iface_bin)
    else:
        respond_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(cast(str, interface))
        )
    return respond_socket


def create_sockets(
    interfaces: InterfacesType = InterfaceChoice.All,
    unicast: bool = False,
    ip_version: IPVersion = IPVersion.V4Only,
    apple_p2p: bool = False,
) -> Tuple[Optional[socket.socket], List[socket.socket]]:
    if unicast:
        listen_socket = None
    else:
        listen_socket = new_socket(ip_version=ip_version, apple_p2p=apple_p2p)

    interfaces = normalize_interface_choice(interfaces, ip_version)

    respond_sockets = []

    for i in interfaces:
        if not unicast:
            respond_socket = add_multicast_member(cast(socket.socket, listen_socket), i, apple_p2p=apple_p2p)
        else:
            respond_socket = new_socket(port=0, ip_version=ip_version, apple_p2p=apple_p2p)

        if respond_socket is not None:
            respond_sockets.append(respond_socket)

    return listen_socket, respond_sockets


def get_errno(e: Exception) -> int:
    assert isinstance(e, socket.error)
    return cast(int, e.args[0])


def can_send_to(sock: socket.socket, address: str) -> bool:
    addr = ipaddress.ip_address(address)
    return cast(bool, addr.version == 6 if sock.family == socket.AF_INET6 else addr.version == 4)


class Zeroconf(QuietLogger):

    """Implementation of Zeroconf Multicast DNS Service Discovery

    Supports registration, unregistration, queries and browsing.
    """

    def __init__(
        self,
        interfaces: InterfacesType = InterfaceChoice.All,
        unicast: bool = False,
        ip_version: Optional[IPVersion] = None,
        apple_p2p: bool = False,
    ) -> None:
        """Creates an instance of the Zeroconf class, establishing
        multicast communications, listening and reaping threads.

        :param interfaces: :class:`InterfaceChoice` or a list of IP addresses
            (IPv4 and IPv6) and interface indexes (IPv6 only).

            IPv6 notes for non-POSIX systems:
            * IPv6 addresses are not supported, use indexes instead.
            * `InterfaceChoice.All` is an alias for `InterfaceChoice.Default`
              on Python versions before 3.8.

            Also listening on loopback (``::1``) doesn't work, use a real address.
        :param ip_version: IP versions to support. If `choice` is a list, the default is detected
            from it. Otherwise defaults to V4 only for backward compatibility.
        :param apple_p2p: use AWDL interface (only macOS)
        """
        if ip_version is None and isinstance(interfaces, list):
            has_v6 = any(
                isinstance(i, int) or (isinstance(i, str) and ipaddress.ip_address(i).version == 6)
                for i in interfaces
            )
            has_v4 = any(isinstance(i, str) and ipaddress.ip_address(i).version == 4 for i in interfaces)
            if has_v4 and has_v6:
                ip_version = IPVersion.All
            elif has_v6:
                ip_version = IPVersion.V6Only

        if ip_version is None:
            ip_version = IPVersion.V4Only

        # hook for threads
        self._GLOBAL_DONE = False
        self.unicast = unicast

        if apple_p2p == True and not platform.system() == 'Darwin':
            raise RuntimeError('Option `apple_p2p` is not supported on non-Apple platforms.')

        self._listen_socket, self._respond_sockets = create_sockets(
            interfaces, unicast, ip_version, apple_p2p=apple_p2p
        )

        self.listeners = []  # type: List[RecordUpdateListener]
        self.browsers = {}  # type: Dict[ServiceListener, ServiceBrowser]
        self.services = {}  # type: Dict[str, ServiceInfo]
        self.servicetypes = {}  # type: Dict[str, int]

        self.cache = DNSCache()

        self.condition = threading.Condition()

        self.engine = Engine(self)
        self.listener = Listener(self)
        if not unicast:
            self.engine.add_reader(self.listener, cast(socket.socket, self._listen_socket))
        else:
            for s in self._respond_sockets:
                self.engine.add_reader(self.listener, s)
        self.reaper = Reaper(self)

        self.debug = None  # type: Optional[DNSOutgoing]

    @property
    def done(self) -> bool:
        return self._GLOBAL_DONE

    def wait(self, timeout: float) -> None:
        """Calling thread waits for a given number of milliseconds or
        until notified."""
        with self.condition:
            self.condition.wait(timeout / 1000.0)

    def notify_all(self) -> None:
        """Notifies all waiting threads"""
        with self.condition:
            self.condition.notify_all()

    def get_service_info(self, type_: str, name: str, timeout: int = 3000) -> Optional[ServiceInfo]:
        """Returns network's service information for a particular
        name and type, or None if no service matches by the timeout,
        which defaults to 3 seconds."""
        info = ServiceInfo(type_, name)
        if info.request(self, timeout):
            return info
        return None

    def add_service_listener(self, type_: str, listener: ServiceListener) -> None:
        """Adds a listener for a particular service type.  This object
        will then have its add_service and remove_service methods called when
        services of that type become available and unavailable."""
        self.remove_service_listener(listener)
        self.browsers[listener] = ServiceBrowser(self, type_, listener)

    def remove_service_listener(self, listener: ServiceListener) -> None:
        """Removes a listener from the set that is currently listening."""
        if listener in self.browsers:
            self.browsers[listener].cancel()
            del self.browsers[listener]

    def remove_all_service_listeners(self) -> None:
        """Removes a listener from the set that is currently listening."""
        for listener in [k for k in self.browsers]:
            self.remove_service_listener(listener)

    def register_service(
        self, info: ServiceInfo, ttl: Optional[int] = None, allow_name_change: bool = False
    ) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service.  The name of the service may be changed if needed to make
        it unique on the network."""
        if ttl is not None:
            # ttl argument is used to maintain backward compatibility
            # Setting TTLs via ServiceInfo is preferred
            info.host_ttl = ttl
            info.other_ttl = ttl
        self.check_service(info, allow_name_change)
        self.services[info.name.lower()] = info
        if info.type in self.servicetypes:
            self.servicetypes[info.type] += 1
        else:
            self.servicetypes[info.type] = 1

        self._broadcast_service(info)

    def update_service(self, info: ServiceInfo) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service."""

        assert self.services[info.name.lower()] is not None

        self.services[info.name.lower()] = info

        self._broadcast_service(info)

    def _broadcast_service(self, info: ServiceInfo) -> None:

        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
            out.add_answer_at_time(DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, info.other_ttl, info.name), 0)
            out.add_answer_at_time(
                DNSService(
                    info.name,
                    _TYPE_SRV,
                    _CLASS_IN,
                    info.host_ttl,
                    info.priority,
                    info.weight,
                    info.port,
                    info.server,
                ),
                0,
            )

            out.add_answer_at_time(DNSText(info.name, _TYPE_TXT, _CLASS_IN, info.other_ttl, info.text), 0)
            for address in info.addresses_by_version(IPVersion.All):
                type_ = _TYPE_AAAA if _is_v6_address(address) else _TYPE_A
                out.add_answer_at_time(DNSAddress(info.server, type_, _CLASS_IN, info.host_ttl, address), 0)
            self.send(out)
            i += 1
            next_time += _REGISTER_TIME

    def unregister_service(self, info: ServiceInfo) -> None:
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
            out.add_answer_at_time(DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, 0, info.name), 0)
            out.add_answer_at_time(
                DNSService(
                    info.name, _TYPE_SRV, _CLASS_IN, 0, info.priority, info.weight, info.port, info.name
                ),
                0,
            )
            out.add_answer_at_time(DNSText(info.name, _TYPE_TXT, _CLASS_IN, 0, info.text), 0)

            for address in info.addresses_by_version(IPVersion.All):
                type_ = _TYPE_AAAA if _is_v6_address(address) else _TYPE_A
                out.add_answer_at_time(DNSAddress(info.server, type_, _CLASS_IN, 0, address), 0)
            self.send(out)
            i += 1
            next_time += _UNREGISTER_TIME

    def unregister_all_services(self) -> None:
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
                    out.add_answer_at_time(DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, 0, info.name), 0)
                    out.add_answer_at_time(
                        DNSService(
                            info.name,
                            _TYPE_SRV,
                            _CLASS_IN,
                            0,
                            info.priority,
                            info.weight,
                            info.port,
                            info.server,
                        ),
                        0,
                    )
                    out.add_answer_at_time(DNSText(info.name, _TYPE_TXT, _CLASS_IN, 0, info.text), 0)
                    for address in info.addresses_by_version(IPVersion.All):
                        type_ = _TYPE_AAAA if _is_v6_address(address) else _TYPE_A
                        out.add_answer_at_time(DNSAddress(info.server, type_, _CLASS_IN, 0, address), 0)
                self.send(out)
                i += 1
                next_time += _UNREGISTER_TIME

    def check_service(self, info: ServiceInfo, allow_name_change: bool) -> None:
        """Checks the network for a unique service name, modifying the
        ServiceInfo passed in if it is not unique."""

        # This is kind of funky because of the subtype based tests
        # need to make subtypes a first class citizen
        service_name = service_type_name(info.name)
        if not info.type.endswith(service_name):
            raise BadTypeInNameException

        instance_name = info.name[: -len(service_name) - 1]
        next_instance_number = 2

        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            # check for a name conflict
            while self.cache.current_entry_with_name_and_alias(info.type, info.name):
                if not allow_name_change:
                    raise NonUniqueNameException

                # change the name and look for a conflict
                info.name = '%s-%s.%s' % (instance_name, next_instance_number, info.type)
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
            out.add_authorative_answer(DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, info.other_ttl, info.name))
            self.send(out)
            i += 1
            next_time += _CHECK_TIME

    def add_listener(self, listener: RecordUpdateListener, question: Optional[DNSQuestion]) -> None:
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

    def remove_listener(self, listener: RecordUpdateListener) -> None:
        """Removes a listener."""
        try:
            self.listeners.remove(listener)
            self.notify_all()
        except Exception as e:  # TODO stop catching all Exceptions
            log.exception('Unknown error, possibly benign: %r', e)

    def update_record(self, now: float, rec: DNSRecord) -> None:
        """Used to notify listeners of new information that has updated
        a record."""
        for listener in self.listeners:
            listener.update_record(self, now, rec)
        self.notify_all()

    def handle_response(self, msg: DNSIncoming) -> None:
        """Deal with incoming response packets.  All answers
        are held in the cache, and listeners are notified."""
        now = current_time_millis()
        for record in msg.answers:
            if record.unique:  # https://tools.ietf.org/html/rfc6762#section-10.2
                for entry in self.cache.entries():
                    if DNSEntry.__eq__(entry, record) and (record.created - entry.created > 1000):
                        self.cache.remove(entry)

            expired = record.is_expired(now)
            entry = self.cache.get(record)
            if not expired:
                if entry is not None:
                    entry.reset_ttl(record)
                else:
                    self.cache.add(record)
                self.update_record(now, record)
            else:
                if entry is not None:
                    self.update_record(now, record)
                    self.cache.remove(entry)

    def handle_query(self, msg: DNSIncoming, addr: Optional[str], port: int) -> None:
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
                        out.add_answer(
                            msg,
                            DNSPointer(
                                "_services._dns-sd._udp.local.", _TYPE_PTR, _CLASS_IN, _DNS_OTHER_TTL, stype
                            ),
                        )
                for service in self.services.values():
                    if question.name == service.type:
                        if out is None:
                            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
                        out.add_answer(
                            msg,
                            DNSPointer(service.type, _TYPE_PTR, _CLASS_IN, service.other_ttl, service.name),
                        )

                        # Add recommended additional answers according to
                        # https://tools.ietf.org/html/rfc6763#section-12.1.
                        out.add_additional_answer(
                            DNSService(
                                service.name,
                                _TYPE_SRV,
                                _CLASS_IN | _CLASS_UNIQUE,
                                service.host_ttl,
                                service.priority,
                                service.weight,
                                service.port,
                                service.server,
                            )
                        )
                        out.add_additional_answer(
                            DNSText(
                                service.name,
                                _TYPE_TXT,
                                _CLASS_IN | _CLASS_UNIQUE,
                                service.other_ttl,
                                service.text,
                            )
                        )
                        for address in service.addresses_by_version(IPVersion.All):
                            type_ = _TYPE_AAAA if _is_v6_address(address) else _TYPE_A
                            out.add_additional_answer(
                                DNSAddress(
                                    service.server,
                                    type_,
                                    _CLASS_IN | _CLASS_UNIQUE,
                                    service.host_ttl,
                                    address,
                                )
                            )
            else:
                try:
                    if out is None:
                        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)

                    # Answer A record queries for any service addresses we know
                    if question.type in (_TYPE_A, _TYPE_ANY):
                        for service in self.services.values():
                            if service.server == question.name.lower():
                                for address in service.addresses_by_version(IPVersion.All):
                                    type_ = _TYPE_AAAA if _is_v6_address(address) else _TYPE_A
                                    out.add_answer(
                                        msg,
                                        DNSAddress(
                                            question.name,
                                            type_,
                                            _CLASS_IN | _CLASS_UNIQUE,
                                            service.host_ttl,
                                            address,
                                        ),
                                    )

                    name_to_find = question.name.lower()
                    if name_to_find not in self.services:
                        continue
                    service = self.services[name_to_find]

                    if question.type in (_TYPE_SRV, _TYPE_ANY):
                        out.add_answer(
                            msg,
                            DNSService(
                                question.name,
                                _TYPE_SRV,
                                _CLASS_IN | _CLASS_UNIQUE,
                                service.host_ttl,
                                service.priority,
                                service.weight,
                                service.port,
                                service.server,
                            ),
                        )
                    if question.type in (_TYPE_TXT, _TYPE_ANY):
                        out.add_answer(
                            msg,
                            DNSText(
                                question.name,
                                _TYPE_TXT,
                                _CLASS_IN | _CLASS_UNIQUE,
                                service.other_ttl,
                                service.text,
                            ),
                        )
                    if question.type == _TYPE_SRV:
                        for address in service.addresses_by_version(IPVersion.All):
                            type_ = _TYPE_AAAA if _is_v6_address(address) else _TYPE_A
                            out.add_additional_answer(
                                DNSAddress(
                                    service.server,
                                    type_,
                                    _CLASS_IN | _CLASS_UNIQUE,
                                    service.host_ttl,
                                    address,
                                )
                            )
                except Exception:  # TODO stop catching all Exceptions
                    self.log_exception_warning()

        if out is not None and out.answers:
            out.id = msg.id
            self.send(out, addr, port)

    def send(self, out: DNSOutgoing, addr: Optional[str] = None, port: int = _MDNS_PORT) -> None:
        """Sends an outgoing packet."""
        packet = out.packet()
        if len(packet) > _MAX_MSG_ABSOLUTE:
            self.log_warning_once("Dropping %r over-sized packet (%d bytes) %r", out, len(packet), packet)
            return
        log.debug('Sending %r (%d bytes) as %r...', out, len(packet), packet)
        for s in self._respond_sockets:
            if self._GLOBAL_DONE:
                return
            try:
                if addr is None:
                    real_addr = _MDNS_ADDR6 if s.family == socket.AF_INET6 else _MDNS_ADDR
                elif not can_send_to(s, addr):
                    continue
                else:
                    real_addr = addr
                bytes_sent = s.sendto(packet, 0, (real_addr, port))
            except Exception as exc:  # TODO stop catching all Exceptions
                if (
                    isinstance(exc, OSError)
                    and exc.errno == errno.ENETUNREACH
                    and s.family == socket.AF_INET6
                ):
                    # with IPv6 we don't have a reliable way to determine if an interface actually has IPv6
                    # support, so we have to try and ignore errors.
                    continue
                # on send errors, log the exception and keep going
                self.log_exception_warning()
            else:
                if bytes_sent != len(packet):
                    self.log_warning_once('!!! sent %d out of %d bytes to %r' % (bytes_sent, len(packet), s))

    def close(self) -> None:
        """Ends the background threads, and prevent this instance from
        servicing further queries."""
        if not self._GLOBAL_DONE:
            # remove service listeners
            self.remove_all_service_listeners()
            self.unregister_all_services()
            self._GLOBAL_DONE = True

            # shutdown recv socket and thread
            if not self.unicast:
                self.engine.del_reader(cast(socket.socket, self._listen_socket))
                cast(socket.socket, self._listen_socket).close()
            else:
                for s in self._respond_sockets:
                    self.engine.del_reader(s)
            self.engine.join()

            # shutdown the rest
            self.notify_all()
            self.reaper.join()
            for s in self._respond_sockets:
                s.close()
