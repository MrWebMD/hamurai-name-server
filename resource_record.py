from enum import Enum

import rdata
import question


class RrClass(Enum):
    # The Internet
    IN = 1

    # CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS = 2

    # CHAOS class
    CH = 3

    # Hesiod [Dyer 87]
    HS = 4


class RrType(Enum):
    """A list of resource types defined by the DNS RFC 
    https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
    """
    A = 1  # a host address

    NS = 2  # an authoritative name server

    MD = 3  # a mail destination (Obsolete - use MX)

    MF = 4  # a mail forwarder (Obsolete - use MX)

    CNAME = 5  # the canonical name for an alias

    SOA = 6  # marks the start of a zone of authority

    MB = 7  # a mailbox domain name (EXPERIMENTAL)

    MG = 8  # a mail group member (EXPERIMENTAL)

    MR = 9  # a mail rename domain name (EXPERIMENTAL)

    NULL = 10  # a null RR (EXPERIMENTAL)

    WKS = 11  # a well known service description

    PTR = 12  # a domain name pointer

    HINFO = 13  # host information

    MINFO = 14  # mailbox or mail list information

    MX = 15  # mail exchange

    TXT = 16  # text strings

    AAAA = 28  # An IPv6 A record

    HTTPS = 65

    OPT = 41


class ResourceRecord:
    def __init__(self, question: 'question.DnsQuestion', ttl: int, rdata: 'rdata.Rdata'):

        #                                 1  1  1  1  1  1
        #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                                               |
        # /                                               /
        # /                      NAME                     /
        # |                                               |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |               TYPE (QTYPE, RrType)            |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                     CLASS                     |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                      TTL                      |
        # |                                               |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                   RDLENGTH                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        # /                     RDATA                     /
        # /                                               /
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        self._data = bytearray([])
        self._question = question
        self._ttl = ttl
        self._rdata = rdata

    @property
    def question(self):
        return self._question

    @question.setter
    def question(self, question: 'question.DnsQuestion'):
        self._question = question

    @property
    def rr_name(self):
        return self._question.name

    @property
    def rr_type(self):
        return self._question.qtype

    @property
    def rr_class(self):
        return self._question.qclass

    @property
    def rr_rdata(self):
        return self._rdata.bytes

    @property
    def ttl(self):
        return self._ttl

    @ttl.setter
    def ttl(self, ttl: int):
        self._ttl = ttl

    @property
    def bytes(self) -> bytearray:
        self._data = bytearray([])
        self._data += self._question.bytes
        self._data += self._ttl.to_bytes(4, "big")

        rdata_as_bytes = self._rdata.bytes

        self._data += len(rdata_as_bytes).to_bytes(2, "big")

        self._data += rdata_as_bytes

        return self._data
