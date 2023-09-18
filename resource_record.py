from enum import Enum


class RrType(Enum):
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

    AAAA = 28


class RrClass(Enum):
    # The Internet
    IN = 1

    # CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS = 2

    # CHAOS class
    CH = 3

    # Hesiod [Dyer 87]
    HS = 4


def create_ipv4_address_rdata(n1: int, n2: int, n3: int, n4: int) -> bytearray:
    return bytearray([n1, n2, n3, n4])


def domain_to_label(domain_name: str) -> bytes:
    labels = b''

    for part in domain_name.split("."):
        labels += len(part).to_bytes(1, "big")
        labels += bytes(part, "utf-8")

    labels += b'\0x00'

    return labels


class ResourceRecord:
    def __init__(self, label: bytearray, rr_type: RrType, rr_class: RrClass, ttl: int, rdata: bytearray):

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

        self.data = bytearray([])
        self.name = label
        self.rr_type = rr_type
        self.rr_class = rr_class
        self.ttl = ttl
        self.rd_length = len(rdata)
        self.rdata = rdata

    def build(self):
        self.data = bytearray([])
        self.data += self.name  # bytearray(b'\x04rick\x03dom\x00')
        self.data += self.rr_type.value.to_bytes(2, "big")
        self.data += self.rr_class.value.to_bytes(2, "big")
        self.data += self.ttl.to_bytes(4, "big")
        self.data += self.rd_length.to_bytes(2, "big")
        self.data += self.rdata

        return self.data

    def get_as_bytes(self) -> bytearray:
        self.build()
        return self.data
