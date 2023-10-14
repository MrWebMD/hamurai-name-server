from enum import Enum
import util


class RdataType(Enum):
    RAW = 0
    IPV4 = 1
    DOMAIN = 2


class Rdata:
    def __init__(self, rdata_type: RdataType, value: bytes):
        """An implementation of DNS RDATA fields within RRs. Supports converting
        domains and ip addresses into octet streams to be used as an RDATA field. 
        Optional specify raw bytes without transformation

        No Support for message compression

        https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3

        Args:
            rdata_type (RdataType):  Is the value an ip address or domain?
            value (bytes): The value as bytes which represents a domain or ipv4 address. Ex: b'127.0.0.1', b'website.com'
        """

        self._type = rdata_type
        self._value = value

    @property
    def type(self) -> RdataType:
        return self._type

    @type.setter
    def type(self, rdata_type: 'RdataType') -> None:
        self._type = rdata_type

    @property
    def bytes(self) -> bytearray:
        if self._type.name == "DOMAIN":
            return util.domain_to_label(self._value.decode())
        elif self._type.name == "IPV4":
            ip_bytes = []
            for octet_str in self._value.decode("utf-8").split("."):
                ip_bytes.append(int(octet_str))
            return util.create_ipv4_address_rdata(ip_bytes)
        elif self._type.name == "RAW":
            return self._value


# 4.3. The fixed part of an OPT RR is structured as follows:

#      Field Name   Field Type     Description
#      ------------------------------------------------------
#      NAME         domain name    empty (root domain)
#      TYPE         u_int16_t      OPT
#      CLASS        u_int16_t      sender's UDP payload size
#      TTL          u_int32_t      extended RCODE and flags
#      RDLEN        u_int16_t      describes RDATA
#      RDATA        octet stream   {attribute,value} pairs

# The variable part of an OPT RR may contain zero or more options in
# the RDATA.  Each option MUST be treated as a bit field.  Each option
# is encoded as:

#               +0 (MSB)                            +1 (LSB)
#     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
# 0: |                          OPTION-CODE                          |
#     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
# 2: |                         OPTION-LENGTH                         |
#     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
# 4: |                                                               |
#     /                          OPTION-DATA                          /
#     /                                                               /
#     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

# OPTION-CODE
#   Assigned by the Expert Review process as defined by the DNSEXT
#   working group and the IESG.

# OPTION-LENGTH
#   Size (in octets) of OPTION-DATA.

# OPTION-DATA
#   Varies per OPTION-CODE.  MUST be treated as a bit field.


class OptRdata(Rdata):
    def __init__(self, rdata_type: RdataType, value: bytes):
        """https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.2
        Args:
            rdata_type (RdataType): _description_
            value (bytes): _description_
        """
        super().__init__(rdata_type, value)

    @property
    def bytes(self) -> bytearray:
        return b''
