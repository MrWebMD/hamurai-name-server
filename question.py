import resource_record
import util
import rdata

dns_question_template = '''QNAME: {}
QTYPE: {}
QCLASS: {}
OFFSET: {}'''


class DnsQuestion:
    def __init__(self, domain: str, qtype: 'resource_record.RrType', qclass: 'resource_record.RrClass'):
        """_summary_

        Args:
            domain (str):
            qtype (resource_record.RrType):
            qclass (resource_record.RrClass):
        """

        self._domain = domain
        self._qname = util.domain_to_label(domain)
        self._qtype = qtype
        self._qclass = qclass

    def create_answer(self, rdata: 'rdata.Rdata', ttl: int) -> bytearray:
        return resource_record.ResourceRecord(
            self._qname,
            self._qtype,
            self._qclass,
            ttl,
            rdata
        ).bytes

    @property
    def bytes(self) -> bytearray:
        data = bytearray([])
        data += self._qname
        data += self._qtype.value.to_bytes(2, "big")
        data += self._qclass.value.to_bytes(2, "big")

        return data

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def name(self) -> bytearray:
        """Domain name represented as a sequence of labels, where
        each label consists of a length octet followed by that
        number of octets.  The domain name terminates with the
        zero length octet for the null label of the root.  Note
        that this field may be an odd number of octets; no
        padding is used.
        """
        return self._qname

    @property
    def qclass(self) -> int:
        """Two octet code that specifies the class of the query.
        For example, the QCLASS field is IN for the Internet.
        """

        return self._qclass

    @property
    def qtype(self) -> int:
        """Two octet code which specifies the type of the query.
        The values for this field include all codes valid for a
        TYPE field, together with some more general codes which
        can match more than one type of RR.
        """

        return self._qtype

    # def get_label_pointer(self) -> bytearray:

        # In order to reduce the size of messages, the domain system utilizes a
        # compression scheme which eliminates the repetition of domain names in a
        # message.  In this scheme, an entire domain name or a list of labels at
        # the end of a domain name is replaced with a pointer to a prior occurance
        # of the same name.

        # The pointer takes the form of a two octet sequence:

        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # | 1  1|                OFFSET                   |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        # return (0b1100000000000000 + self.label_pointer).to_bytes(2, "big")

    def __str__(self) -> str:
        return dns_question_template.format(
            self._qname,
            self._qtype,
            self._qclass,
            self._domain
        )
