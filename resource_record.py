from enum import Enum

from util import Rdata

from util import Rdata, domain_to_label

dns_question_template = '''QNAME: {}
QTYPE: {}
QCLASS: {}
OFFSET: {}'''

dns_questions_section_template = '''
DECODED QUESTIONS SECTION:
{}

RAW QUESTIONS SECTION:
{}
'''


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

    HTTPS = 65

    OPT = 41


class RrClass(Enum):
    # The Internet
    IN = 1

    # CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS = 2

    # CHAOS class
    CH = 3

    # Hesiod [Dyer 87]
    HS = 4


class DnsQuestion:
    def __init__(self, domain: str, qtype: RrType, qclass: RrClass):
        self.domain = domain
        self.qname = domain_to_label(domain)
        self.qtype = qtype
        print("THE QTYPE IS: {}".format(self.qtype.value))
        self.qclass = qclass
        print("THE QCLASS IS: {}".format(self.qclass.value))

    def create_answer(self, rdata: Rdata, ttl):
        return ResourceRecord(
            self.qname,
            self.qtype,
            self.qclass,
            ttl,
            rdata
        ).build()

    def build(self) -> bytearray:
        data = bytearray([])
        data += self.qname
        data += self.qtype.value.to_bytes(2, "big")
        data += self.qclass.value.to_bytes(2, "big")

        print("QUESTION DATA PACKED: ", data.hex())

        return data

    def get_domain(self) -> str:

        return self.domain

    def get_name(self) -> bytearray:

        # Domain name represented as a sequence of labels, where
        # each label consists of a length octet followed by that
        # number of octets.  The domain name terminates with the
        # zero length octet for the null label of the root.  Note
        # that this field may be an odd number of octets; no
        # padding is used.

        return self.qname

    def get_class(self) -> int:

        # Two octet code that specifies the class of the query.
        # For example, the QCLASS field is IN for the Internet.

        return self.qclass

    def get_type(self) -> int:

        # Two octet code which specifies the type of the query.
        # The values for this field include all codes valid for a
        # TYPE field, together with some more general codes which
        # can match more than one type of RR.

        return self.qtype

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
            self.get_name(),
            self.get_type(),
            self.get_class(),
            self.domain
        )


class ResourceRecord:
    def __init__(self, question: DnsQuestion, ttl: int, rdata: Rdata):

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
        self.question = question
        self.ttl = ttl
        self.rdata = rdata

    def build(self) -> bytearray:
        self.data = bytearray([])
        # self.data += self.question.qname  # bytearray(b'\x04rick\x03dom\x00')
        # self.data += self.question.qtype.value.to_bytes(2, "big")
        # self.data += self.question.qclass.value.to_bytes(2, "big")
        self.data += self.question.build()
        self.data += self.ttl.to_bytes(4, "big")

        rdata_as_bytes = self.rdata.build()

        self.data += len(rdata_as_bytes).to_bytes(2, "big")

        self.data += rdata_as_bytes

        return self.data

    def get_as_bytes(self) -> bytearray:
        return self.build()


class DnsQuestionsSection:
    def __init__(self, question_data: bytearray, question_count: int):

        self.data = question_data
        self.question_count = question_count

    def get_as_bytes(self) -> bytearray:
        return self.data

    def __str__(self) -> str:
        return dns_questions_section_template.format(
            self.get_first_question().__str__(),
            # self.data.hex()
            bin(int.from_bytes(self.data, "big"))
        )

    def get_first_question(self) -> DnsQuestion:

        # DNS MESSAGE QUESTION SECTION STARTS AT
        # BYTE 13 AND ENDS WITH A SINGLE NULL TERMINATOR 00 AT THE END

        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # | LN | LABEL | LN | LABEL...                    |
        # /                     QNAME                     /
        # /                                      | NULL   /
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                     QTYPE                     |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                     QCLASS                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        # Each question starts with one byte that I have called LN.
        # This byte tells you the length of the next "label".

        # Labels are each word that is separated by a dot in a domain name. Ex, ["docs", "google", "com"]

        # When a null terminator is reached, the final character of a single domain
        # has been reached. QTYPE, and QNAME are 2 bytes each and come right after
        # the null terminator.

        labels: list[str] = []

        # Keep track of where the last offset was
        # so we can know where QTYPE and QCLASS starts

        label_offset = 0

        # Not RFC compliant but we're stopping at 10 sub domains + 1 TLD

        for _ in range(0, 11):

            # Read the first byte of the questions section which tells
            # you the length of the next label

            label_length = int.from_bytes(
                self.data[label_offset:label_offset+1], "big")

            # If the label is a null terminator then, that means the QTYPE and QCLASS
            # fields have started

            if label_length == 0:
                break

            # Move past the one byte length

            label_offset += 1

            # Read all bytes between the current offset and the length of the next label
            # then convert the bytes to readable characters

            label_content = self.data[
                label_offset:
                label_offset+label_length
            ].decode()

            # Add the piece of a full domain to the labels list

            labels.append(label_content)

            # Start the next iteration at an ofset equal to the end of the current label

            label_offset += label_length

        # Move past the one byte NULL terminator

        label_offset += label_length+1

        qname = '.'.join(labels)

        qtype = int.from_bytes(self.data[label_offset:label_offset+2], "big")

        qclass = int.from_bytes(
            self.data[label_offset+2:label_offset+4], "big")

        # The start of the first questions label is immediately after the 12 byte header.
        # This offset will be used to reference these labels without having to re-write
        # their data again in the answer section

        # offset_in_message = 12

        return DnsQuestion(
            qname,
            RrType(qtype),
            RrClass(qclass),
        )
