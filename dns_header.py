from textwrap import wrap
from enum import Enum
dns_header_template = '''**************** RAW DNS HEADER ****************
{}
**************** DECODED HEADER ****************

ID: {}
OPCODE: {}
RCODE: {}
QR: {}\t\t\tZ: {}
AA: {}\t\t\tQDCOUNT: {}
TC: {}\t\t\tANCOUNT: {}
RD: {}\t\t\tNSCOUNT: {}
RA: {}\t\t\tARCOUNT: {}'''


class Rcode(Enum):
    NO_ERROR_CONDITION = 0
    SERVER_FAILURE = 1
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5


class OperationCode(Enum):
    STANDARD_QUERY = 0  # QUERY
    INVERSE_QUERY = 1  # IQUERY
    SERVER_STATUS_REQUEST = 2  # STATUS


class QueryOrResponse(Enum):
    QUERY = 0
    RESPONSE = 1


class DnsHeaderSection:
    def __init__(self, header_data: bytearray):

        # DNS MESSAGE HEADER STARTS AT
        # BYTE 1 AND ENDS AT BYTE 12 INCLUSIVE
        #                                 1  1  1  1  1  1
        #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                      ID                       |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    QDCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    ANCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    NSCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                    ARCOUNT                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        if len(header_data) == 0:
            header_data = bytearray(b'\0'*12)

        self._data = header_data

        self._header_byte_1_2 = int.from_bytes(self._data[:2], "big")
        self._header_byte_3 = self._data[2]
        self._header_byte_4 = self._data[3]
        self._header_byte_5_6 = int.from_bytes(self._data[4:6], "big")
        self._header_byte_7_8 = int.from_bytes(self._data[6:8], "big")
        self._header_byte_9_10 = int.from_bytes(self._data[8:10], "big")
        self._header_byte_10_12 = int.from_bytes(self._data[10:12], "big")

    @property
    def bytes(self) -> bytearray:
        return self._data

    @property
    def transaction_id(self) -> int:

        # A 16 bit identifier assigned by the program that
        # generates any kind of query.  This identifier is copied
        # the corresponding reply and can be used by the requester
        # to match up replies to outstanding queries.

        return self._header_byte_1_2  # ID

    @transaction_id.setter
    def transaction_id(self, transaction_id: int) -> None:

        self._data[:2] = transaction_id.to_bytes(2, "big")

        self._header_byte_1_2 = int.from_bytes(self._data[:2], "big")

        return

    @property
    def query_or_response(self) -> 'QueryOrResponse':

        # A one bit field that specifies whether this
        # message is a query (0), or a response (1).

        # QR
        return QueryOrResponse(1 if 0b10000000 & self._header_byte_3 > 0 else 0)

    @query_or_response.setter
    def query_or_response(self, qr: 'QueryOrResponse') -> None:
        if qr.name == "QUERY":
            self._header_byte_3 &= 0b01111111
        else:
            self._header_byte_3 |= 0b10000000

        self._data[2] = self._header_byte_3

    @property
    def operation_code(self) -> 'OperationCode':

        # A four bit field that specifies kind of query in this
        # message.  This value is set by the originator of a query
        # and copied into the response.  The values are:

        # 0               a standard query (QUERY)
        # 1               an inverse query (IQUERY)
        # 2               a server status request (STATUS)
        # 3-15            reserved for future use

        return OperationCode(0b01111000 & self._header_byte_3)  # OPCODE

    @operation_code.setter
    def operation_code(self, op_code: 'OperationCode') -> None:

        self._header_byte_3 = (
            self._header_byte_3 & 0b10000111) + (op_code.value << 3)

        self._data[2] = self._header_byte_3

    @property
    def authoritative_answer(self) -> int:

        # This bit is valid in responses,
        # and specifies that the responding name server is an
        # authority for the domain name in the question section.

        return 0b00000100 & self._header_byte_3  # AA

    @authoritative_answer.setter
    def authoritative_answer(self, is_authoritative: bool) -> None:

        flag_byte = self._header_byte_3

        if is_authoritative:
            self._header_byte_3 |= 0b00000100
        else:
            self._header_byte_3 &= 0b11111011

        self._data[2] = self._header_byte_3

    @property
    def truncation(self) -> int:

        # Specifies that this message was truncated
        # due to length greater than that permitted on the
        # transmission channel.

        return 0b00000010 & self._header_byte_3  # TC

    @truncation.setter
    def truncation(self, is_truncated: bool) -> None:
        if is_truncated:
            self._header_byte_3 |= 0b00000010
        else:
            self._header_byte_3 &= 0b11111101

        self._data[2] = self._header_byte_3

    @property
    def recursion_desired(self) -> int:

        # This bit may be set in a query and
        # is copied into the response.  If RD is set, it directs
        # the name server to pursue the query recursively.
        # Recursive query support is optional.

        return 0b00000001 & self._header_byte_3  # RD

    @recursion_desired.setter
    def recursion_desired(self, recursion_desired: bool) -> None:
        if recursion_desired:
            self._header_byte_3 |= 0b00000001
        else:
            self._header_byte_3 &= 0b11111110

        self._data[2] = self._header_byte_3

    @property
    def recursion_available(self) -> int:

        # This be is set or cleared in a
        # response, and denotes whether recursive query support is
        # available in the name server.

        return 0b10000000 & self._header_byte_4  # RA

    @recursion_available.setter
    def recursion_available(self, recursion_available: bool) -> None:
        if recursion_available:
            self._header_byte_4 |= 0b10000000
        else:
            self._header_byte_4 &= 0b01111111

        self._data[3] = self._header_byte_4

    @property
    def reserved_z(self) -> int:

        # Must always stay zero, reserved for future use

        return 0b01110000 & self._header_byte_4  # Z

    @reserved_z.setter
    def set_reserved_z(self, z_value: int) -> None:

        self._header_byte_4 &= 0b10001111
        self._header_byte_4 |= z_value << 4
        self._data[3] = self._header_byte_4

    @property
    def response_code(self) -> Rcode:

        # 0 = No error condition

        # 1 = Format error - The name server was
        #     unable to interpret the query.

        # 2 = Server failure - The name server was
        #     unable to process this query due to a
        #     problem with the name server.

        # 3 = Name Error (404)

        # 4 = Not Implemented - The name server does
        #     not support the requested kind of query.

        # 5 = Refused - The name server refuses to perform the specified operation for policy reasons.

        return Rcode(0b00001111 & self._header_byte_4)

    @response_code.setter
    def response_code(self, rcode: 'Rcode') -> None:

        self._header_byte_4 = (self._data[3] & 0b11110000) + Rcode(rcode).value

        self._data[3] = self._header_byte_4

    @property
    def question_count(self) -> int:

        # Unsigned 16 bit integer specifying the number of
        # entries in the question section.

        return self._header_byte_5_6  # QDCOUNT

    @question_count.setter
    def question_count(self, value: int) -> None:

        self._header_byte_5_6 = value
        self._data[4:6] = value.to_bytes(2, "big")

    @property
    def answer_count(self) -> int:

        # Unsigned 16 bit integer specifying the number of
        # resource records in the answer section.

        return self._header_byte_7_8  # ANCOUNT

    @answer_count.setter
    def answer_count(self, value: int) -> None:
        self._header_byte_7_8 = value
        self._data[6:8] = value.to_bytes(2, "big")

    @property
    def name_server_count(self) -> int:

        # Unsigned 16 bit integer specifying the number of name
        # server resource records in the authority records
        # section.

        return self._header_byte_9_10  # NSCOUNT

    @name_server_count.setter
    def name_server_count(self, value: int) -> None:
        self._header_byte_9_10 = value
        self._data[8:10] = value.to_bytes(2, "big")

    @property
    def additional_record_count(self) -> int:

        # Unsigned 16 bit integer specifying the number of
        # resource records in the additional records section.

        return self._header_byte_10_12  # ARCOUNT

    @additional_record_count.setter
    def additional_record_count(self, value: int) -> None:
        self._header_byte_10_12 = value.to_bytes(2, "big")
        self.data[9:12] = self._header_byte_10_12

    def __str__(self):

        return dns_header_template.format(
            '\n'.join(wrap(self._data.hex(), 48)),
            self.transaction_id,
            self.operation_code,
            self.response_code,
            self.query_or_response,
            self.reserved_z,
            self.authoritative_answer,
            self.question_count,
            self.truncation,
            self.answer_count,
            self.recursion_desired,
            self.name_server_count,
            self.recursion_available,
            self.additional_record_count
        )
