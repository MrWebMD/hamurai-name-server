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

        self.data = header_data

        self.header_byte_1_2 = int.from_bytes(self.data[:2], "big")
        self.header_byte_3 = self.data[2]
        self.header_byte_4 = self.data[3]
        self.header_byte_5_6 = int.from_bytes(self.data[4:6], "big")
        self.header_byte_7_8 = int.from_bytes(self.data[6:8], "big")
        self.header_byte_9_10 = int.from_bytes(self.data[8:10], "big")
        self.header_byte_10_12 = int.from_bytes(self.data[10:12], "big")

    def get_as_bytes(self) -> bytearray:
        return self.data

    def get_transaction_id(self) -> int:

        # A 16 bit identifier assigned by the program that
        # generates any kind of query.  This identifier is copied
        # the corresponding reply and can be used by the requester
        # to match up replies to outstanding queries.

        return self.header_byte_1_2  # ID

    def get_query_or_response(self) -> int:

        # A one bit field that specifies whether this
        # message is a query (0), or a response (1).

        return 1 if 0b10000000 & self.header_byte_3 > 0 else 0  # QR

    def set_query_or_response(self, bit_value: int) -> None:
        flag_byte = self.header_byte_3

        if bit_value == 0:
            self.header_byte_3 = flag_byte & 0b01111111
        else:
            self.header_byte_3 = flag_byte | 0b10000000

        self.data[2] = self.header_byte_3

    def get_operation_code(self) -> int:

        # A four bit field that specifies kind of query in this
        # message.  This value is set by the originator of a query
        # and copied into the response.  The values are:

        # 0               a standard query (QUERY)
        # 1               an inverse query (IQUERY)
        # 2               a server status request (STATUS)
        # 3-15            reserved for future use

        return 0b01111000 & self.header_byte_3  # OPCODE

    def get_operation_code_str(self) -> str:

        operation_code_map = {
            0: "Standard Query (QUERY)",
            1: "Inverse Query (IQUERY)",
            2: "Server Status Request (STATUS)"
        }

        try:
            return operation_code_map[self.get_operation_code()]
        except Exception:
            return "Operation code doesn't exist"

    def get_authoritative_answer(self) -> int:

        # This bit is valid in responses,
        # and specifies that the responding name server is an
        # authority for the domain name in the question section.

        return 0b00000100 & self.header_byte_3  # AA

    def get_truncation(self) -> int:

        # Specifies that this message was truncated
        # due to length greater than that permitted on the
        # transmission channel.

        return 0b00000010 & self.header_byte_3  # TC

    def get_recursion_desired(self) -> int:

        # This bit may be set in a query and
        # is copied into the response.  If RD is set, it directs
        # the name server to pursue the query recursively.
        # Recursive query support is optional.

        return 0b00000001 & self.header_byte_3  # RD

    def get_recursion_available(self) -> int:

        # This be is set or cleared in a
        # response, and denotes whether recursive query support is
        # available in the name server.

        return 0b10000000 & self.header_byte_4  # RA

    def get_reserved_z(self) -> int:

        # Must always stay zero, reserved for future use

        return 0b01110000 & self.header_byte_4  # Z

    def get_response_code(self) -> int:

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

        return 0b00001111 & self.header_byte_4

    def get_response_code_str(self) -> str:

        response_code_map = {
            0: "No Error Condition",
            1: "Server Failure",
            3: "Name Error",
            4: "Not Implemented",
            5: "Refused"
        }

        try:
            return response_code_map[self.get_response_code()]
        except Exception:
            return "Response code doesn't exist"

    def set_response_code(self, rcode: Rcode) -> None:

        rcode_int = Rcode(rcode).value

        new_byte_4_value = (self.data[3] & 0b11110000) + rcode_int

        print('Response code set to {}'.format(bin(new_byte_4_value)))

        self.header_byte_4 = new_byte_4_value

        self.data[3] = new_byte_4_value

    def get_question_count(self) -> int:

        # Unsigned 16 bit integer specifying the number of
        # entries in the question section.

        return self.header_byte_5_6  # QDCOUNT

    def get_answer_count(self) -> int:

        # Unsigned 16 bit integer specifying the number of
        # resource records in the answer section.

        return self.header_byte_7_8  # ANCOUNT

    def set_answer_count(self, value: int) -> int:
        self.header_byte_7_8 = value
        self.data[6:8] = value.to_bytes(2, "big")

    def get_name_server_count(self) -> int:

        # Unsigned 16 bit integer specifying the number of name
        # server resource records in the authority records
        # section.

        return self.header_byte_9_10  # NSCOUNT

    def set_name_server_count(self, value: int) -> None:
        ns_count = value.to_bytes(2, "big")
        self.header_byte_9_10 = value
        self.data[8:10] = ns_count

    def get_additional_record_count(self) -> int:

        # Unsigned 16 bit integer specifying the number of
        # resource records in the additional records section.

        return self.header_byte_10_12  # ARCOUNT

    def __str__(self):

        return dns_header_template.format(
            '\n'.join(wrap(self.data.hex(), 48)),
            self.get_transaction_id(),
            self.get_operation_code_str(),
            self.get_response_code_str(),
            self.get_query_or_response(),
            self.get_reserved_z(),
            self.get_authoritative_answer(),
            self.get_question_count(),
            self.get_truncation(),
            self.get_answer_count(),
            self.get_recursion_desired(),
            self.get_name_server_count(),
            self.get_recursion_available(),
            self.get_additional_record_count()
        )
