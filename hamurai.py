import socket
import signal
from dns_header import DnsHeaderSection, Rcode, QueryOrResponse, OperationCode
from resource_record import ResourceRecord, RrType, DnsQuestionsSection, DnsQuestion
from util import Rdata, RdataType

DNS_PORT = 53
IP_ADDRESS = "0.0.0.0"

# https://datatracker.ietf.org/doc/html/rfc1035

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def get_server_error_dns_response():
    response = bytearray([])

    res_dns_header_section = DnsHeaderSection([])

    res_dns_header_section.set_answer_count(0)

    res_dns_header_section.set_question_count(0)

    res_dns_header_section.set_transaction_id(1)

    res_dns_header_section.set_query_or_response(QueryOrResponse.RESPONSE)

    res_dns_header_section.set_authoritative_answer(True)

    res_dns_header_section.set_operation_code(
        op_code=OperationCode.STANDARD_QUERY)
    res_dns_header_section.set_truncation(False)

    res_dns_header_section.set_recursion_desired(False)

    res_dns_header_section.set_recursion_available(False)

    res_dns_header_section.set_response_code(Rcode.SERVER_FAILURE)

    response += res_dns_header_section.get_as_bytes()

    return response


def get_404_dns_response(req_dns_header_section: DnsHeaderSection, question: DnsQuestion) -> bytearray:
    response = bytearray([])

    res_dns_header_section = DnsHeaderSection([])

    res_dns_header_section.set_answer_count(0)

    res_dns_header_section.set_question_count(1)

    res_dns_header_section.set_transaction_id(
        req_dns_header_section.get_transaction_id()
    )
    res_dns_header_section.set_query_or_response(QueryOrResponse.RESPONSE)

    res_dns_header_section.set_authoritative_answer(False)

    res_dns_header_section.set_operation_code(
        op_code=OperationCode.STANDARD_QUERY)

    res_dns_header_section.set_truncation(False)

    res_dns_header_section.set_recursion_desired(False)

    res_dns_header_section.set_recursion_available(False)

    res_dns_header_section.set_response_code(Rcode.NAME_ERROR)

    response += res_dns_header_section.get_as_bytes()

    response += question.build()

    return response


def request_handler(data: bytearray, addr):

    req_dns_header_section = DnsHeaderSection(data[:12])

    req_dns_questions_section = DnsQuestionsSection(
        data[12:], req_dns_header_section.get_question_count()
    )

    first_question = req_dns_questions_section.get_first_question()

    print(req_dns_header_section)

    print(req_dns_questions_section)

    if not first_question.get_domain().startswith("ricklantis.com") or first_question.qtype.value != RrType.A.value:
        response = get_404_dns_response(req_dns_header_section, first_question)
        sock.sendto(
            response,
            addr
        )
        return

    response = bytearray([])

    res_dns_header_section = DnsHeaderSection([])

    res_dns_header_section.set_answer_count(1)

    res_dns_header_section.set_transaction_id(
        req_dns_header_section.get_transaction_id()
    )
    res_dns_header_section.set_query_or_response(QueryOrResponse.RESPONSE)

    res_dns_header_section.set_authoritative_answer(True)

    res_dns_header_section.set_operation_code(
        op_code=OperationCode.STANDARD_QUERY)

    res_dns_header_section.set_truncation(False)

    res_dns_header_section.set_recursion_desired(False)

    res_dns_header_section.set_recursion_available(False)

    response += res_dns_header_section.get_as_bytes()

    print('Response data header: {}'.format(
        # res_dns_header_section.get_as_bytes().hex()
        bin(int.from_bytes(res_dns_header_section.get_as_bytes(), "big"))
    ))

    resource_record = ResourceRecord(
        first_question,
        10,
        Rdata(RdataType.IPV4, "147.182.185.61")
    ).build()

    print("THE RESOURCE RECORD: ", resource_record.hex())

    response += resource_record

    print("RAW RESPONSE: {}".format(response.hex()))

    sock.sendto(response, addr)


if __name__ == "__main__":

    sock.bind((IP_ADDRESS, DNS_PORT))

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    while True:
        data, addr = sock.recvfrom(512)
        try:
            request_handler(bytearray(data), addr)
        except Exception as e:
            print(e)
            response = get_server_error_dns_response()
            sock.sendto(
                response,
                addr
            )
