import socket
import signal
from dns_header import DnsHeaderSection, Rcode
from dns_questions import DnsQuestionsSection
from resource_record import ResourceRecord, domain_to_label, RrType, RrClass, create_ipv4_address_rdata

DNS_PORT = 53
IP_ADDRESS = "127.0.0.1"

# https://datatracker.ietf.org/doc/html/rfc1035

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def request_handler(data: bytearray, addr):

    dns_header_section = DnsHeaderSection(data[:12])

    dns_questions_section = DnsQuestionsSection(
        data[12:], dns_header_section.get_question_count()
    )

    first_question = dns_questions_section.get_first_question()

    print(dns_header_section)
    print(dns_questions_section)

    if first_question.get_name() != "ricklantis.com" or first_question.qtype != RrType.A:
        dns_header_section.set_response_code(rcode=Rcode.NAME_ERROR)
        dns_header_section.set_query_or_response(1)
        dns_header_section.set_answer_count(0)
        sock.sendto(
            dns_header_section.get_as_bytes() +
            dns_questions_section.get_as_bytes(),
            addr
        )
        return

    response = bytearray([])

    dns_header_section.set_query_or_response(1)
    dns_header_section.set_answer_count(1)
    # dns_header_section.set_name_server_count(1)

    response += dns_header_section.get_as_bytes()

    response += dns_questions_section.get_as_bytes()

    response += first_question.create_answer(
        create_ipv4_address_rdata(104, 26, 7, 8),
        10
    )

    response += ResourceRecord(
        domain_to_label("hamurai.council-of-ricks.com"),
        RrType.NS,
        RrClass.IN,
        5,
        domain_to_label("hamurai.council-of-ricks.com")
    ).build()

    print("RAW RESPONSE: {}".format(response.hex()))

    sock.sendto(response, addr)


if __name__ == "__main__":

    sock.bind((IP_ADDRESS, DNS_PORT))

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    while True:
        data, addr = sock.recvfrom(512)
        request_handler(bytearray(data), addr)
