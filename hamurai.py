import socket
import signal
from dns_header import DnsHeaderSection
from dns_questions import DnsQuestionsSection

DNS_PORT = 53
IP_ADDRESS = "127.0.0.1"

# https://datatracker.ietf.org/doc/html/rfc1035

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def request_handler(data: bytes, addr):

    dns_header_section = DnsHeaderSection(data[:12])

    dns_questions_section = DnsQuestionsSection(
        data[12:], dns_header_section.get_question_count()
    )

    print(dns_header_section)

    print(dns_questions_section)

    sock.sendto(b'Hello World', addr)


if __name__ == "__main__":

    sock.bind((IP_ADDRESS, DNS_PORT))

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    while True:
        data, addr = sock.recvfrom(512)
        request_handler(data, addr)
