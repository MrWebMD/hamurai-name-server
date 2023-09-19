import socket
import signal
import handlers.server_error as server_error
import req_handler

DNS_PORT = 53

IP_ADDRESS = "0.0.0.0"

# https://datatracker.ietf.org/doc/html/rfc1035

# https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.2


def main_loop():
    data, addr = sock.recvfrom(512)
    # try:
    req_handler.request_handler(bytearray(data), addr, sock)
    # except Exception as e:
    #     print(e)
    #     response = server_error.handler()
    #     sock.sendto(
    #         response,
    #         addr
    #     )


if __name__ == "__main__":

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind((IP_ADDRESS, DNS_PORT))

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    while True:
        main_loop()
