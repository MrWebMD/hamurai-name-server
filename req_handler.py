import dns_header
import resource_record
import question_section
import handlers.name_error as name_error
import handlers.a_record as a_record
import handlers.opt_record as opt_record
import handlers.not_implemented as not_implemented
import socket


def request_handler(data: bytearray, addr, sock: 'socket.socket'):

    req_head = dns_header.DnsHeaderSection(data[:12])

    req_questions = question_section.DnsQuestionsSection(
        data[12:], req_head.question_count
    )

    first_question = req_questions.first_question

    print(req_head)

    print(req_questions)

    response = bytearray([])

    if not first_question.domain.startswith("ricklantis.com"):
        response = name_error.handler(
            req_head, first_question)

    elif first_question.qtype.value == resource_record.RrType.A.value:
        response = a_record.handler(
            req_head, first_question)

    elif first_question.qtype.value == resource_record.RrType.OPT.value:
        response = opt_record.handler(req_head, first_question)
    else:
        response = not_implemented.handler(req_head, first_question)

    print("RAW RESPONSE: {}".format(response.hex()))

    sock.sendto(response, addr)
