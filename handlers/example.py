
import dns_header
import question


def handler(req_head: 'dns_header.DnsHeaderSection', question: 'question.DnsQuestion') -> bytearray:
    response = bytearray([])

    res_head = dns_header.DnsHeaderSection([])

    res_head.answer_count = 0

    res_head.question_count = 0

    res_head.transaction_id = req_head.transaction_id
    res_head.query_or_response = dns_header.QueryOrResponse.RESPONSE

    # res_head.authoritative_answer = False

    # res_head.operation_code = dns_header.OperationCode.STANDARD_QUERY

    # res_head.truncation = False

    # res_head.recursion_desired = False

    # res_head.recursion_available = False

    # res_head.response_code = dns_header.Rcode.NAME_ERROR

    response += res_head.bytes

    response += question.bytes

    return response
