
import dns_header
import question


def handler():
    response = bytearray([])

    res_head = dns_header.DnsHeaderSection([])

    res_head.set_answer_count(0)

    res_head.set_question_count(0)

    res_head.set_transaction_id(1)

    res_head.set_query_or_response(
        dns_header.QueryOrResponse.RESPONSE)

    res_head.set_authoritative_answer(True)

    res_head.set_operation_code(
        op_code=dns_header.OperationCode.STANDARD_QUERY)
    res_head.set_truncation(False)

    res_head.set_recursion_desired(False)

    res_head.set_recursion_available(False)

    res_head.set_response_code(dns_header.Rcode.SERVER_FAILURE)

    response += res_head.bytes

    return response
