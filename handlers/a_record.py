
import dns_header
import resource_record
import rdata


def handler(req_head: 'dns_header.DnsHeaderSection', first_question) -> bytearray:
    response = bytearray([])

    res_head = dns_header.DnsHeaderSection([])

    res_head.answer_count = 1

    res_head.transaction_id = req_head.transaction_id

    res_head.query_or_response = dns_header.QueryOrResponse.RESPONSE

    res_head.authoritative_answer = True

    res_head.operation_code = dns_header.OperationCode.STANDARD_QUERY

    res_head.truncation = False

    res_head.recursion_desired = False

    res_head.recursion_available = False

    response += res_head.bytes

    res_resource_record = resource_record.ResourceRecord(
        first_question,
        10,
        rdata.Rdata(rdata.RdataType.IPV4, b"147.182.185.61")
    ).bytes

    response += res_resource_record

    return response
