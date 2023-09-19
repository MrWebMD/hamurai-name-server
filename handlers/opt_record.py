import dns_header
import resource_record
import rdata
import question


def handler(req_head: 'dns_header.DnsHeaderSection', first_question: question.DnsQuestion) -> bytearray:

    response = bytearray([])

    res_head = dns_header.DnsHeaderSection([])

    res_head.answer_count = 1

    res_head.transaction_id = req_head.transaction_id

    res_head.query_or_response = dns_header.QueryOrResponse.RESPONSE

    res_head.authoritative_answer = True

    res_head.operation_code = dns_header.OperationCode.STANDARD_QUERY

    response += res_head.bytes

    res_rdata = rdata.Rdata(rdata.OptRdata, b'')

    res_resource_record = resource_record.ResourceRecord(
        first_question,
        10,
        res_rdata
    )

    response += res_resource_record.bytes

    return response
