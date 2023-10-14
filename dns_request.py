import dns_header
import question_section


class DnsRequest:
    def __init__(self, req_bytes: bytearray):
        self._data = req_bytes
        self._head = dns_header.DnsHeaderSection(req_bytes[:12])
        self._question_section = question_section.DnsQuestionsSection(
            req_bytes[12:])
        self._additional_records = False

        # if self._head.additional_record_count > 0:

        self.parse()

    def parse(self):
        print("")

    @property
    def head(self):
        return self._head

    @property
    def bytes(self) -> bytearray:
        return self._data
