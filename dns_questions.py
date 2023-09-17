dns_question_template = '''QNAME: {}
QTYPE: {}
QCLASS: {}'''

dns_questions_section_template = '''
DECODED QUESTIONS SECTION:
{}

RAW QUESTIONS SECTION:
{}
'''


class DnsQuestion:
    def __init__(self, qname: str, qtype: int, qclass: int):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def get_name(self) -> str:

        # Domain name represented as a sequence of labels, where
        # each label consists of a length octet followed by that
        # number of octets.  The domain name terminates with the
        # zero length octet for the null label of the root.  Note
        # that this field may be an odd number of octets; no
        # padding is used.

        return self.qname

    def get_class(self) -> int:

        # Two octet code that specifies the class of the query.
        # For example, the QCLASS field is IN for the Internet.

        return self.qclass

    def get_type(self) -> int:

        # Two octet code which specifies the type of the query.
        # The values for this field include all codes valid for a
        # TYPE field, together with some more general codes which
        # can match more than one type of RR.

        return self.qtype

    def __str__(self) -> str:
        return dns_question_template.format(
            self.get_name(),
            self.get_type(),
            self.get_class()
        )


class DnsQuestionsSection:
    def __init__(self, question_data: bytes, question_count: int):

        self.data = question_data
        self.question_count = question_count

    def __str__(self) -> str:
        return dns_questions_section_template.format(
            self.get_first_question().__str__(),
            self.data.hex()
        )

    def get_first_question(self) -> DnsQuestion:

        # DNS MESSAGE QUESTION SECTION STARTS AT
        # BYTE 13 AND ENDS WITH A SINGLE NULL TERMINATOR 00 AT THE END

        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # | LN | LABEL | LN | LABEL...                    |
        # /                     QNAME                     /
        # /                                      | NULL   /
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                     QTYPE                     |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                     QCLASS                    |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        # Each question starts with one byte that I have called LN.
        # This byte tells you the length of the next "label".

        # Labels are each word that is separated by a dot in a domain name. Ex, ["docs", "google", "com"]

        # When a null terminator is reached, the final character of a single domain
        # has been reached. QTYPE, and QNAME are 2 bytes each and come right after
        # the null terminator.

        labels: list[str] = []

        # Keep track of where the last offset was
        # so we can know where QTYPE and QCLASS starts

        label_offset = 0

        # Not RFC compliant but we're stopping at 10 sub domains + 1 TLD

        for _ in range(0, 11):

            # Read the first byte of the questions section which tells
            # you the length of the next label

            label_length = int.from_bytes(
                self.data[label_offset:label_offset+1])

            # If the label is a null terminator then, that means the QTYPE and QCLASS
            # fields have started

            if label_length == 0:
                break

            # Move past the one byte length

            label_offset += 1

            # Read all bytes between the current offset and the length of the next label
            # then convert the bytes to readable characters

            label_content = self.data[
                label_offset:
                label_offset+label_length
            ].decode()

            # Add the piece of a full domain to the labels list

            labels.append(label_content)

            # Start the next iteration at an ofset equal to the end of the current label

            label_offset += label_length

        # Move past the one byte NULL terminator

        label_offset += label_length+1

        qname = '.'.join(labels)

        qtype = int.from_bytes(self.data[label_offset:label_offset+2])

        qclass = int.from_bytes(self.data[label_offset+2:label_offset+4])

        return DnsQuestion(qname, qtype, qclass)
