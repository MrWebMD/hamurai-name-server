import question
import resource_record

dns_questions_section_template = '''
DECODED QUESTIONS SECTION:
{}

RAW QUESTIONS SECTION:
{}
'''


class DnsQuestionsSection:
    def __init__(self, question_data: bytearray, question_count: int):

        self._data = question_data
        self._question_count = question_count

    @property
    def bytes(self) -> bytearray:
        return self._data

    def __str__(self) -> str:
        return dns_questions_section_template.format(
            self.first_question.__str__(),
            bin(int.from_bytes(self._data, "big"))
        )

    @property
    def first_question(self) -> 'question.DnsQuestion':

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
                self._data[label_offset:label_offset+1], "big")

            # If the label is a null terminator then, that means the QTYPE and QCLASS
            # fields have started

            if label_length == 0:
                break

            # Move past the one byte length

            label_offset += 1

            # Read all bytes between the current offset and the length of the next label
            # then convert the bytes to readable characters

            label_content = self._data[
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

        qtype = int.from_bytes(self._data[label_offset:label_offset+2], "big")

        qclass = int.from_bytes(
            self._data[label_offset+2:label_offset+4], "big")

        # The start of the first questions label is immediately after the 12 byte header.
        # This offset will be used to reference these labels without having to re-write
        # their data again in the answer section

        # offset_in_message = 12

        return question.DnsQuestion(
            qname,
            resource_record.RrType(qtype),
            resource_record.RrClass(qclass),
        )
