from enum import Enum


def create_ipv4_address_rdata(octet_array: [int]) -> bytearray:
    return bytearray(octet_array)


def domain_to_label(domain_name: str) -> bytearray:
    labels = bytearray([])

    for part in domain_name.replace(" ", "").split("."):
        labels += bytearray(len(part).to_bytes(1, "big"))
        labels += bytearray(part, "utf-8")

    labels += bytearray(b'\0')

    print("GENERATED LABEL:", labels.hex())

    return labels


class RdataType(Enum):
    IPV4 = 0
    DOMAIN = 1


class Rdata:
    def __init__(self, rdata_type: RdataType, value: str):
        self.type = rdata_type
        self.value = value

    def build(self) -> bytearray:
        if self.type.name == "DOMAIN":
            return domain_to_label(self.value)
        if self.type.name == "IPV4":
            ip_bytes = []
            for octet_str in self.value.split("."):
                ip_bytes.append(int(octet_str))
            return create_ipv4_address_rdata(ip_bytes)
