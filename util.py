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
