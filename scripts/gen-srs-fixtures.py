#!/usr/bin/env python3
"""Write sing-box binary rule-set fixtures for the Segue .srs reader.

The encoder follows github.com/sagernet/sing-box/common/srs and
github.com/sagernet/sing/common/domain (succinct set). Python only; there is
no Go toolchain here. Running the script rewrites the fixtures and checks that
a second implementation of the succinct-set walk recovers the domains that
were encoded.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

PREFIX_LABEL = "\r"
ROOT_LABEL = "\n"
ITEM_NETWORK = 1
ITEM_DOMAIN = 2
ITEM_DOMAIN_KEYWORD = 3
ITEM_DOMAIN_REGEX = 4
ITEM_SOURCE_IP_CIDR = 5
ITEM_IP_CIDR = 6
ITEM_SOURCE_PORT = 7
ITEM_SOURCE_PORT_RANGE = 8
ITEM_PORT = 9
ITEM_PORT_RANGE = 10
ITEM_PROCESS_NAME = 11
ITEM_PACKAGE_NAME_REGEX = 23
ITEM_NETWORK_IS_EXPENSIVE = 19
ITEM_NETWORK_INTERFACE_ADDRESS = 21
ITEM_DEFAULT_INTERFACE_ADDRESS = 22
ITEM_FINAL = 0xFF

FIXTURE_DIR = (
    Path(__file__).resolve().parents[1] / "crates" / "segue-routing" / "fixtures"
)


def uvarint(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative uvarint")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def u64s(values: list[int]) -> bytes:
    return uvarint(len(values)) + b"".join(struct.pack(">Q", value) for value in values)


def u16s(values: list[int]) -> bytes:
    return uvarint(len(values)) + b"".join(struct.pack(">H", value) for value in values)


def byte_slice(payload: bytes) -> bytes:
    return uvarint(len(payload)) + payload


def strings(values: list[str]) -> bytes:
    body = bytearray(uvarint(len(values)))
    for value in values:
        raw = value.encode("utf-8")
        body += uvarint(len(raw))
        body += raw
    return bytes(body)


def reverse_domain(domain: str) -> str:
    return "".join(reversed(domain))


def set_bit(bitmap: list[int], index: int) -> None:
    while index >> 6 >= len(bitmap):
        bitmap.append(0)
    bitmap[index >> 6] |= 1 << (index & 63)


class SuccinctSet:
    def __init__(self, leaves: list[int], label_bitmap: list[int], labels: bytes) -> None:
        self.leaves = leaves
        self.label_bitmap = label_bitmap
        self.labels = labels

    def write(self) -> bytes:
        return b"\x00" + u64s(self.leaves) + u64s(self.label_bitmap) + byte_slice(self.labels)


def new_succinct_set(keys: list[str]) -> SuccinctSet:
    """Port of domain.newSuccinctSet. `keys` must already be sorted and unique."""
    leaves: list[int] = []
    label_bitmap: list[int] = []
    labels = bytearray()
    label_index = 0
    queue: list[tuple[int, int, int]] = [(0, len(keys), 0)]
    node = 0
    while node < len(queue):
        start, end, column = queue[node]
        if column == len(keys[start]):
            start += 1
            set_bit(leaves, node)
        cursor = start
        while cursor < end:
            first = cursor
            label = keys[first][column]
            while cursor < end and keys[cursor][column] == label:
                cursor += 1
            queue.append((first, cursor, column + 1))
            labels.append(ord(label))
            label_index += 1
        set_bit(label_bitmap, label_index)
        label_index += 1
        node += 1
    return SuccinctSet(leaves, label_bitmap, bytes(labels))


def matcher_keys(domains: list[str], suffixes: list[str], legacy: bool) -> list[str]:
    """Port of domain.NewMatcher’s key list, before the succinct set is built."""
    domain_list: list[str] = []
    seen: set[str] = set()
    for domain in suffixes:
        if domain in seen:
            continue
        seen.add(domain)
        if domain.startswith("."):
            domain_list.append(reverse_domain(PREFIX_LABEL + domain))
        elif legacy:
            domain_list.append(reverse_domain(domain))
            dotted = "." + domain
            if dotted not in seen:
                seen.add(dotted)
                domain_list.append(reverse_domain(PREFIX_LABEL + dotted))
        else:
            domain_list.append(reverse_domain(ROOT_LABEL + domain))
    for domain in domains:
        if domain in seen:
            continue
        seen.add(domain)
        domain_list.append(reverse_domain(domain))
    domain_list.sort()
    unique: list[str] = []
    for key in domain_list:
        if not unique or unique[-1] != key:
            unique.append(key)
    return unique


def encode_domain_matcher(domains: list[str], suffixes: list[str], legacy: bool) -> bytes:
    return new_succinct_set(matcher_keys(domains, suffixes, legacy)).write()


def prefix(addr: str) -> bytes:
    if ":" in addr:
        text, _, bits = addr.partition("/")
        raw = socket_inet_pton(text)
        return uvarint(len(raw)) + raw + bytes([int(bits)])
    text, _, bits = addr.partition("/")
    octets = bytes(int(part) for part in text.split("."))
    return uvarint(4) + octets + bytes([int(bits)])


def socket_inet_pton(text: str) -> bytes:
    # Expand a compressed IPv6 literal. Enough for the fixtures, not a general parser.
    head, sep, tail = text.partition("::")
    head_parts = [int(part, 16) for part in head.split(":") if part]
    tail_parts = [int(part, 16) for part in tail.split(":") if part] if sep else []
    if not sep:
        parts = head_parts
    else:
        missing = 8 - len(head_parts) - len(tail_parts)
        parts = head_parts + [0] * missing + tail_parts
    if len(parts) != 8:
        raise ValueError(f"bad ipv6 {text}")
    return b"".join(struct.pack(">H", part) for part in parts)


def cidr_bounds(cidr: str) -> tuple[bytes, bytes]:
    if ":" in cidr:
        text, _, bits_text = cidr.partition("/")
        raw = int.from_bytes(socket_inet_pton(text), "big")
        bits = int(bits_text)
        mask = (1 << 128) - 1 if bits == 0 else ((1 << bits) - 1) << (128 - bits)
        start = raw & mask
        end = start | (~mask & ((1 << 128) - 1))
        return start.to_bytes(16, "big"), end.to_bytes(16, "big")
    text, _, bits_text = cidr.partition("/")
    raw = 0
    for octet in text.split("."):
        raw = (raw << 8) | int(octet)
    bits = int(bits_text)
    mask = 0 if bits == 0 else ((1 << bits) - 1) << (32 - bits)
    start = raw & mask
    end = start | (~mask & 0xFFFFFFFF)
    return start.to_bytes(4, "big"), end.to_bytes(4, "big")


def encode_ip_set(cidrs: list[str]) -> bytes:
    body = bytearray(b"\x01")
    body += struct.pack(">Q", len(cidrs))
    for cidr in cidrs:
        start, end = cidr_bounds(cidr)
        body += uvarint(len(start)) + start
        body += uvarint(len(end)) + end
    return bytes(body)


def encode_rule(rule: dict) -> bytes:
    if rule["type"] == "logical":
        body = bytearray(b"\x01")
        body.append(0 if rule["mode"] == "and" else 1)
        children = rule["rules"]
        body += uvarint(len(children))
        for child in children:
            body += encode_rule(child)
        body.append(1 if rule.get("invert") else 0)
        return bytes(body)

    body = bytearray(b"\x00")
    if rule.get("network"):
        body.append(ITEM_NETWORK)
        body += strings(rule["network"])
    domains = rule.get("domain") or []
    suffixes = rule.get("domain_suffix") or []
    if domains or suffixes:
        body.append(ITEM_DOMAIN)
        body += encode_domain_matcher(domains, suffixes, rule.get("legacy", False))
    if rule.get("domain_keyword"):
        body.append(ITEM_DOMAIN_KEYWORD)
        body += strings(rule["domain_keyword"])
    if rule.get("domain_regex"):
        body.append(ITEM_DOMAIN_REGEX)
        body += strings(rule["domain_regex"])
    if rule.get("source_ip_cidr"):
        body.append(ITEM_SOURCE_IP_CIDR)
        body += encode_ip_set(rule["source_ip_cidr"])
    if rule.get("ip_cidr"):
        body.append(ITEM_IP_CIDR)
        body += encode_ip_set(rule["ip_cidr"])
    if rule.get("source_port"):
        body.append(ITEM_SOURCE_PORT)
        body += u16s(rule["source_port"])
    if rule.get("source_port_range"):
        body.append(ITEM_SOURCE_PORT_RANGE)
        body += strings(rule["source_port_range"])
    if rule.get("port"):
        body.append(ITEM_PORT)
        body += u16s(rule["port"])
    if rule.get("port_range"):
        body.append(ITEM_PORT_RANGE)
        body += strings(rule["port_range"])
    if rule.get("process_name"):
        body.append(ITEM_PROCESS_NAME)
        body += strings(rule["process_name"])
    if rule.get("package_name_regex"):
        body.append(ITEM_PACKAGE_NAME_REGEX)
        body += strings(rule["package_name_regex"])
    if rule.get("network_is_expensive"):
        body.append(ITEM_NETWORK_IS_EXPENSIVE)
    if rule.get("network_interface_address"):
        body.append(ITEM_NETWORK_INTERFACE_ADDRESS)
        entries = rule["network_interface_address"]
        body += uvarint(len(entries))
        for key, prefixes in entries:
            body.append(key)
            body += uvarint(len(prefixes))
            for cidr in prefixes:
                body += prefix(cidr)
    if rule.get("default_interface_address"):
        body.append(ITEM_DEFAULT_INTERFACE_ADDRESS)
        prefixes = rule["default_interface_address"]
        body += uvarint(len(prefixes))
        for cidr in prefixes:
            body += prefix(cidr)
    body.append(ITEM_FINAL)
    body.append(1 if rule.get("invert") else 0)
    return bytes(body)


def encode_ruleset(version: int, rules: list[dict]) -> bytes:
    payload = bytearray(uvarint(len(rules)))
    for rule in rules:
        payload += encode_rule(rule)
    compressed = zlib.compress(bytes(payload), 9)
    return b"SRS" + bytes([version]) + compressed


def popcount(word: int) -> int:
    return bin(word).count("1")


def count_ones_before(words: list[int], index: int) -> int:
    """Number of 1-bits in [0, index), using the same rank as the Rust reader."""
    word_index = index >> 6
    bit = index & 63
    total = 0
    for word in words[:word_index]:
        total += popcount(word)
    if bit:
        total += popcount(words[word_index] & ((1 << bit) - 1))
    return total


def build_ranks(words: list[int]) -> list[int]:
    ranks = [0]
    total = 0
    for word in words:
        total += popcount(word)
        ranks.append(total)
    return ranks


def build_selects(words: list[int]) -> list[int]:
    selects: list[int] = []
    ith = -1
    limit = len(words) << 6
    for index in range(limit):
        if words[index >> 6] & (1 << (index & 63)):
            ith += 1
            if ith & 31 == 0:
                selects.append(index)
    return selects


def select_ith_one(words: list[int], ranks: list[int], selects: list[int], ith: int) -> int:
    """Port of domain.select32R64’s returned position (first result)."""
    word_i = selects[ith >> 5] >> 6
    while ranks[word_i + 1] <= ith:
        word_i += 1
    word = words[word_i]
    window = word
    base = word_i << 6
    find = ith - ranks[word_i]
    offset = 0
    ones = popcount(window & 0xFFFFFFFF)
    if ones <= find:
        find -= ones
        offset |= 32
        window >>= 32
    ones = popcount(window & 0xFFFF)
    if ones <= find:
        find -= ones
        offset |= 16
        window >>= 16
    ones = popcount(window & 0xFF)
    if ones <= find:
        index = ((window >> 5) & 0x7F8) | (find - ones)
        position = SELECT8[index] + offset + 8
    else:
        index = ((window & 0xFF) << 3) | find
        position = SELECT8[index] + offset
    return base + position


def _trailing_zeros8(value: int) -> int:
    if value == 0:
        return 8
    return (value & -value).bit_length() - 1


SELECT8 = [0] * (256 * 8)
for _byte in range(256):
    _cursor = _byte
    for _nth in range(8):
        SELECT8[_byte * 8 + _nth] = _trailing_zeros8(_cursor)
        _cursor = (_cursor - 1) & _cursor & 0xFF


def walk_keys(succinct: SuccinctSet) -> list[str]:
    words = succinct.label_bitmap
    ranks = build_ranks(words)
    selects = build_selects(words)
    leaves = succinct.leaves
    labels = succinct.labels

    def bit(bitmap: list[int], index: int) -> int:
        return (bitmap[index >> 6] >> (index & 63)) & 1

    def count_zeros(index: int) -> int:
        return index - count_ones_before(words, index)

    result: list[str] = []
    current = bytearray()
    if leaves and bit(leaves, 0):
        result.append("")
    stack = [(0, 0)]
    while stack:
        node_id, bm_idx = stack[-1]
        if bit(words, bm_idx):
            stack.pop()
            if stack:
                current.pop()
                node, idx = stack[-1]
                stack[-1] = (node, idx + 1)
            continue
        current.append(labels[bm_idx - node_id])
        next_node = count_zeros(bm_idx + 1)
        next_bm = select_ith_one(words, ranks, selects, next_node - 1) + 1
        if bit(leaves, next_node):
            result.append(current.decode("utf-8"))
        stack.append((next_node, next_bm))
    return result


def dump_matcher(keys: list[str]) -> tuple[list[str], list[str]]:
    domains: set[str] = set()
    prefixes: set[str] = set()
    dotted: set[str] = set()
    for key in keys:
        restored = reverse_domain(key)
        if not restored:
            domains.add("")
            continue
        marker, rest = restored[0], restored[1:]
        if marker == PREFIX_LABEL:
            dotted.add(rest)
        elif marker == ROOT_LABEL:
            prefixes.add(rest)
        else:
            domains.add(restored)
    for raw in dotted:
        if raw.startswith(".") and raw[1:] in domains:
            domains.remove(raw[1:])
            prefixes.add(raw[1:])
        else:
            prefixes.add(raw)
    return sorted(domains), sorted(prefixes)


def self_check() -> None:
    single = new_succinct_set(["ba"])
    assert single.leaves == [4], single.leaves
    assert single.label_bitmap == [26], single.label_bitmap
    assert single.labels == b"ba"
    assert walk_keys(single) == ["ba"]

    branched = new_succinct_set(["a", "b"])
    assert branched.leaves == [6], branched.leaves
    assert branched.label_bitmap == [28], branched.label_bitmap
    assert branched.labels == b"ab"
    assert walk_keys(branched) == ["a", "b"]

    domains, suffixes = dump_matcher(walk_keys(SuccinctSet(single.leaves, single.label_bitmap, single.labels)))
    assert domains == ["ab"] and suffixes == []

    sample_domains = ["example.com", "www.example.com"]
    sample_suffixes = [".com.cn", "sagernet.org"]
    for legacy in (False, True):
        keys = matcher_keys(sample_domains, sample_suffixes, legacy)
        recovered_domains, recovered_suffixes = dump_matcher(walk_keys(new_succinct_set(keys)))
        assert recovered_domains == sorted(sample_domains), (legacy, recovered_domains)
        assert recovered_suffixes == sorted(sample_suffixes), (legacy, recovered_suffixes)


def default_rule(**fields: object) -> dict:
    rule = {"type": "default"}
    rule.update(fields)
    return rule


def write_fixtures() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    fixtures = {
        "domain-v1.srs": encode_ruleset(
            1,
            [
                default_rule(
                    legacy=True,
                    domain=["example.com", "www.example.com"],
                    domain_suffix=[".com.cn", "sagernet.org"],
                    domain_keyword=["ads"],
                    domain_regex=["^ads[.]"],
                )
            ],
        ),
        "domain-v2.srs": encode_ruleset(
            2,
            [
                default_rule(
                    domain=["example.com", "www.example.com"],
                    domain_suffix=[".com.cn", "sagernet.org"],
                    domain_keyword=["ads"],
                    domain_regex=["^ads[.]"],
                )
            ],
        ),
        "ip-v2.srs": encode_ruleset(
            2,
            [default_rule(ip_cidr=["10.0.0.0/8", "2001:db8::/32"], source_ip_cidr=["192.0.2.1/32"])],
        ),
        "mixed-v2.srs": encode_ruleset(
            2,
            [
                default_rule(
                    domain=["example.com"],
                    ip_cidr=["192.0.2.0/24"],
                    network=["tcp"],
                    port_range=["80:443"],
                    source_port=[53],
                )
            ],
        ),
        "logical-or-v2.srs": encode_ruleset(
            2,
            [
                {
                    "type": "logical",
                    "mode": "or",
                    "rules": [
                        default_rule(domain_suffix=["a.test"]),
                        default_rule(domain_suffix=["b.test"]),
                    ],
                }
            ],
        ),
        "unsupported-v3.srs": encode_ruleset(
            3,
            [
                default_rule(network_is_expensive=True, domain=["nope.example"]),
                default_rule(domain=["keep.example"]),
            ],
        ),
        "unsupported-v4.srs": encode_ruleset(
            4,
            [
                default_rule(
                    network_interface_address=[(0, ["10.0.0.0/8"])],
                    domain=["dropped.example"],
                ),
                default_rule(default_interface_address=["192.0.2.0/24"]),
                default_rule(domain=["kept.example"]),
            ],
        ),
        "unsupported-v5.srs": encode_ruleset(
            5,
            [
                default_rule(package_name_regex=["^com\\.foo$"]),
                default_rule(domain=["still.example"]),
            ],
        ),
        "invert-v2.srs": encode_ruleset(
            2,
            [default_rule(domain=["example.com"], invert=True)],
        ),
        "process-v2.srs": encode_ruleset(
            2,
            [
                default_rule(domain=["drop.example"], process_name=["chrome"]),
                default_rule(domain=["keep.example"]),
            ],
        ),
    }
    for name, payload in fixtures.items():
        (FIXTURE_DIR / name).write_bytes(payload)
        print(f"{name}: {len(payload)} bytes")


def main() -> None:
    self_check()
    write_fixtures()
    print("self-check ok")


if __name__ == "__main__":
    main()
