#!/usr/bin/env python3
"""Write mihomo binary rule-set fixtures for the Segue .mrs reader.

The encoder follows mihomo's rules/provider/mrs_converter.go,
component/trie/domain_set.go and component/cidr/ipcidr_set_bin.go. Python
only: there is no Go toolchain here, and this interpreter has no
compression.zstd, so each file is a zstd frame of raw blocks. Running the
script rewrites the fixtures, checks that a second walk of the succinct set
restores the domains, and (when the zstd CLI is on PATH) that it inflates
the frame to the same payload.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
from pathlib import Path

FIXTURE_DIR = (
    Path(__file__).resolve().parents[1] / "crates" / "segue-routing" / "fixtures"
)

BEHAVIOR_DOMAIN = 0
BEHAVIOR_IPCIDR = 1


def rune_reverse(text: str) -> str:
    return "".join(reversed(text))


def set_bit(bitmap: list[int], index: int) -> None:
    while index >> 6 >= len(bitmap):
        bitmap.append(0)
    bitmap[index >> 6] |= 1 << (index & 63)


def build_domain_set(keys: list[bytes]) -> tuple[list[int], list[int], bytes]:
    """Port of trie.buildDomainSet. `keys` are the reversed UTF-8 strings."""
    ordered = sorted(keys)
    unique: list[bytes] = []
    for key in ordered:
        if not unique or unique[-1] != key:
            unique.append(key)
    if not unique:
        raise ValueError("empty domain set")

    leaves: list[int] = []
    label_bitmap: list[int] = []
    labels = bytearray()
    label_index = 0
    node_id = 0
    queue: list[tuple[int, int]] = [(0, len(unique))]
    column = 0
    while queue:
        nxt: list[tuple[int, int]] = []
        for start, end in queue:
            if column == len(unique[start]):
                start += 1
                set_bit(leaves, node_id)
            cursor = start
            while cursor < end:
                first = cursor
                label = unique[first][column]
                while cursor < end and unique[cursor][column] == label:
                    cursor += 1
                nxt.append((first, cursor))
                labels.append(label)
                label_index += 1
            set_bit(label_bitmap, label_index)
            label_index += 1
            node_id += 1
        queue = nxt
        column += 1
    return leaves, label_bitmap, bytes(labels)


def insert_patterns(patterns: list[str]) -> list[bytes]:
    """Port of DomainSetBuilder.Insert for the patterns the fixtures use."""
    keys: list[bytes] = []
    for pattern in patterns:
        parts = pattern.split(".")
        if parts[0] == "+":
            if len(parts) < 2:
                raise ValueError(pattern)
            keys.append(rune_reverse(".".join(parts[1:])).encode("utf-8"))
            keys.append(rune_reverse(".".join(parts)).encode("utf-8"))
        elif parts[0] == "":
            parts[0] = "+"
            keys.append(rune_reverse(".".join(parts)).encode("utf-8"))
        else:
            keys.append(rune_reverse(".".join(parts)).encode("utf-8"))
    return keys


def bit(words: list[int], index: int) -> int:
    if index >> 6 >= len(words):
        raise RuntimeError(f"bit {index} is outside {len(words)} words")
    return (words[index >> 6] >> (index & 63)) & 1


def ith_one(words: list[int], ith: int) -> int:
    seen = 0
    for index in range(len(words) * 64):
        if bit(words, index):
            if seen == ith:
                return index
            seen += 1
    raise RuntimeError(f"select {ith} failed")


def dump_internal_keys(
    leaves: list[int], label_bitmap: list[int], labels: bytes
) -> list[bytes]:
    """Port of DomainSet.keys. Pads leaves the way the Rust reader does."""
    ones = sum(bin(word).count("1") for word in label_bitmap)
    if not label_bitmap:
        raise RuntimeError("empty label bitmap")
    last_one = 0
    for word_index, word in enumerate(label_bitmap):
        if word:
            highest = word.bit_length() - 1
            last_one = (word_index << 6) | highest
    zeros = last_one + 1 - ones
    if ones != zeros + 1 or len(labels) != zeros:
        raise RuntimeError("malformed succinct set")
    words_needed = (ones + 63) >> 6
    padded = list(leaves) + [0] * max(0, words_needed - len(leaves))

    found: list[bytes] = []

    def traverse(node_id: int, bm_idx: int, current: bytearray) -> None:
        if bit(padded, node_id):
            found.append(bytes(current))
        while True:
            if bit(label_bitmap, bm_idx):
                return
            label = labels[bm_idx - node_id]
            current.append(label)
            next_node = bm_idx - node_id + 1
            next_bm = ith_one(label_bitmap, next_node - 1) + 1
            traverse(next_node, next_bm, current)
            current.pop()
            bm_idx += 1

    traverse(0, 0, bytearray())
    return found


def foreach_patterns(
    leaves: list[int], label_bitmap: list[int], labels: bytes
) -> list[str]:
    patterns = []
    for key in dump_internal_keys(leaves, label_bitmap, labels):
        text = key.decode("utf-8")
        if text.endswith("+"):
            text = text[:-1]
        patterns.append(rune_reverse(text))
    return patterns


def write_domain_set(leaves: list[int], label_bitmap: list[int], labels: bytes) -> bytes:
    body = bytearray(b"\x01")
    body += struct.pack(">q", len(leaves))
    body += b"".join(struct.pack(">Q", word) for word in leaves)
    body += struct.pack(">q", len(label_bitmap))
    body += b"".join(struct.pack(">Q", word) for word in label_bitmap)
    body += struct.pack(">q", len(labels))
    body += labels
    return bytes(body)


def ipv4_mapped(raw: bytes) -> bytes:
    if len(raw) != 4:
        raise ValueError("ipv4")
    return b"\x00" * 10 + b"\xff\xff" + raw


def ipv4_cidr(cidr: str) -> tuple[bytes, bytes]:
    text, _, bits_text = cidr.partition("/")
    bits = int(bits_text)
    raw = 0
    for octet in text.split("."):
        raw = (raw << 8) | int(octet)
    if bits == 0:
        mask = 0
    else:
        mask = ((1 << bits) - 1) << (32 - bits)
    start = raw & mask
    host = 0 if bits == 32 else (1 << (32 - bits)) - 1
    end = start | host
    return ipv4_mapped(start.to_bytes(4, "big")), ipv4_mapped(end.to_bytes(4, "big"))


def ipv4_span(
    start: tuple[int, int, int, int], end: tuple[int, int, int, int]
) -> tuple[bytes, bytes]:
    return ipv4_mapped(bytes(start)), ipv4_mapped(bytes(end))


def parse_ipv6(text: str) -> bytes:
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


def ipv6_cidr(cidr: str) -> tuple[bytes, bytes]:
    text, _, bits_text = cidr.partition("/")
    bits = int(bits_text)
    raw = int.from_bytes(parse_ipv6(text), "big")
    if bits == 0:
        mask = 0
    else:
        mask = ((1 << bits) - 1) << (128 - bits)
    start = raw & mask
    host = 0 if bits == 128 else (1 << (128 - bits)) - 1
    end = start | host
    width = (1 << 128) - 1
    return start.to_bytes(16, "big"), (end & width).to_bytes(16, "big")


def write_ipcidr(ranges: list[tuple[bytes, bytes]]) -> bytes:
    body = bytearray(b"\x01")
    body += struct.pack(">q", len(ranges))
    for start, end in ranges:
        if len(start) != 16 or len(end) != 16:
            raise ValueError("ip range must be 16 bytes")
        body += start
        body += end
    return bytes(body)


def mrs_payload(behavior: int, count: int, payload: bytes, extra: bytes = b"") -> bytes:
    body = bytearray(b"MRS\x01")
    body.append(behavior)
    body += struct.pack(">q", count)
    body += struct.pack(">q", len(extra))
    body += extra
    body += payload
    return bytes(body)


def zstd_raw_frame(payload: bytes) -> bytes:
    """One zstd frame, single segment, no checksum, one raw block."""
    if not payload:
        raise ValueError("empty zstd payload")
    if len(payload) > 128 * 1024:
        raise ValueError("raw block is larger than the zstd block limit")
    magic = b"\x28\xb5\x2f\xfd"
    if len(payload) < 256:
        descriptor = 0x20
        fcs = bytes([len(payload)])
    elif len(payload) <= 0xFFFFFFFF:
        descriptor = 0xA0
        fcs = struct.pack("<I", len(payload))
    else:
        descriptor = 0xE0
        fcs = struct.pack("<Q", len(payload))
    header = (len(payload) << 3) | 1
    block = struct.pack("<I", header)[:3]
    return magic + bytes([descriptor]) + fcs + block + payload


def decode_raw_zstd(frame: bytes) -> bytes:
    if frame[:4] != b"\x28\xb5\x2f\xfd":
        raise ValueError("bad zstd magic")
    descriptor = frame[4]
    if descriptor & 0x1C:
        raise ValueError("fixture frames have no checksum, dict or reserved bits")
    if not descriptor & 0x20:
        raise ValueError("fixture frames are single-segment")
    fcs_flag = descriptor >> 6
    cursor = 5
    if fcs_flag == 0:
        size = frame[cursor]
        cursor += 1
    elif fcs_flag == 2:
        size = struct.unpack_from("<I", frame, cursor)[0]
        cursor += 4
    elif fcs_flag == 3:
        size = struct.unpack_from("<Q", frame, cursor)[0]
        cursor += 8
    else:
        raise ValueError(f"unexpected fcs flag {fcs_flag}")
    header = int.from_bytes(frame[cursor : cursor + 3], "little")
    cursor += 3
    if header & 0x1 != 1 or (header >> 1) & 0x3 != 0:
        raise ValueError("expected one last raw block")
    block_size = header >> 3
    if block_size != size or cursor + block_size != len(frame):
        raise ValueError("raw block does not fill the frame")
    return frame[cursor:]


def expect_patterns(patterns: list[str]) -> set[str]:
    """What DomainSet.Foreach emits. `+.` becomes the apex and the dot form."""
    found = set()
    for pattern in patterns:
        parts = pattern.split(".")
        if parts[0] == "+":
            domain = ".".join(parts[1:])
            found.add(domain)
            found.add("." + domain)
        else:
            found.add(pattern)
    return found


def write_domain_fixture() -> None:
    patterns = [
        "example.com",
        "+.sagernet.org",
        ".com.cn",
        "*.qq.com",
        "*.*.baidu.com",
        "www.baidu.*",
        "пример.рф",
        "Mijia Cloud",
    ]
    leaves, bitmap, labels = build_domain_set(insert_patterns(patterns))
    # The chain for reverse("ab") is the vector the sing-box reader tests too.
    ab_leaves, ab_bitmap, ab_labels = build_domain_set([rune_reverse("ab").encode()])
    if ab_leaves != [4] or ab_bitmap != [26] or ab_labels != b"ba":
        raise SystemExit(f"ab succinct set changed: {ab_leaves} {ab_bitmap} {ab_labels!r}")
    restored = set(foreach_patterns(leaves, bitmap, labels))
    if restored != expect_patterns(patterns):
        raise SystemExit(f"domain walk mismatch: {sorted(restored)}")
    payload = mrs_payload(
        BEHAVIOR_DOMAIN, len(patterns), write_domain_set(leaves, bitmap, labels)
    )
    write_checked("domain.mrs", payload)


def write_ip_fixture() -> None:
    ranges = [
        ipv4_cidr("10.0.0.0/8"),
        ipv4_cidr("192.0.2.0/24"),
        ipv4_span((203, 0, 113, 1), (203, 0, 113, 2)),
        ipv6_cidr("2001:db8::/32"),
    ]
    payload = mrs_payload(BEHAVIOR_IPCIDR, len(ranges), write_ipcidr(ranges))
    write_checked("ipcidr.mrs", payload)


def write_checked(name: str, payload: bytes) -> None:
    frame = zstd_raw_frame(payload)
    if decode_raw_zstd(frame) != payload:
        raise SystemExit(f"{name} raw frame did not round-trip")
    zstd = shutil.which("zstd")
    if zstd:
        result = subprocess.run(
            [zstd, "-d", "-c"],
            input=frame,
            check=False,
            capture_output=True,
        )
        if result.returncode != 0 or result.stdout != payload:
            raise SystemExit(
                f"zstd CLI rejected {name}: {result.stderr.decode('utf-8', 'replace')}"
            )
    path = FIXTURE_DIR / name
    path.write_bytes(frame)
    print(f"wrote {path} ({len(frame)} bytes, payload {len(payload)})")


def main() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    write_domain_fixture()
    write_ip_fixture()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
