#!/usr/bin/env python3
"""Pure report and plan helpers for the macOS TUN benchmark.

Nothing in this module opens a socket, touches PF, or changes routes.
The shell script is the only thing that runs privileged commands, and
only after the VM gate. Numbers follow segue-bench: decimal megabits
per second via div_ceil, nearest-rank percentiles, and CPU ms per GiB
of payload bytes.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

MARK_BEGIN = "BEGIN-TUN-BENCH"
MARK_END = "END-TUN-BENCH"
SCHEMA = "tun-bench-macos/1"

# dummynet on this macOS rejects a pipe queue of 1 MiB or more and a
# slot queue above 100. A delay pipe with the default 50-slot queue
# drops on lo0 (16 KiB packets) and would turn "no loss" into loss.
# Bandwidth is capped so the bandwidth-delay product fits in 900 KiB
# even after delay is rounded up to a 10 ms tick (25 -> 30, 75 -> 80).
# Clean installs no pipe. Loss profiles also use the smaller transfer
# (see bulk_bytes): a 3% loss at 150 ms cannot finish 1 GiB here.
IMPAIRMENTS = {
    "clean": {
        "label": "clean",
        "delay_ms": 0,
        "plr": "0",
        "bw": None,
        "queue": None,
        "lossy": False,
        "rtt_ms": 0,
    },
    "rtt50": {
        "label": "50 ms RTT",
        "delay_ms": 25,
        "plr": "0",
        "bw": "200Mbit/s",
        "queue": "900Kbytes",
        "lossy": False,
        "rtt_ms": 50,
    },
    "rtt50-loss1": {
        "label": "50 ms RTT + 1% loss",
        "delay_ms": 25,
        "plr": "0.01",
        "bw": "200Mbit/s",
        "queue": "900Kbytes",
        "lossy": True,
        "rtt_ms": 50,
    },
    "rtt150-loss3": {
        "label": "150 ms RTT + 3% loss",
        "delay_ms": 75,
        "plr": "0.03",
        "bw": "80Mbit/s",
        "queue": "900Kbytes",
        "lossy": True,
        "rtt_ms": 150,
    },
}

ENGINES = (
    "segue-kernel",
    "sing-box",
    "mihomo-system",
    "mihomo-mixed",
)
PROTOCOLS = ("reality", "grpc")
IMPAIRMENT_ORDER = tuple(IMPAIRMENTS)
WORKLOAD_ORDER = ("bulk-1", "bulk-8", "tcp-rr", "ttfb")

ANCHOR_CHILD = "com.apple/segue.tunbench"
ANCHOR_FALLBACK = "segue.tunbench"

GIB = 1024 * 1024 * 1024


class ReportError(ValueError):
    """A plan or sample the report generator will not accept."""


def div_ceil(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ReportError("div_ceil denominator must be positive")
    return (numerator + denominator - 1) // denominator


def parse_ps_time_to_millis(raw: str) -> int:
    """Parse a macOS `ps` TIME field into milliseconds.

    Accepts ``mm:ss``, ``mm:ss.s``, ``hh:mm:ss``, ``hh:mm:ss.sss`` and a
    leading ``d-`` day count, matching segue-bench's ``parse_ps_time_to_millis``.
    """
    text = raw.strip()
    days = 0
    if "-" in text:
        day_text, text = text.split("-", 1)
        if not day_text.isdigit():
            raise ReportError("invalid ps day field {0!r}".format(raw))
        days = int(day_text)
    parts = text.split(":")
    if len(parts) == 2:
        hours = 0
        minutes = _time_part(parts[0], raw)
        seconds_ms = _seconds_millis(parts[1], raw)
    elif len(parts) == 3:
        hours = _time_part(parts[0], raw)
        minutes = _time_part(parts[1], raw)
        seconds_ms = _seconds_millis(parts[2], raw)
    else:
        raise ReportError("invalid ps time field {0!r}".format(raw))
    return (
        days * 24 * 60 * 60 * 1000
        + hours * 60 * 60 * 1000
        + minutes * 60 * 1000
        + seconds_ms
    )


def _time_part(raw: str, whole: str) -> int:
    if not raw.isdigit():
        raise ReportError("invalid ps time component {0!r}".format(whole))
    return int(raw)


def _seconds_millis(raw: str, whole: str) -> int:
    if "." in raw:
        sec_text, frac = raw.split(".", 1)
    else:
        sec_text, frac = raw, ""
    seconds = _time_part(sec_text, whole)
    millis = 0
    for index, char in enumerate(frac[:3]):
        if not char.isdigit():
            raise ReportError("invalid ps second component {0!r}".format(whole))
        digit = int(char)
        millis += digit * (100, 10, 1)[index]
    return seconds * 1000 + millis


def parse_ps_sample(raw: str) -> dict:
    """Parse one `ps -o rss= -o time=` line into rss_kib and cpu_millis."""
    fields = raw.split()
    if len(fields) < 2:
        raise ReportError("invalid ps sample {0!r}".format(raw))
    if not fields[0].isdigit():
        raise ReportError("invalid ps rss field {0!r}".format(fields[0]))
    return {
        "rss_kib": int(fields[0]),
        "cpu_millis": parse_ps_time_to_millis(fields[1]),
    }


def percentile_nearest_rank(sorted_values: list, percentile: int):
    """Nearest-rank percentile, the same index segue-bench uses.

    ``rank = ceil(n * percentile / 100)``, then index ``rank - 1``.
    Empty input is None (the harness returns 0; a report should not
    pretend a latency of zero).
    """
    if not sorted_values:
        return None
    if percentile < 0 or percentile > 100:
        raise ReportError("percentile must be 0..=100")
    rank = div_ceil(len(sorted_values) * percentile, 100)
    return sorted_values[max(rank - 1, 0)]


def median_upper(sorted_values: list):
    """``sorted[len // 2]``, segue-bench's phase-memory median index."""
    if not sorted_values:
        return None
    return sorted_values[len(sorted_values) // 2]


def throughput_mbps(nbytes: int, duration_ms: int):
    """Decimal Mbps. ``ceil(bytes * 8 / (duration_ms * 1000))``.

    1,073,741,824 bytes in 329 ms is 26110, the 2026-11-18 segue gRPC
    median. None when there is nothing to divide.
    """
    if nbytes <= 0 or duration_ms <= 0:
        return None
    return div_ceil(nbytes * 8, duration_ms * 1000)


def cpu_ms_per_gib(cpu_ms: int, nbytes: int):
    """CPU milliseconds per GiB of payload, div_ceil like segue-bench."""
    if nbytes <= 0 or cpu_ms < 0:
        return None
    return div_ceil(cpu_ms * GIB, nbytes)


def bulk_bytes(impairment: str, full_bytes: int, lossy_bytes: int) -> int:
    spec = _impairment(impairment)
    if full_bytes <= 0 or lossy_bytes <= 0:
        raise ReportError("byte counts must be positive")
    if spec["lossy"]:
        return lossy_bytes
    return full_bytes


def requested_count(workload: str, impairment: str, full_bytes: int, lossy_bytes: int, rr_count: int, ttfb_count: int) -> dict:
    _workload(workload)
    if workload in ("bulk-1", "bulk-8"):
        return {"bytes_requested": bulk_bytes(impairment, full_bytes, lossy_bytes)}
    if workload == "tcp-rr":
        if rr_count <= 0:
            raise ReportError("rr_count must be positive")
        return {"iterations": rr_count}
    if ttfb_count <= 0:
        raise ReportError("ttfb_count must be positive")
    return {"iterations": ttfb_count}


def dnctl_argv(impairment: str, pipe: int = 7) -> list:
    """Arguments after ``dnctl``. Empty for the clean profile (no pipe)."""
    spec = _impairment(impairment)
    if pipe < 1 or pipe > 65535:
        raise ReportError("pipe must be 1..=65535")
    if spec["delay_ms"] == 0:
        return []
    return [
        "pipe",
        str(pipe),
        "config",
        "delay",
        str(spec["delay_ms"]),
        "plr",
        spec["plr"],
        "bw",
        spec["bw"],
        "queue",
        spec["queue"],
    ]


def pf_rules(port: int, pipe: int) -> str:
    """Dummynet filter rules for one carrier port, both directions.

    ``out`` on lo0 matches each direction once (the reply is a new
    outbound packet), so one-way delay is half the intended RTT.
    ``no state`` is required: pfctl rejects stateful dummynet rules.
    """
    if not 1 <= port <= 65535:
        raise ReportError("port out of range")
    if not 1 <= pipe <= 65535:
        raise ReportError("pipe out of range")
    return (
        "dummynet out quick on lo0 inet proto tcp "
        "from any to 127.0.0.1 port {port} no state pipe {pipe}\n"
        "dummynet out quick on lo0 inet proto tcp "
        "from 127.0.0.1 port {port} to any no state pipe {pipe}\n"
    ).format(port=port, pipe=pipe)


def pf_ruleset_for_bench(text: str, anchor: str = ANCHOR_FALLBACK) -> str:
    """Comment out ``set skip on lo0`` and reference ``anchor`` once.

    Used only when the running ruleset does not already evaluate
    ``dummynet-anchor "com.apple/*"``. The child anchor under com.apple
    is not written here. Idempotent.
    """
    if (
        not anchor
        or any(char.isspace() for char in anchor)
        or '"' in anchor
        or "/" in anchor
    ):
        raise ReportError("unsafe anchor name")
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            lines.append(line)
            continue
        if _skip_lo0(stripped):
            lines.append(
                "# segue-tun-bench: lo0 must not be skipped, or dummynet never sees the carrier"
            )
            lines.append("# " + line)
        else:
            lines.append(line)
    body = "\n".join(lines)
    if body and not body.endswith("\n"):
        body += "\n"
    extra = []
    dummynet_line = 'dummynet-anchor "{0}"'.format(anchor)
    anchor_line = 'anchor "{0}"'.format(anchor)
    if dummynet_line not in body:
        extra.append(dummynet_line)
    if anchor_line not in body:
        extra.append(anchor_line)
    if extra:
        body += "\n".join(extra) + "\n"
    return body


def _skip_lo0(stripped: str) -> bool:
    # "set skip on lo0" or "set skip on { lo0, en0 }".
    if not stripped.startswith("set skip"):
        return False
    return "lo0" in stripped.split()


def parse_netstat(text: str, family: str) -> list:
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        dest, gateway, _flags, netif = parts[0], parts[1], parts[2], parts[3]
        if dest in {"Destination", "Routing", "Internet:", "Internet6:"}:
            continue
        if not netif.startswith("utun"):
            continue
        rows.append((family, dest, gateway, netif))
    return rows


def leftover_tun_routes(before_v4: str, after_v4: str, before_v6: str = "", after_v6: str = "") -> list:
    """Route-delete argument tails for utun routes that appeared during a run.

    Each item is ``["v4", dest, gateway]`` or ``["v6", dest, gateway]``.
    Routes whose interface is not a utun (the system default on en0) are
    ignored. A route that was already present before the engine started
    is left alone.
    """
    before = set(parse_netstat(before_v4, "v4")) | set(parse_netstat(before_v6, "v6"))
    after = parse_netstat(after_v4, "v4") + parse_netstat(after_v6, "v6")
    deletes = []
    seen = set()
    for row in after:
        if row in before or row in seen:
            continue
        seen.add(row)
        family, dest, gateway, _netif = row
        deletes.append([family, dest, gateway])
    return deletes


def summarize_samples(samples: list) -> dict:
    """RSS first/median/peak/last and CPU milliseconds during the sample window.

    Median uses the phase-memory index ``sorted[len // 2]``. CPU is the
    last cumulative `ps` time minus the first, never negative.
    """
    if not samples:
        return {
            "samples": 0,
            "first_rss_kib": None,
            "median_rss_kib": None,
            "peak_rss_kib": None,
            "last_rss_kib": None,
            "cpu_ms": None,
        }
    rss = [int(sample["rss_kib"]) for sample in samples]
    ordered = sorted(rss)
    first_cpu = int(samples[0]["cpu_millis"])
    last_cpu = int(samples[-1]["cpu_millis"])
    return {
        "samples": len(samples),
        "first_rss_kib": rss[0],
        "median_rss_kib": median_upper(ordered),
        "peak_rss_kib": ordered[-1],
        "last_rss_kib": rss[-1],
        "cpu_ms": max(0, last_cpu - first_cpu),
    }


def latency_summary(values: list) -> dict:
    ordered = sorted(int(v) for v in values)
    return {
        "count": len(ordered),
        "min_us": ordered[0] if ordered else None,
        "p50_us": percentile_nearest_rank(ordered, 50),
        "p99_us": percentile_nearest_rank(ordered, 99),
        "max_us": ordered[-1] if ordered else None,
    }


def _tokens(raw: str, allowed: tuple, flag: str) -> list:
    items = [part.strip() for part in raw.split(",") if part.strip()]
    if not items:
        raise ReportError("{0} is empty".format(flag))
    unknown = [item for item in items if item not in allowed]
    if unknown:
        raise ReportError("unknown {0}: {1}".format(flag, ", ".join(unknown)))
    return items


def _impairment(name: str) -> dict:
    try:
        return IMPAIRMENTS[name]
    except KeyError as exc:
        raise ReportError("unknown impairment {0}".format(name)) from exc


def _workload(name: str) -> str:
    if name not in WORKLOAD_ORDER:
        raise ReportError("unknown workload {0}".format(name))
    return name


def _engine(name: str) -> str:
    if name not in ENGINES:
        raise ReportError("unknown engine {0}".format(name))
    return name


def _protocol(name: str) -> str:
    if name not in PROTOCOLS:
        raise ReportError("unknown protocol {0}".format(name))
    return name


def planned_cells(engines, protocols, impairments, workloads, full_bytes, lossy_bytes, rr_count, ttfb_count) -> list:
    cells = []
    for engine in engines:
        for protocol in protocols:
            for impairment in impairments:
                for workload in workloads:
                    cell = {
                        "engine": engine,
                        "protocol": protocol,
                        "impairment": impairment,
                        "workload": workload,
                        "status": "planned",
                    }
                    cell.update(
                        requested_count(
                            workload, impairment, full_bytes, lossy_bytes, rr_count, ttfb_count
                        )
                    )
                    cells.append(cell)
    return cells


def summarize_cell(cell: dict) -> dict:
    """Drop raw samples. Keep the numbers the markdown table prints."""
    engine = _engine(str(cell.get("engine", "")))
    protocol = _protocol(str(cell.get("protocol", "")))
    impairment = str(cell.get("impairment", ""))
    _impairment(impairment)
    workload = _workload(str(cell.get("workload", "")))
    status = cell.get("status")
    if status == "planned":
        out = {
            "engine": engine,
            "protocol": protocol,
            "impairment": impairment,
            "workload": workload,
            "status": "planned",
            "ok": None,
            "error": None,
        }
        if "bytes_requested" in cell:
            out["bytes_requested"] = int(cell["bytes_requested"])
        if "iterations" in cell:
            out["iterations"] = int(cell["iterations"])
        return out

    ok = bool(cell.get("ok"))
    error = cell.get("error")
    if error is not None:
        error = str(error)
    nbytes = int(cell.get("bytes") or 0)
    duration_ms = int(cell.get("duration_ms") or 0)
    samples = summarize_samples(list(cell.get("samples") or []))
    latency = latency_summary(list(cell.get("latency_us") or []))
    ttfb_us = latency_summary(list(cell.get("ttfb_samples_us") or []))
    cpu_ms = samples["cpu_ms"]
    per_gib = None
    if workload in ("bulk-1", "bulk-8") and cpu_ms is not None:
        per_gib = cpu_ms_per_gib(cpu_ms, nbytes)
    ttfb_ms = cell.get("ttfb_ms")
    if ttfb_ms is not None:
        ttfb_ms = round(float(ttfb_ms), 3)
    elif ttfb_us["p50_us"] is not None and workload == "ttfb":
        ttfb_ms = round(ttfb_us["p50_us"] / 1000.0, 3)
    out = {
        "engine": engine,
        "protocol": protocol,
        "impairment": impairment,
        "workload": workload,
        "status": "ok" if ok and not error else "fail",
        "ok": ok and not error,
        "error": error,
        "bytes": nbytes,
        "duration_ms": duration_ms,
        "throughput_mbps": throughput_mbps(nbytes, duration_ms) if workload in ("bulk-1", "bulk-8") else None,
        "ttfb_ms": ttfb_ms,
        "ttfb_p50_ms": None if ttfb_us["p50_us"] is None else round(ttfb_us["p50_us"] / 1000.0, 3),
        "ttfb_p99_ms": None if ttfb_us["p99_us"] is None else round(ttfb_us["p99_us"] / 1000.0, 3),
        "latency_p50_us": latency["p50_us"] if workload == "tcp-rr" else None,
        "latency_p99_us": latency["p99_us"] if workload == "tcp-rr" else None,
        "latency_count": latency["count"] if workload == "tcp-rr" else None,
        "rss_kib": {
            "samples": samples["samples"],
            "first": samples["first_rss_kib"],
            "median": samples["median_rss_kib"],
            "peak": samples["peak_rss_kib"],
            "last": samples["last_rss_kib"],
        },
        "cpu_ms": cpu_ms,
        "cpu_ms_per_gib": per_gib,
    }
    if "bytes_requested" in cell:
        out["bytes_requested"] = int(cell["bytes_requested"])
    if "iterations" in cell:
        out["iterations"] = int(cell["iterations"])
    return out


def sort_key(cell: dict) -> tuple:
    def index(order, value):
        try:
            return order.index(value)
        except ValueError:
            return len(order)

    return (
        index(ENGINES, cell.get("engine")),
        index(PROTOCOLS, cell.get("protocol")),
        index(IMPAIRMENT_ORDER, cell.get("impairment")),
        index(WORKLOAD_ORDER, cell.get("workload")),
    )


def build_report(meta: dict, cells: list) -> dict:
    summarized = [summarize_cell(cell) for cell in cells]
    summarized.sort(key=sort_key)
    failed = sum(1 for cell in summarized if cell["status"] == "fail")
    report = {
        "schema": SCHEMA,
        "generated_at": meta.get("generated_at") or "unspecified",
        "dry_run": bool(meta.get("dry_run")),
        "hv_vmm_present": meta.get("hv_vmm_present"),
        "target": meta.get("target") or "198.51.100.20:5001",
        "sink": meta.get("sink") or "127.0.0.1:5001",
        "carrier_ports": meta.get("carrier_ports") or {"reality": 24443, "grpc": 24444},
        "pins": meta.get("pins") or {},
        "full_bytes": meta.get("full_bytes"),
        "lossy_bytes": meta.get("lossy_bytes"),
        "rr_count": meta.get("rr_count"),
        "ttfb_count": meta.get("ttfb_count"),
        "sample_interval_ms": meta.get("sample_interval_ms"),
        "cell_timeout_s": meta.get("cell_timeout_s"),
        "impairments": {
            name: {
                "label": spec["label"],
                "delay_ms": spec["delay_ms"],
                "plr": spec["plr"],
                "bw": spec["bw"],
                "queue": spec["queue"],
                "lossy": spec["lossy"],
                "intended_rtt_ms": spec["rtt_ms"],
            }
            for name, spec in IMPAIRMENTS.items()
        },
        "cell_count": len(summarized),
        "failed": failed,
        "cells": summarized,
    }
    for key in ("notes", "work_dir", "json_path"):
        if key in meta:
            report[key] = meta[key]
    return report


def _fmt(value, dash="—") -> str:
    if value is None:
        return dash
    return str(value)


def _rss_mib(kib) -> str:
    if kib is None:
        return "—"
    return "{0:.1f}".format(kib / 1024.0)


def _cell_text(value: str) -> str:
    return value.replace("|", "/").replace("\n", " ").strip() or "—"


def render_markdown(report: dict) -> str:
    lines = [
        "TUN path, one engine at a time. Destination {0} is redirected by the Xray freedom outbound to {1}.".format(
            report.get("target"), report.get("sink")
        ),
        "",
        "| engine | protocol | link | workload | status | bytes | ms | Mbps | ttfb ms | rr p50 us | rr p99 us | peak RSS MiB | CPU ms | CPU ms/GiB | note |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for cell in report["cells"]:
        spec = IMPAIRMENTS[cell["impairment"]]
        if cell["status"] == "planned":
            note = "planned"
            if "bytes_requested" in cell:
                note = "planned {0} bytes".format(cell["bytes_requested"])
            elif "iterations" in cell:
                note = "planned {0} iters".format(cell["iterations"])
            row = [
                cell["engine"],
                cell["protocol"],
                spec["label"],
                cell["workload"],
                "planned",
                _fmt(cell.get("bytes_requested")),
                "—",
                "—",
                "—",
                "—",
                "—",
                "—",
                "—",
                "—",
                note,
            ]
        else:
            note = _cell_text(cell["error"]) if cell.get("error") else ""
            row = [
                cell["engine"],
                cell["protocol"],
                spec["label"],
                cell["workload"],
                cell["status"],
                _fmt(cell.get("bytes")),
                _fmt(cell.get("duration_ms")),
                _fmt(cell.get("throughput_mbps")),
                _fmt(cell.get("ttfb_ms")),
                _fmt(cell.get("latency_p50_us")),
                _fmt(cell.get("latency_p99_us")),
                _rss_mib(cell.get("rss_kib", {}).get("peak")),
                _fmt(cell.get("cpu_ms")),
                _fmt(cell.get("cpu_ms_per_gib")),
                note or "—",
            ]
        lines.append("| " + " | ".join(_cell_text(str(item)) for item in row) + " |")
    lines.extend(
        [
            "",
            "Mbps is decimal (`ceil(bytes * 8 / (duration_ms * 1000))`), the segue-bench formula. "
            "RSS median in the JSON is `sorted[len // 2]`. Latency percentiles are nearest-rank. "
            "CPU ms/GiB is payload bytes only and only on the bulk workloads.",
            "",
            "Link model: dummynet `out` on lo0 for the carrier port only, both directions, so RTT is twice `delay`. "
            "The pipe queue must be under 1 MiB on this macOS; delay profiles set `bw` and `queue 900Kbytes` "
            "so the bandwidth-delay product fits and a delay is not accidental loss. "
            "Dummynet rounds `delay` up to the clock tick (often 10 ms), so 25 ms may be 30 ms (RTT 60 ms) "
            "and 75 ms may be 80 ms (RTT 160 ms). Loss profiles transfer `lossy_bytes` rather than 1 GiB: "
            "at 3% loss and 150 ms, TCP cannot finish a gibibyte inside a Satellite lifetime. "
            "Clean and the no-loss 50 ms profile transfer `full_bytes`.",
            "",
            "failed={0} cells={1} dry_run={2}".format(
                report.get("failed"), report.get("cell_count"), report.get("dry_run")
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def render_marked(report: dict) -> str:
    return "{0}\n{1}\n{2}\n{3}".format(
        MARK_BEGIN, render_markdown(report).rstrip(), render_json(report).rstrip(), MARK_END
    )


def extract_json(marked: str) -> dict:
    start = marked.index("\n{") + 1
    end = marked.rindex("\n" + MARK_END)
    return json.loads(marked[start:end])


def load_cells(directory: Path) -> list:
    cells = []
    if not directory.is_dir():
        raise ReportError("cells directory does not exist: {0}".format(directory))
    for path in sorted(directory.glob("*.json")):
        try:
            cells.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            raise ReportError("{0}: {1}".format(path.name, exc)) from exc
    return cells


def _split_opt(parser, dest, default, allowed, help_text):
    parser.add_argument(dest, default=",".join(default), help=help_text)
    return allowed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TUN benchmark report generator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    plan = sub.add_parser("plan")
    plan.add_argument("--engines", default=",".join(ENGINES))
    plan.add_argument("--protocols", default=",".join(PROTOCOLS))
    plan.add_argument("--impairments", default=",".join(IMPAIRMENT_ORDER))
    plan.add_argument("--workloads", default=",".join(WORKLOAD_ORDER))
    plan.add_argument("--full-bytes", type=int, default=GIB)
    plan.add_argument("--lossy-bytes", type=int, default=8 * 1024 * 1024)
    plan.add_argument("--rr-count", type=int, default=200)
    plan.add_argument("--ttfb-count", type=int, default=20)
    plan.add_argument("--json", dest="json_path")
    plan.add_argument("--meta", dest="meta_path")

    render = sub.add_parser("render")
    render.add_argument("--cells", required=True)
    render.add_argument("--meta", required=True)
    render.add_argument("--json", dest="json_path")

    err = sub.add_parser("error-cell")
    err.add_argument("--out", required=True)
    err.add_argument("--engine", required=True)
    err.add_argument("--protocol", required=True)
    err.add_argument("--impairment", required=True)
    err.add_argument("--workload", required=True)
    err.add_argument("--error", required=True)
    err.add_argument("--bytes-requested", type=int)
    err.add_argument("--iterations", type=int)

    dn = sub.add_parser("dnctl-args")
    dn.add_argument("--impairment", required=True)
    dn.add_argument("--pipe", type=int, default=7)

    pf = sub.add_parser("pf-rules")
    pf.add_argument("--port", type=int, required=True)
    pf.add_argument("--pipe", type=int, default=7)

    patch = sub.add_parser("pf-patch")
    patch.add_argument("--anchor", default=ANCHOR_FALLBACK)

    left = sub.add_parser("leftover-routes")
    left.add_argument("--before-v4", required=True)
    left.add_argument("--after-v4", required=True)
    left.add_argument("--before-v6", default="")
    left.add_argument("--after-v6", default="")

    bulk = sub.add_parser("bulk-bytes")
    bulk.add_argument("--impairment", required=True)
    bulk.add_argument("--full-bytes", type=int, required=True)
    bulk.add_argument("--lossy-bytes", type=int, required=True)
    return parser


def _meta_from_plan_args(args) -> dict:
    meta = {
        "dry_run": True,
        "generated_at": "dry-run",
        "full_bytes": args.full_bytes,
        "lossy_bytes": args.lossy_bytes,
        "rr_count": args.rr_count,
        "ttfb_count": args.ttfb_count,
        "pins": {
            "xray_core": "676eaf66f8f05d4d558ee7a74b4736623d3feeb9",
            "xray_tag": "v26.11.9",
            "sing_box": "824dbcfb4dd0a95921840b1737b950cde590241e",
            "sing_box_tag": "v1.15.0-alpha.13",
            "mihomo": "3c0d10a503f7b2fde3fe167d4d91dd05725d5268",
        },
    }
    if args.meta_path:
        loaded = json.loads(Path(args.meta_path).read_text(encoding="utf-8"))
        meta.update(loaded)
        meta["dry_run"] = True
    return meta


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.cmd == "dnctl-args":
            for item in dnctl_argv(args.impairment, args.pipe):
                print(item)
            return 0
        if args.cmd == "pf-rules":
            sys.stdout.write(pf_rules(args.port, args.pipe))
            return 0
        if args.cmd == "pf-patch":
            sys.stdout.write(pf_ruleset_for_bench(sys.stdin.read(), args.anchor))
            return 0
        if args.cmd == "bulk-bytes":
            print(bulk_bytes(args.impairment, args.full_bytes, args.lossy_bytes))
            return 0
        if args.cmd == "leftover-routes":
            before_v6 = Path(args.before_v6).read_text(encoding="utf-8") if args.before_v6 else ""
            after_v6 = Path(args.after_v6).read_text(encoding="utf-8") if args.after_v6 else ""
            rows = leftover_tun_routes(
                Path(args.before_v4).read_text(encoding="utf-8"),
                Path(args.after_v4).read_text(encoding="utf-8"),
                before_v6,
                after_v6,
            )
            for family, dest, gateway in rows:
                print("{0}\t{1}\t{2}".format(family, dest, gateway))
            return 0
        if args.cmd == "error-cell":
            cell = {
                "engine": args.engine,
                "protocol": args.protocol,
                "impairment": args.impairment,
                "workload": args.workload,
                "ok": False,
                "error": args.error,
                "bytes": 0,
                "duration_ms": 0,
                "samples": [],
                "latency_us": [],
                "ttfb_samples_us": [],
            }
            if args.bytes_requested is not None:
                cell["bytes_requested"] = args.bytes_requested
            if args.iterations is not None:
                cell["iterations"] = args.iterations
            Path(args.out).write_text(json.dumps(cell, indent=2) + "\n", encoding="utf-8")
            return 0
        if args.cmd == "plan":
            engines = _tokens(args.engines, ENGINES, "engines")
            protocols = _tokens(args.protocols, PROTOCOLS, "protocols")
            impairments = _tokens(args.impairments, IMPAIRMENT_ORDER, "impairments")
            workloads = _tokens(args.workloads, WORKLOAD_ORDER, "workloads")
            meta = _meta_from_plan_args(args)
            cells = planned_cells(
                engines,
                protocols,
                impairments,
                workloads,
                args.full_bytes,
                args.lossy_bytes,
                args.rr_count,
                args.ttfb_count,
            )
            report = build_report(meta, cells)
        else:
            meta = json.loads(Path(args.meta).read_text(encoding="utf-8"))
            report = build_report(meta, load_cells(Path(args.cells)))
        marked = render_marked(report)
        sys.stdout.write(marked)
        if not marked.endswith("\n"):
            sys.stdout.write("\n")
        if args.json_path:
            Path(args.json_path).write_text(render_json(report), encoding="utf-8")
        return 0
    except ReportError as exc:
        print("tun-bench report: {0}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
