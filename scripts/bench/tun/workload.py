#!/usr/bin/env python3
"""Sink and TUN client for the macOS benchmark.

The sink listens on loopback. The client dials 198.51.100.20, which only
answers if an engine has captured that address and the Xray fixture has
redirected it back to the sink. Running the client against loopback
directly is a manual check; the benchmark script is what points it at
the documentation address.

Protocol, one ASCII line then a byte stream:
  BULK <nbytes>\\n   sink writes exactly nbytes
  ECHO <count>\\n    sink echoes the next count single bytes, one at a time
"""

from __future__ import annotations

import argparse
import json
import signal
import socket
import sys
import threading
import time
from pathlib import Path

import report


def _ignore_sigpipe():
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)


def read_line(conn: socket.socket, limit: int = 64) -> str:
    buf = bytearray()
    while len(buf) < limit:
        piece = conn.recv(1)
        if not piece:
            raise ConnectionError("short header")
        if piece == b"\n":
            return buf.decode("ascii")
        buf += piece
    raise ConnectionError("header too long")


def read_exact(conn: socket.socket, nbytes: int) -> bytes:
    buf = bytearray()
    while len(buf) < nbytes:
        piece = conn.recv(nbytes - len(buf))
        if not piece:
            raise ConnectionError("short read")
        buf += piece
    return bytes(buf)


def write_all(conn: socket.socket, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        sent = conn.send(view)
        if sent <= 0:
            raise ConnectionError("short write")
        view = view[sent:]


def _tune(conn: socket.socket) -> None:
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    buf = 1 << 20
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            conn.setsockopt(socket.SOL_SOCKET, opt, buf)
        except OSError:
            pass


def serve_sink(listen: str) -> None:
    host, port_text = listen.rsplit(":", 1)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, int(port_text)))
    server.listen(128)
    server.settimeout(1.0)
    stopping = threading.Event()

    def handle(conn: socket.socket) -> None:
        with conn:
            _tune(conn)
            conn.settimeout(300)
            try:
                line = read_line(conn)
            except (ConnectionError, OSError, UnicodeError):
                return
            try:
                if line.startswith("BULK "):
                    left = int(line.split()[1])
                    if left < 0:
                        return
                    chunk = b"\0" * 65536
                    while left:
                        take = chunk if left >= len(chunk) else chunk[:left]
                        write_all(conn, take)
                        left -= len(take)
                elif line.startswith("ECHO "):
                    count = int(line.split()[1])
                    for _ in range(count):
                        write_all(conn, read_exact(conn, 1))
            except (ConnectionError, OSError, ValueError):
                return

    def accept_loop() -> None:
        while not stopping.is_set():
            try:
                conn, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    print("sink listening {0}".format(server.getsockname()), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stopping.set()
        server.close()


def _connect(target: str, timeout: float) -> socket.socket:
    host, port_text = target.rsplit(":", 1)
    conn = socket.create_connection((host, int(port_text)), timeout=timeout)
    _tune(conn)
    return conn


def _sample_once(pid: int, started: float):
    import subprocess

    try:
        proc = subprocess.run(
            ["/bin/ps", "-o", "rss=", "-o", "time=", "-p", str(pid)],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    line = next((item for item in proc.stdout.splitlines() if item.strip()), "")
    if not line:
        return None
    try:
        parsed = report.parse_ps_sample(line)
    except report.ReportError:
        return None
    parsed["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return parsed


def _sampler(pid: int, interval: float, samples: list, stop: threading.Event, started: float) -> None:
    while not stop.is_set():
        parsed = _sample_once(pid, started)
        if parsed is not None:
            samples.append(parsed)
        stop.wait(interval)


class _Deadline:
    def __init__(self, seconds: float) -> None:
        self.end = time.monotonic() + seconds

    def remaining(self) -> float:
        return self.end - time.monotonic()

    def check(self) -> None:
        if self.remaining() <= 0:
            raise TimeoutError("cell timeout")


def _apply_timeout(conn: socket.socket, deadline: _Deadline) -> None:
    deadline.check()
    conn.settimeout(max(deadline.remaining(), 0.1))


def run_bulk(target, nbytes, streams, deadline):
    started = time.perf_counter()
    errors = []
    if streams < 1 or nbytes < 1:
        return {
            "ok": False,
            "error": "bulk size must be positive",
            "bytes": 0,
            "duration_ms": 0,
            "ttfb_ms": None,
            "ttfb_samples_us": [],
            "latency_us": [],
        }
    if nbytes < streams:
        streams = 1
    per_stream = nbytes // streams
    # The last stream carries the remainder so the total is exact.
    sizes = [per_stream] * (streams - 1)
    sizes.append(nbytes - per_stream * (streams - 1))
    results = [None] * streams

    def one(index, size):
        ttfb_us = None
        got = 0
        try:
            local = _Deadline(deadline.remaining())
            begin = time.perf_counter()
            conn = _connect(target, local.remaining())
            with conn:
                _apply_timeout(conn, local)
                write_all(conn, "BULK {0}\n".format(size).encode("ascii"))
                first = True
                while got < size:
                    _apply_timeout(conn, local)
                    piece = conn.recv(min(65536, size - got))
                    if not piece:
                        raise ConnectionError("short bulk read")
                    if first:
                        ttfb_us = int((time.perf_counter() - begin) * 1_000_000)
                        first = False
                    got += len(piece)
            results[index] = (got, ttfb_us, None)
        except Exception as exc:  # noqa: BLE001 - one cell records the failure
            results[index] = (got, ttfb_us, str(exc))

    threads = [
        threading.Thread(target=one, args=(index, size), daemon=True)
        for index, size in enumerate(sizes)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    duration_ms = int(round((time.perf_counter() - started) * 1000))
    total = 0
    ttfbs = []
    for item in results:
        if item is None:
            errors.append("stream did not finish")
            continue
        got, ttfb_us, err = item
        total += got
        if ttfb_us is not None:
            ttfbs.append(ttfb_us)
        if err:
            errors.append(err)
    ttfb_ms = None if not ttfbs else round(min(ttfbs) / 1000.0, 3)
    return {
        "ok": not errors and total == nbytes,
        "error": "; ".join(errors) if errors else None,
        "bytes": total,
        "duration_ms": duration_ms,
        "ttfb_ms": ttfb_ms,
        "ttfb_samples_us": ttfbs,
        "latency_us": [],
    }


def run_echo(target, count, deadline):
    started = time.perf_counter()
    latencies = []
    try:
        conn = _connect(target, deadline.remaining())
        with conn:
            _apply_timeout(conn, deadline)
            write_all(conn, "ECHO {0}\n".format(count).encode("ascii"))
            for _ in range(count):
                _apply_timeout(conn, deadline)
                begin = time.perf_counter()
                write_all(conn, b"x")
                read_exact(conn, 1)
                latencies.append(int((time.perf_counter() - begin) * 1_000_000))
        duration_ms = int(round((time.perf_counter() - started) * 1000))
        return {
            "ok": len(latencies) == count,
            "error": None if len(latencies) == count else "short echo",
            "bytes": len(latencies),
            "duration_ms": duration_ms,
            "ttfb_ms": None,
            "ttfb_samples_us": [],
            "latency_us": latencies,
        }
    except Exception as exc:  # noqa: BLE001
        duration_ms = int(round((time.perf_counter() - started) * 1000))
        return {
            "ok": False,
            "error": str(exc),
            "bytes": len(latencies),
            "duration_ms": duration_ms,
            "ttfb_ms": None,
            "ttfb_samples_us": [],
            "latency_us": latencies,
        }


def run_ttfb(target, count, deadline):
    started = time.perf_counter()
    samples = []
    error = None
    try:
        for _ in range(count):
            deadline.check()
            begin = time.perf_counter()
            conn = _connect(target, deadline.remaining())
            with conn:
                _apply_timeout(conn, deadline)
                write_all(conn, b"BULK 1\n")
                piece = conn.recv(1)
                if not piece:
                    raise ConnectionError("no first byte")
                samples.append(int((time.perf_counter() - begin) * 1_000_000))
    except Exception as exc:  # noqa: BLE001
        error = str(exc)
    duration_ms = int(round((time.perf_counter() - started) * 1000))
    ttfb_ms = None if not samples else round(samples[0] / 1000.0, 3)
    return {
        "ok": error is None and len(samples) == count,
        "error": error,
        "bytes": len(samples),
        "duration_ms": duration_ms,
        "ttfb_ms": ttfb_ms,
        "ttfb_samples_us": samples,
        "latency_us": [],
    }


def _identity(args) -> dict:
    return {
        "engine": args.engine,
        "protocol": args.protocol,
        "impairment": args.impairment,
        "workload": args.workload,
    }


def _run_client(args) -> dict:
    deadline = _Deadline(args.timeout)
    samples = []
    stop = threading.Event()
    started = time.monotonic()
    sampler = None
    if args.engine_pid > 0 and args.workload != "probe":
        sampler = threading.Thread(
            target=_sampler,
            args=(args.engine_pid, args.interval_ms / 1000.0, samples, stop, started),
            daemon=True,
        )
        sampler.start()
    try:
        if args.cmd == "bulk":
            result = run_bulk(args.target, args.bytes, args.streams, deadline)
            result["bytes_requested"] = args.bytes
        elif args.cmd == "tcp-rr":
            result = run_echo(args.target, args.count, deadline)
            result["iterations"] = args.count
        elif args.cmd == "ttfb":
            result = run_ttfb(args.target, args.count, deadline)
            result["iterations"] = args.count
        else:
            result = run_bulk(args.target, 1, 1, deadline)
            result["workload"] = "probe"
    finally:
        stop.set()
        if sampler is not None:
            sampler.join(timeout=2)
            last = _sample_once(args.engine_pid, started)
            if last is not None:
                samples.append(last)
    result.update(_identity(args))
    result["samples"] = samples
    return result


def main(argv=None) -> int:
    _ignore_sigpipe()
    parser = argparse.ArgumentParser(description="TUN benchmark workload")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sink = sub.add_parser("sink")
    sink.add_argument("--listen", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--target", required=True)
    common.add_argument("--timeout", type=float, default=240)
    common.add_argument("--engine-pid", type=int, default=0)
    common.add_argument("--interval-ms", type=int, default=100)
    common.add_argument("--out", required=True)
    common.add_argument("--engine", default="probe")
    common.add_argument("--protocol", default="probe")
    common.add_argument("--impairment", default="clean")
    common.add_argument("--workload", default="probe")
    bulk = sub.add_parser("bulk", parents=[common])
    bulk.add_argument("--bytes", type=int, required=True)
    bulk.add_argument("--streams", type=int, default=1)
    rr = sub.add_parser("tcp-rr", parents=[common])
    rr.add_argument("--count", type=int, required=True)
    ttfb = sub.add_parser("ttfb", parents=[common])
    ttfb.add_argument("--count", type=int, required=True)
    sub.add_parser("probe", parents=[common])
    args = parser.parse_args(argv)
    if args.cmd == "sink":
        serve_sink(args.listen)
        return 0
    try:
        result = _run_client(args)
    except Exception as exc:  # noqa: BLE001
        result = {
            "ok": False,
            "error": str(exc),
            "bytes": 0,
            "duration_ms": 0,
            "ttfb_ms": None,
            "ttfb_samples_us": [],
            "latency_us": [],
            "samples": [],
        }
        result.update(_identity(args))
    Path(args.out).write_text(json.dumps(result) + "\n", encoding="utf-8")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
