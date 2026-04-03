#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import select
import socket
import socketserver
import struct
import threading
import time
from typing import Any

from bench_common import (
    analysis_flags,
    fmt_bytes,
    fmt_number,
    now_iso,
    summarize_boolean_results,
    summarize_samples,
    summarize_transfer,
    system_metadata,
    write_json,
)


DEFAULT_PORT = 47000
UDP_MAGIC = b"NBUD"
RPC_HEADER = struct.Struct("!I")
UDP_HEADER = struct.Struct("!4sIQ")
BUFFER_SIZE = 64 * 1024


def log_progress(message: str) -> None:
    print(message, flush=True)


def log_test_start(name: str, detail: str | None = None) -> None:
    suffix = f" ({detail})" if detail else ""
    log_progress(f"[client] starting {name}{suffix}")


def log_test_done(name: str, detail: str | None = None) -> None:
    suffix = f": {detail}" if detail else ""
    log_progress(f"[client] finished {name}{suffix}")


def transfer_progress(prefix: str, elapsed_s: float, total_bytes: int) -> None:
    mbps = (total_bytes * 8) / max(elapsed_s, 0.001) / 1_000_000
    log_progress(
        f"{prefix} progress {elapsed_s:.1f}s | {fmt_bytes(total_bytes)} transferred | avg {fmt_number(mbps)} Mbps"
    )


def summarize_transfer_brief(result: dict[str, Any]) -> str:
    return (
        f"{fmt_number(result.get('mbps'))} Mbps over {fmt_number(result.get('seconds'))}s "
        f"({fmt_bytes(result.get('bytes'))})"
    )


def summarize_latency_brief(result: dict[str, Any], field: str = "latency_ms") -> str:
    data = result[field]
    return (
        f"p50 {fmt_number(data.get('p50'))} ms, "
        f"p95 {fmt_number(data.get('p95'))} ms, "
        f"success {fmt_number(result.get('reliability', {}).get('success_rate', 1.0) * 100 if result.get('reliability') and result.get('reliability', {}).get('success_rate') is not None else None)}%"
    )


def send_json_line(conn: socket.socket, payload: dict[str, Any]) -> None:
    conn.sendall((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))


def recv_json_line(fileobj, limit: int = 64 * 1024) -> dict[str, Any] | None:
    raw = fileobj.readline(limit)
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


def recv_exact(fileobj, size: int) -> bytes | None:
    data = bytearray()
    while len(data) < size:
        chunk = fileobj.read(size - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def monotonic_ms() -> float:
    return time.perf_counter_ns() / 1_000_000


def bucket_index(start_ns: int, now_ns: int) -> int:
    return max(0, int((now_ns - start_ns) / 1_000_000_000))


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class BenchTCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        conn = self.request
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        fileobj = conn.makefile("rb")
        request = recv_json_line(fileobj)
        if not request:
            return

        cmd = request.get("cmd")
        if cmd == "hello":
            send_json_line(
                conn,
                {
                    "ok": True,
                    "version": 1,
                    "timestamp": now_iso(),
                    "platform": platform.platform(),
                    "hostname": platform.node(),
                },
            )
            return

        if cmd == "rpc_echo":
            self.handle_rpc_echo(conn, fileobj)
            return

        if cmd == "tcp_send":
            self.handle_tcp_send(conn, fileobj, request)
            return

        if cmd == "tcp_recv":
            self.handle_tcp_recv(fileobj, request)
            return

        send_json_line(conn, {"ok": False, "error": f"unknown command: {cmd}"})

    def maybe_wait_for_start(self, fileobj, request: dict[str, Any]) -> None:
        if request.get("await_start"):
            recv_exact(fileobj, 1)

    def handle_rpc_echo(self, conn: socket.socket, fileobj) -> None:
        while True:
            header = recv_exact(fileobj, RPC_HEADER.size)
            if header is None:
                return
            (size,) = RPC_HEADER.unpack(header)
            payload = recv_exact(fileobj, size)
            if payload is None:
                return
            conn.sendall(header + payload)

    def handle_tcp_send(self, conn: socket.socket, fileobj, request: dict[str, Any]) -> None:
        self.maybe_wait_for_start(fileobj, request)
        duration_s = float(request.get("duration_s", 0))
        total_bytes = request.get("total_bytes")
        chunk_size = max(4096, min(int(request.get("chunk_size", BUFFER_SIZE)), BUFFER_SIZE))
        payload = b"x" * chunk_size
        sent = 0
        deadline = time.perf_counter() + duration_s if duration_s > 0 else None
        try:
            while True:
                if total_bytes is not None and sent >= int(total_bytes):
                    break
                if deadline is not None and time.perf_counter() >= deadline:
                    break
                remaining = (
                    min(chunk_size, int(total_bytes) - sent)
                    if total_bytes is not None
                    else chunk_size
                )
                conn.sendall(payload[:remaining])
                sent += remaining
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def handle_tcp_recv(self, fileobj, request: dict[str, Any]) -> None:
        self.maybe_wait_for_start(fileobj, request)
        while True:
            chunk = fileobj.read(BUFFER_SIZE)
            if not chunk:
                return


def udp_echo_loop(listen: str, port: int, stop_event: threading.Event) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen, port))
        sock.settimeout(0.5)
        while not stop_event.is_set():
            try:
                payload, addr = sock.recvfrom(64 * 1024)
            except socket.timeout:
                continue
            except OSError:
                return
            if payload.startswith(UDP_MAGIC):
                try:
                    sock.sendto(payload, addr)
                except OSError:
                    continue


def run_server(args: argparse.Namespace) -> int:
    stop_event = threading.Event()
    udp_thread = threading.Thread(
        target=udp_echo_loop,
        args=(args.listen, args.port, stop_event),
        daemon=True,
    )
    udp_thread.start()

    with ThreadedTCPServer((args.listen, args.port), BenchTCPHandler) as server:
        print(f"[server] listening on TCP/UDP {args.listen}:{args.port}")
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            print("\n[server] shutting down")
        finally:
            stop_event.set()
            server.shutdown()
    udp_thread.join(timeout=1.0)
    return 0


def hello(host: str, port: int, timeout: float) -> dict[str, Any]:
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        send_json_line(conn, {"cmd": "hello"})
        fileobj = conn.makefile("rb")
        response = recv_json_line(fileobj)
        if not response:
            raise RuntimeError("no hello response from server")
        return response


def tcp_connect_latency(host: str, port: int, attempts: int, timeout: float) -> dict[str, Any]:
    latencies = []
    successes = []
    for _ in range(attempts):
        started = time.perf_counter_ns()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
            latencies.append((time.perf_counter_ns() - started) / 1_000_000)
            successes.append(True)
        except OSError:
            successes.append(False)
    return {
        "latency_ms": summarize_samples(latencies),
        "reliability": summarize_boolean_results(successes),
    }


def tcp_rpc_latency(
    host: str,
    port: int,
    iterations: int,
    payload_size: int,
    timeout: float,
) -> dict[str, Any]:
    payload = os.urandom(payload_size)
    latencies = []
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.settimeout(timeout)
        send_json_line(conn, {"cmd": "rpc_echo"})
        fileobj = conn.makefile("rb")
        for _ in range(iterations):
            started = time.perf_counter_ns()
            conn.sendall(RPC_HEADER.pack(len(payload)) + payload)
            header = recv_exact(fileobj, RPC_HEADER.size)
            if header is None:
                raise RuntimeError("server closed rpc connection")
            (size,) = RPC_HEADER.unpack(header)
            echoed = recv_exact(fileobj, size)
            if echoed != payload:
                raise RuntimeError("rpc echo payload mismatch")
            latencies.append((time.perf_counter_ns() - started) / 1_000_000)
    return {
        "iterations": iterations,
        "payload_size": payload_size,
        "latency_ms": summarize_samples(latencies),
    }


def tcp_download_once(
    host: str,
    port: int,
    seconds: float,
    timeout: float,
    await_start: bool = False,
    start_event: threading.Event | None = None,
    progress_label: str | None = None,
) -> dict[str, Any]:
    total_bytes = 0
    per_second: dict[int, int] = {}
    last_logged_bucket = -1
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        send_json_line(
            conn,
            {
                "cmd": "tcp_send",
                "duration_s": seconds,
                "chunk_size": BUFFER_SIZE,
                "await_start": await_start,
            },
        )
        if await_start and start_event is not None:
            start_event.wait()
            conn.sendall(b"S")
        started = time.perf_counter_ns()
        while True:
            try:
                chunk = conn.recv(BUFFER_SIZE)
            except socket.timeout:
                break
            if not chunk:
                break
            total_bytes += len(chunk)
            idx = bucket_index(started, time.perf_counter_ns())
            per_second[idx] = per_second.get(idx, 0) + len(chunk)
            if progress_label and idx > last_logged_bucket:
                elapsed_s = max((time.perf_counter_ns() - started) / 1_000_000_000, 0.001)
                transfer_progress(progress_label, elapsed_s, total_bytes)
                last_logged_bucket = idx
        ended = time.perf_counter_ns()
    series = [per_second.get(idx, 0) for idx in range(max(per_second.keys(), default=-1) + 1)]
    return summarize_transfer(total_bytes, (ended - started) / 1_000_000_000, series)


def tcp_upload_once(
    host: str,
    port: int,
    seconds: float,
    timeout: float,
    await_start: bool = False,
    start_event: threading.Event | None = None,
    progress_label: str | None = None,
) -> dict[str, Any]:
    total_bytes = 0
    per_second: dict[int, int] = {}
    payload = b"u" * BUFFER_SIZE
    last_logged_bucket = -1
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        send_json_line(
            conn,
            {
                "cmd": "tcp_recv",
                "await_start": await_start,
            },
        )
        if await_start and start_event is not None:
            start_event.wait()
            conn.sendall(b"S")
        started = time.perf_counter_ns()
        deadline = time.perf_counter() + seconds
        while time.perf_counter() < deadline:
            sent = conn.send(payload)
            total_bytes += sent
            idx = bucket_index(started, time.perf_counter_ns())
            per_second[idx] = per_second.get(idx, 0) + sent
            if progress_label and idx > last_logged_bucket:
                elapsed_s = max((time.perf_counter_ns() - started) / 1_000_000_000, 0.001)
                transfer_progress(progress_label, elapsed_s, total_bytes)
                last_logged_bucket = idx
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        ended = time.perf_counter_ns()
    series = [per_second.get(idx, 0) for idx in range(max(per_second.keys(), default=-1) + 1)]
    return summarize_transfer(total_bytes, (ended - started) / 1_000_000_000, series)


def parallel_transfers(
    host: str,
    port: int,
    seconds: float,
    timeout: float,
    streams: int,
    direction: str,
) -> dict[str, Any]:
    log_progress(f"[client] starting parallel {direction} test with {streams} streams for {seconds:.1f}s")
    start_event = threading.Event()
    results: list[dict[str, Any] | None] = [None] * streams
    errors: list[str] = []
    threads = []

    def worker(index: int) -> None:
        try:
            if direction == "download":
                results[index] = tcp_download_once(
                    host,
                    port,
                    seconds,
                    timeout,
                    await_start=True,
                    start_event=start_event,
                )
            else:
                results[index] = tcp_upload_once(
                    host,
                    port,
                    seconds,
                    timeout,
                    await_start=True,
                    start_event=start_event,
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"stream {index}: {exc}")

    for idx in range(streams):
        thread = threading.Thread(target=worker, args=(idx,), daemon=True)
        thread.start()
        threads.append(thread)

    time.sleep(0.25)
    wall_start = time.perf_counter_ns()
    start_event.set()
    for thread in threads:
        thread.join()
    wall_end = time.perf_counter_ns()

    total_bytes = sum(item["bytes"] for item in results if item)
    wall_seconds = (wall_end - wall_start) / 1_000_000_000
    outcome = {
        "streams": streams,
        "direction": direction,
        "aggregate": summarize_transfer(total_bytes, wall_seconds),
        "per_stream": results,
        "errors": errors,
    }
    log_progress(
        f"[client] finished parallel {direction} test: {summarize_transfer_brief(outcome['aggregate'])}"
    )
    return outcome


def start_background_download(
    host: str,
    port: int,
    timeout: float,
    stop_event: threading.Event,
    counters: list[int],
    index: int,
) -> threading.Thread:
    def runner() -> None:
        received = 0
        try:
            with socket.create_connection((host, port), timeout=timeout) as conn:
                conn.settimeout(1.0)
                send_json_line(
                    conn,
                    {
                        "cmd": "tcp_send",
                        "duration_s": 3600,
                        "chunk_size": BUFFER_SIZE,
                    },
                )
                while not stop_event.is_set():
                    try:
                        data = conn.recv(BUFFER_SIZE)
                    except socket.timeout:
                        continue
                    if not data:
                        break
                    received += len(data)
        except OSError:
            pass
        counters[index] = received

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread


def start_background_upload(
    host: str,
    port: int,
    timeout: float,
    stop_event: threading.Event,
    counters: list[int],
    index: int,
) -> threading.Thread:
    def runner() -> None:
        sent_total = 0
        payload = b"b" * BUFFER_SIZE
        try:
            with socket.create_connection((host, port), timeout=timeout) as conn:
                conn.settimeout(1.0)
                send_json_line(conn, {"cmd": "tcp_recv"})
                while not stop_event.is_set():
                    try:
                        sent = conn.send(payload)
                    except (socket.timeout, BlockingIOError):
                        continue
                    sent_total += sent
                try:
                    conn.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        except OSError:
            pass
        counters[index] = sent_total

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread


def udp_echo_test(
    host: str,
    port: int,
    packet_size: int,
    count: int,
    pps: float,
    timeout: float,
) -> dict[str, Any]:
    log_progress(
        f"[client] starting UDP echo test: {count} packets, {packet_size} bytes, {fmt_number(pps)} pps"
    )
    packet_size = max(packet_size, UDP_HEADER.size)
    send_times: dict[int, int] = {}
    received = set()
    duplicates = 0
    reordered = 0
    highest_seen = -1
    latencies = []
    socket_timeout = min(max(1.0 / max(pps, 1), 0.05), 1.0)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(socket_timeout)
        target = (host, port)
        started = time.perf_counter()
        progress_step = max(1, count // 5)
        for seq in range(count):
            deadline = started + (seq / max(pps, 0.1))
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                time.sleep(min(remaining, 0.005))

            sent_ns = time.perf_counter_ns()
            send_times[seq] = sent_ns
            payload = UDP_HEADER.pack(UDP_MAGIC, seq, sent_ns) + b"z" * (
                packet_size - UDP_HEADER.size
            )
            sock.sendto(payload, target)

            end_wait = time.perf_counter() + socket_timeout
            while time.perf_counter() < end_wait:
                wait = max(0.0, end_wait - time.perf_counter())
                readable, _, _ = select.select([sock], [], [], wait)
                if not readable:
                    break
                data, _ = sock.recvfrom(64 * 1024)
                if len(data) < UDP_HEADER.size:
                    continue
                magic, echoed_seq, echoed_sent_ns = UDP_HEADER.unpack(data[: UDP_HEADER.size])
                if magic != UDP_MAGIC:
                    continue
                if echoed_seq in received:
                    duplicates += 1
                    continue
                if echoed_seq < highest_seen:
                    reordered += 1
                highest_seen = max(highest_seen, echoed_seq)
                received.add(echoed_seq)
                latencies.append((time.perf_counter_ns() - echoed_sent_ns) / 1_000_000)
            if (seq + 1) % progress_step == 0 or seq + 1 == count:
                log_progress(
                    f"[client] UDP progress {seq + 1}/{count} sent | received {len(received)} | loss so far {seq + 1 - len(received)}"
                )

        grace_deadline = time.perf_counter() + 1.0
        while time.perf_counter() < grace_deadline and len(received) < count:
            readable, _, _ = select.select([sock], [], [], 0.1)
            if not readable:
                continue
            data, _ = sock.recvfrom(64 * 1024)
            if len(data) < UDP_HEADER.size:
                continue
            magic, echoed_seq, echoed_sent_ns = UDP_HEADER.unpack(data[: UDP_HEADER.size])
            if magic != UDP_MAGIC:
                continue
            if echoed_seq in received:
                duplicates += 1
                continue
            if echoed_seq < highest_seen:
                reordered += 1
            highest_seen = max(highest_seen, echoed_seq)
            received.add(echoed_seq)
            latencies.append((time.perf_counter_ns() - echoed_sent_ns) / 1_000_000)

    sorted_latencies = latencies
    jitter_samples = [
        abs(sorted_latencies[idx] - sorted_latencies[idx - 1])
        for idx in range(1, len(sorted_latencies))
    ]
    loss = count - len(received)
    outcome = {
        "packet_size": packet_size,
        "count": count,
        "pps": pps,
        "received": len(received),
        "loss": loss,
        "loss_rate": loss / count if count else None,
        "duplicates": duplicates,
        "reordered": reordered,
        "rtt_ms": summarize_samples(latencies),
        "jitter_ms": summarize_samples(jitter_samples),
    }
    log_progress(
        f"[client] finished UDP echo test: loss {fmt_number(outcome['loss_rate'] * 100 if outcome['loss_rate'] is not None else None)}%, "
        f"rtt p95 {fmt_number(outcome['rtt_ms']['p95'])} ms"
    )
    return outcome


def udp_size_sweep(
    host: str,
    port: int,
    sizes: list[int],
    count: int,
    pps: float,
    timeout: float,
) -> list[dict[str, Any]]:
    results = []
    for size in sizes:
        results.append(udp_echo_test(host, port, size, count, pps, timeout))
    return results


def soak_test(
    host: str,
    port: int,
    duration_s: int,
    interval_s: float,
    payload_size: int,
    timeout: float,
) -> dict[str, Any]:
    log_progress(f"[client] starting soak test for {duration_s}s with {interval_s:.1f}s probes")
    latencies = []
    successes = []
    samples = []
    deadline = time.perf_counter() + duration_s
    started = time.perf_counter()
    next_progress = started + 5.0
    while time.perf_counter() < deadline:
        loop_start = time.perf_counter()
        try:
            result = tcp_rpc_latency(host, port, iterations=1, payload_size=payload_size, timeout=timeout)
            latency = result["latency_ms"]["mean"]
            latencies.append(latency)
            successes.append(True)
            samples.append({"ok": True, "latency_ms": latency})
        except Exception as exc:  # noqa: BLE001
            successes.append(False)
            samples.append({"ok": False, "error": str(exc)})
        now = time.perf_counter()
        if now >= next_progress:
            log_progress(
                f"[client] soak progress {int(now - started)}s/{duration_s}s | probes {len(samples)} | failures {sum(1 for item in successes if not item)}"
            )
            next_progress = now + 5.0
        remaining = interval_s - (time.perf_counter() - loop_start)
        if remaining > 0:
            time.sleep(remaining)
    outcome = {
        "duration_s": duration_s,
        "interval_s": interval_s,
        "payload_size": payload_size,
        "latency_ms": summarize_samples(latencies),
        "reliability": summarize_boolean_results(successes),
        "samples": samples,
    }
    log_progress(
        f"[client] finished soak test: failures {outcome['reliability']['failures']}, "
        f"latency p95 {fmt_number(outcome['latency_ms']['p95'])} ms"
    )
    return outcome


def mixed_load_test(
    host: str,
    port: int,
    timeout: float,
    streams: int,
    duration_s: int,
    rpc_iterations: int,
    rpc_payload_size: int,
    udp_packet_size: int,
    udp_count: int,
    udp_pps: float,
) -> dict[str, Any]:
    log_progress(
        f"[client] starting mixed-load test for {duration_s}s with {streams} background download and {streams} background upload streams"
    )
    stop_event = threading.Event()
    download_counters = [0] * streams
    upload_counters = [0] * streams
    threads = []
    for idx in range(streams):
        threads.append(start_background_download(host, port, timeout, stop_event, download_counters, idx))
        threads.append(start_background_upload(host, port, timeout, stop_event, upload_counters, idx))
    time.sleep(1.0)
    start = time.perf_counter()
    rpc_result = tcp_rpc_latency(
        host,
        port,
        iterations=rpc_iterations,
        payload_size=rpc_payload_size,
        timeout=timeout,
    )
    udp_result = udp_echo_test(
        host,
        port,
        packet_size=udp_packet_size,
        count=udp_count,
        pps=udp_pps,
        timeout=timeout,
    )
    remaining = duration_s - (time.perf_counter() - start)
    if remaining > 0:
        time.sleep(remaining)
    stop_event.set()
    for thread in threads:
        thread.join(timeout=2.0)
    outcome = {
        "duration_s": duration_s,
        "background_streams_each_direction": streams,
        "background_download_mbps": sum(download_counters) * 8 / max(duration_s, 1) / 1_000_000,
        "background_upload_mbps": sum(upload_counters) * 8 / max(duration_s, 1) / 1_000_000,
        "rpc_latency_ms": rpc_result["latency_ms"],
        "udp": udp_result,
    }
    log_progress(
        f"[client] finished mixed-load test: bg down {fmt_number(outcome['background_download_mbps'])} Mbps, "
        f"bg up {fmt_number(outcome['background_upload_mbps'])} Mbps, "
        f"RPC p95 {fmt_number(outcome['rpc_latency_ms']['p95'])} ms"
    )
    return outcome


def profile_defaults(name: str) -> dict[str, Any]:
    profiles = {
        "quick": {
            "connect_attempts": 15,
            "rpc_iterations": 100,
            "rpc_payload_size": 64,
            "transfer_seconds": 5,
            "parallel_streams": 4,
            "udp_idle_count": 120,
            "udp_idle_pps": 20.0,
            "udp_idle_size": 64,
            "udp_stress_count": 300,
            "udp_stress_pps": 150.0,
            "udp_stress_size": 1200,
            "udp_sweep_sizes": [64, 256, 512, 1200, 1400],
            "udp_sweep_count": 40,
            "udp_sweep_pps": 40.0,
            "mixed_seconds": 8,
            "soak_seconds": 20,
        },
        "standard": {
            "connect_attempts": 30,
            "rpc_iterations": 200,
            "rpc_payload_size": 64,
            "transfer_seconds": 8,
            "parallel_streams": 4,
            "udp_idle_count": 200,
            "udp_idle_pps": 20.0,
            "udp_idle_size": 64,
            "udp_stress_count": 800,
            "udp_stress_pps": 250.0,
            "udp_stress_size": 1200,
            "udp_sweep_sizes": [64, 256, 512, 1024, 1200, 1400],
            "udp_sweep_count": 60,
            "udp_sweep_pps": 50.0,
            "mixed_seconds": 10,
            "soak_seconds": 30,
        },
        "extended": {
            "connect_attempts": 50,
            "rpc_iterations": 400,
            "rpc_payload_size": 64,
            "transfer_seconds": 15,
            "parallel_streams": 6,
            "udp_idle_count": 400,
            "udp_idle_pps": 20.0,
            "udp_idle_size": 64,
            "udp_stress_count": 2000,
            "udp_stress_pps": 400.0,
            "udp_stress_size": 1200,
            "udp_sweep_sizes": [64, 256, 512, 1024, 1200, 1400, 1472],
            "udp_sweep_count": 100,
            "udp_sweep_pps": 80.0,
            "mixed_seconds": 15,
            "soak_seconds": 60,
        },
    }
    return profiles[name].copy()


def infer_flags(results: dict[str, Any]) -> list[str]:
    flags = []

    connect = results["tests"]["connect_latency"]["latency_ms"]
    if connect["count"] and connect["p95"] and connect["p50"] and connect["p95"] > max(10, connect["p50"] * 3):
        flags.append("TCP connect latency is spiky; expect inconsistent session setup times.")

    rpc_idle = results["tests"]["rpc_idle"]["latency_ms"]
    if rpc_idle["count"] and rpc_idle["p95"] and rpc_idle["p50"] and rpc_idle["p95"] > max(5, rpc_idle["p50"] * 4):
        flags.append("Idle request/response latency has a heavy tail; interactive traffic may feel uneven.")

    udp_idle_loss = results["tests"]["udp_idle"]["loss_rate"]
    if udp_idle_loss is not None and udp_idle_loss > 0.01:
        flags.append("UDP shows packet loss even while idle; real-time traffic may be fragile.")

    udp_stress_loss = results["tests"]["udp_stress"]["loss_rate"]
    if udp_stress_loss is not None and udp_stress_loss > 0.05:
        flags.append("UDP loss rises sharply under stress; voice/video/game traffic may degrade under bursty load.")

    dl_single = results["tests"]["tcp_download_single"]["mbps"]
    dl_parallel = results["tests"]["tcp_download_parallel"]["aggregate"]["mbps"]
    if dl_single and dl_parallel and dl_parallel < dl_single * 1.15:
        flags.append("Parallel download streams add little over a single stream; the path may already be single-flow limited or rate-shaped.")

    ul_single = results["tests"]["tcp_upload_single"]["mbps"]
    ul_parallel = results["tests"]["tcp_upload_parallel"]["aggregate"]["mbps"]
    if ul_single and ul_parallel and ul_parallel < ul_single * 1.15:
        flags.append("Parallel upload streams add little over a single stream; upstream shaping or single-flow saturation is likely.")

    mixed_rpc = results["tests"]["mixed_load"]["rpc_latency_ms"]
    if rpc_idle["p95"] and mixed_rpc["p95"]:
        if mixed_rpc["p95"] > rpc_idle["p95"] + 50 and mixed_rpc["p95"] > rpc_idle["p95"] * 2:
            flags.append("Latency inflates heavily under load; likely bufferbloat or weak queue management.")

    soak = results["tests"]["soak"]["reliability"]
    if soak["failures"] > 0:
        flags.append("The soak test observed stalls/failures; the path may have intermittent drops or resets.")

    dl_cv = results["tests"]["tcp_download_single"]["stability_cv"]
    if dl_cv is not None and dl_cv > 0.25:
        flags.append("Single-stream download throughput fluctuates strongly over time.")

    ul_cv = results["tests"]["tcp_upload_single"]["stability_cv"]
    if ul_cv is not None and ul_cv > 0.25:
        flags.append("Single-stream upload throughput fluctuates strongly over time.")

    return analysis_flags(flags)


def print_client_summary(results: dict[str, Any]) -> None:
    tests = results["tests"]
    print("")
    print("=== Pair benchmark summary ===")
    print(
        f"Connect p50/p95: {fmt_number(tests['connect_latency']['latency_ms']['p50'])} / "
        f"{fmt_number(tests['connect_latency']['latency_ms']['p95'])} ms"
    )
    print(
        f"RPC idle p50/p95: {fmt_number(tests['rpc_idle']['latency_ms']['p50'])} / "
        f"{fmt_number(tests['rpc_idle']['latency_ms']['p95'])} ms"
    )
    print(
        f"TCP down single/parallel: {fmt_number(tests['tcp_download_single']['mbps'])} / "
        f"{fmt_number(tests['tcp_download_parallel']['aggregate']['mbps'])} Mbps"
    )
    print(
        f"TCP up single/parallel: {fmt_number(tests['tcp_upload_single']['mbps'])} / "
        f"{fmt_number(tests['tcp_upload_parallel']['aggregate']['mbps'])} Mbps"
    )
    idle_loss = tests["udp_idle"]["loss_rate"]
    stress_loss = tests["udp_stress"]["loss_rate"]
    print(
        f"UDP idle loss: {fmt_number(idle_loss * 100 if idle_loss is not None else None)}% | "
        f"UDP stress loss: {fmt_number(stress_loss * 100 if stress_loss is not None else None)}%"
    )
    print(
        f"Mixed-load RPC p95: {fmt_number(tests['mixed_load']['rpc_latency_ms']['p95'])} ms | "
        f"Soak failures: {tests['soak']['reliability']['failures']}"
    )
    if results["analysis_flags"]:
        print("Flags:")
        for item in results["analysis_flags"]:
            print(f"  - {item}")


def run_client(args: argparse.Namespace) -> int:
    profile = profile_defaults(args.profile)
    if args.transfer_seconds is not None:
        profile["transfer_seconds"] = args.transfer_seconds
    if args.parallel_streams is not None:
        profile["parallel_streams"] = args.parallel_streams
    if args.soak_seconds is not None:
        profile["soak_seconds"] = args.soak_seconds

    server_info = hello(args.host, args.port, args.timeout)
    print(
        f"[client] connected to {args.host}:{args.port} "
        f"({server_info.get('hostname')} / {server_info.get('platform')})"
    )

    results = {
        "meta": {
            **system_metadata(),
            "mode": "pair_client",
            "profile": args.profile,
            "server": {
                "host": args.host,
                "port": args.port,
                "hello": server_info,
            },
        },
        "config": profile,
        "tests": {},
    }

    log_test_start("connect latency", f"{profile['connect_attempts']} attempts")
    results["tests"]["connect_latency"] = tcp_connect_latency(
        args.host, args.port, profile["connect_attempts"], args.timeout
    )
    log_test_done("connect latency", summarize_latency_brief(results["tests"]["connect_latency"]))

    log_test_start("idle RPC latency", f"{profile['rpc_iterations']} iterations")
    results["tests"]["rpc_idle"] = tcp_rpc_latency(
        args.host,
        args.port,
        profile["rpc_iterations"],
        profile["rpc_payload_size"],
        args.timeout,
    )
    log_test_done(
        "idle RPC latency",
        f"p50 {fmt_number(results['tests']['rpc_idle']['latency_ms']['p50'])} ms, "
        f"p95 {fmt_number(results['tests']['rpc_idle']['latency_ms']['p95'])} ms",
    )

    log_test_start("single-stream download", f"{profile['transfer_seconds']}s")
    results["tests"]["tcp_download_single"] = tcp_download_once(
        args.host,
        args.port,
        profile["transfer_seconds"],
        args.timeout,
        progress_label="[client] download",
    )
    log_test_done("single-stream download", summarize_transfer_brief(results["tests"]["tcp_download_single"]))

    log_test_start("single-stream upload", f"{profile['transfer_seconds']}s")
    results["tests"]["tcp_upload_single"] = tcp_upload_once(
        args.host,
        args.port,
        profile["transfer_seconds"],
        args.timeout,
        progress_label="[client] upload",
    )
    log_test_done("single-stream upload", summarize_transfer_brief(results["tests"]["tcp_upload_single"]))

    log_test_start("parallel download", f"{profile['parallel_streams']} streams")
    results["tests"]["tcp_download_parallel"] = parallel_transfers(
        args.host,
        args.port,
        profile["transfer_seconds"],
        args.timeout,
        profile["parallel_streams"],
        direction="download",
    )
    log_test_done(
        "parallel download",
        summarize_transfer_brief(results["tests"]["tcp_download_parallel"]["aggregate"]),
    )

    log_test_start("parallel upload", f"{profile['parallel_streams']} streams")
    results["tests"]["tcp_upload_parallel"] = parallel_transfers(
        args.host,
        args.port,
        profile["transfer_seconds"],
        args.timeout,
        profile["parallel_streams"],
        direction="upload",
    )
    log_test_done(
        "parallel upload",
        summarize_transfer_brief(results["tests"]["tcp_upload_parallel"]["aggregate"]),
    )

    log_test_start("UDP idle test")
    results["tests"]["udp_idle"] = udp_echo_test(
        args.host,
        args.port,
        profile["udp_idle_size"],
        profile["udp_idle_count"],
        profile["udp_idle_pps"],
        args.timeout,
    )
    log_test_done(
        "UDP idle test",
        f"loss {fmt_number(results['tests']['udp_idle']['loss_rate'] * 100 if results['tests']['udp_idle']['loss_rate'] is not None else None)}%, "
        f"rtt p95 {fmt_number(results['tests']['udp_idle']['rtt_ms']['p95'])} ms",
    )

    log_test_start("UDP stress test")
    results["tests"]["udp_stress"] = udp_echo_test(
        args.host,
        args.port,
        profile["udp_stress_size"],
        profile["udp_stress_count"],
        profile["udp_stress_pps"],
        args.timeout,
    )
    log_test_done(
        "UDP stress test",
        f"loss {fmt_number(results['tests']['udp_stress']['loss_rate'] * 100 if results['tests']['udp_stress']['loss_rate'] is not None else None)}%, "
        f"rtt p95 {fmt_number(results['tests']['udp_stress']['rtt_ms']['p95'])} ms",
    )

    log_test_start("UDP size sweep", f"{len(profile['udp_sweep_sizes'])} packet sizes")
    results["tests"]["udp_size_sweep"] = udp_size_sweep(
        args.host,
        args.port,
        profile["udp_sweep_sizes"],
        profile["udp_sweep_count"],
        profile["udp_sweep_pps"],
        args.timeout,
    )
    log_test_done("UDP size sweep", "completed all packet sizes")

    log_test_start("mixed-load test", f"{profile['mixed_seconds']}s")
    results["tests"]["mixed_load"] = mixed_load_test(
        args.host,
        args.port,
        args.timeout,
        streams=profile["parallel_streams"],
        duration_s=profile["mixed_seconds"],
        rpc_iterations=max(50, profile["rpc_iterations"] // 2),
        rpc_payload_size=profile["rpc_payload_size"],
        udp_packet_size=profile["udp_idle_size"],
        udp_count=max(80, profile["udp_idle_count"] // 2),
        udp_pps=profile["udp_idle_pps"],
    )
    log_test_done(
        "mixed-load test",
        f"RPC p95 {fmt_number(results['tests']['mixed_load']['rpc_latency_ms']['p95'])} ms, "
        f"bg down {fmt_number(results['tests']['mixed_load']['background_download_mbps'])} Mbps",
    )

    log_test_start("soak test", f"{profile['soak_seconds']}s")
    results["tests"]["soak"] = soak_test(
        args.host,
        args.port,
        duration_s=profile["soak_seconds"],
        interval_s=1.0,
        payload_size=profile["rpc_payload_size"],
        timeout=args.timeout,
    )
    log_test_done(
        "soak test",
        f"failures {results['tests']['soak']['reliability']['failures']}, "
        f"p95 {fmt_number(results['tests']['soak']['latency_ms']['p95'])} ms",
    )
    results["analysis_flags"] = infer_flags(results)

    print_client_summary(results)
    if args.output:
        write_json(args.output, results)
        print(f"[client] wrote JSON results to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Client/server benchmark for measuring the real network path between a client and a server."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server = subparsers.add_parser("server", help="Run the benchmark server on the VPS")
    server.add_argument("--listen", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    server.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port to bind (default: {DEFAULT_PORT})")

    client = subparsers.add_parser("client", help="Run the benchmark client against a remote server")
    client.add_argument("--host", required=True, help="Server hostname or IP")
    client.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Server port (default: {DEFAULT_PORT})")
    client.add_argument(
        "--profile",
        choices=["quick", "standard", "extended"],
        default="standard",
        help="Benchmark intensity profile",
    )
    client.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds")
    client.add_argument("--transfer-seconds", type=float, help="Override transfer duration")
    client.add_argument("--parallel-streams", type=int, help="Override parallel stream count")
    client.add_argument("--soak-seconds", type=int, help="Override soak test duration")
    client.add_argument("--output", help="Write full JSON results to this path")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.mode == "server":
        return run_server(args)
    return run_client(args)


if __name__ == "__main__":
    raise SystemExit(main())
