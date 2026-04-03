#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import copy
import http.client
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

from bench_common import (
    analysis_flags,
    fmt_bytes,
    fmt_number,
    summarize_boolean_results,
    summarize_samples,
    summarize_transfer,
    system_metadata,
    write_json,
)


DEFAULT_PROFILE: dict[str, Any] = {
    "dns_hosts": ["example.com", "cloudflare.com", "speed.cloudflare.com"],
    "latency_targets": [
        {
            "name": "cloudflare_speed",
            "host": "speed.cloudflare.com",
            "port": 443,
            "tls_sni": "speed.cloudflare.com",
        },
        {
            "name": "cloudflare_www",
            "host": "www.cloudflare.com",
            "port": 443,
            "tls_sni": "www.cloudflare.com",
        },
        {"name": "dns_google", "host": "dns.google", "port": 443, "tls_sni": "dns.google"},
    ],
    "http_small_objects": [
        {"name": "example_home", "url": "https://example.com/"},
        {"name": "cloudflare_home", "url": "https://www.cloudflare.com/"},
    ],
    "http_bulk_downloads": [
        {
            "name": "cloudflare_download_25mb",
            "url": "https://speed.cloudflare.com/__down?bytes=25000000",
            "read_bytes": 25_000_000,
        },
        {
            "name": "cloudflare_download_100mb",
            "url": "https://speed.cloudflare.com/__down?bytes=100000000",
            "read_bytes": 100_000_000,
        },
    ],
    "http_uploads": [
        {
            "name": "cloudflare_upload_25mb",
            "url": "https://speed.cloudflare.com/__up",
            "method": "POST",
            "bytes": 25_000_000,
            "headers": {"Content-Type": "application/octet-stream"},
        }
    ],
    "reliability_targets": [
        {
            "name": "speed_cloudflare_tls",
            "kind": "tls",
            "host": "speed.cloudflare.com",
            "port": 443,
            "tls_sni": "speed.cloudflare.com",
        },
        {"name": "example_http", "kind": "http", "url": "https://example.com/"},
        {"name": "cloudflare_tcp", "kind": "tcp", "host": "1.1.1.1", "port": 443},
    ],
}


PROFILE_PRESETS = {
    "quick": {
        "dns_repeats": 5,
        "latency_repeats": 8,
        "http_small_repeats": 5,
        "http_burst_requests": 12,
        "http_burst_concurrency": 4,
        "soak_seconds": 20,
        "load_seconds": 8,
    },
    "standard": {
        "dns_repeats": 10,
        "latency_repeats": 15,
        "http_small_repeats": 8,
        "http_burst_requests": 24,
        "http_burst_concurrency": 6,
        "soak_seconds": 40,
        "load_seconds": 12,
    },
    "extended": {
        "dns_repeats": 20,
        "latency_repeats": 30,
        "http_small_repeats": 12,
        "http_burst_requests": 40,
        "http_burst_concurrency": 8,
        "soak_seconds": 90,
        "load_seconds": 20,
    },
}


def log_progress(message: str) -> None:
    print(message, flush=True)


def log_test_start(name: str, detail: str | None = None) -> None:
    suffix = f" ({detail})" if detail else ""
    log_progress(f"[self] starting {name}{suffix}")


def log_test_done(name: str, detail: str | None = None) -> None:
    suffix = f": {detail}" if detail else ""
    log_progress(f"[self] finished {name}{suffix}")


def transfer_progress(prefix: str, elapsed_s: float, total_bytes: int) -> None:
    mbps = (total_bytes * 8) / max(elapsed_s, 0.001) / 1_000_000
    log_progress(
        f"{prefix} progress {elapsed_s:.1f}s | {fmt_bytes(total_bytes)} transferred | avg {fmt_number(mbps)} Mbps"
    )


def load_profile(path: str | None) -> dict[str, Any]:
    profile = copy.deepcopy(DEFAULT_PROFILE)
    if not path:
        return profile
    with open(path, "r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    for key, value in loaded.items():
        profile[key] = value
    return profile


def run_command(command: list[str], timeout: float = 5.0) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "command": command,
        }
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "command": command}


def read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def parse_resolv_conf() -> dict[str, Any]:
    nameservers = []
    search = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("nameserver "):
                    nameservers.append(line.split(None, 1)[1])
                elif line.startswith("search "):
                    search.extend(line.split()[1:])
    except OSError:
        pass
    return {"nameservers": nameservers, "search": search}


def system_snapshot() -> dict[str, Any]:
    snapshot = {
        **system_metadata(),
        "resolv_conf": parse_resolv_conf(),
        "tcp_congestion_control": read_text("/proc/sys/net/ipv4/tcp_congestion_control"),
        "tcp_available_congestion_control": read_text("/proc/sys/net/ipv4/tcp_available_congestion_control"),
        "tcp_mtu_probing": read_text("/proc/sys/net/ipv4/tcp_mtu_probing"),
        "default_qdisc": read_text("/proc/sys/net/core/default_qdisc"),
        "optional_tools": {
            tool: shutil.which(tool)
            for tool in ["ping", "ip", "ss", "tracepath", "curl"]
        },
    }
    if shutil.which("ip"):
        snapshot["ip_route_default"] = run_command(["ip", "route", "show", "default"])
        snapshot["ip_brief_link"] = run_command(["ip", "-brief", "link"])
        snapshot["ip_brief_addr"] = run_command(["ip", "-brief", "addr"])
    if shutil.which("ss"):
        snapshot["ss_summary"] = run_command(["ss", "-s"])
    return snapshot


def timed_getaddrinfo(host: str, timeout: float) -> tuple[list[Any] | None, float | None, str | None]:
    started = time.perf_counter_ns()
    state: dict[str, Any] = {}
    done = threading.Event()

    def runner() -> None:
        try:
            state["result"] = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except Exception as exc:  # noqa: BLE001
            state["error"] = str(exc)
        finally:
            done.set()

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    if not done.wait(timeout):
        return None, None, f"timeout after {timeout}s"
    if "error" in state:
        return None, None, state["error"]
    return state.get("result"), (time.perf_counter_ns() - started) / 1_000_000, None


def dns_resolution_test(hosts: list[str], repeats: int, timeout: float) -> list[dict[str, Any]]:
    results = []
    for host in hosts:
        latencies = []
        successes = []
        unique_answers = set()
        errors = []
        for _ in range(repeats):
            answers, latency_ms, error = timed_getaddrinfo(host, timeout)
            if error:
                successes.append(False)
                errors.append(error)
                continue
            successes.append(True)
            latencies.append(latency_ms)
            for entry in answers or []:
                sockaddr = entry[4]
                if sockaddr:
                    unique_answers.add(sockaddr[0])
        results.append(
            {
                "host": host,
                "latency_ms": summarize_samples(latencies),
                "reliability": summarize_boolean_results(successes),
                "answers": sorted(unique_answers),
                "errors": errors[:5],
            }
        )
    return results


def tcp_connect_once(host: str, port: int, timeout: float) -> tuple[bool, float | None, str | None]:
    started = time.perf_counter_ns()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.perf_counter_ns() - started) / 1_000_000
            return True, latency, None
    except OSError as exc:
        return False, None, str(exc)


def tcp_connect_test(targets: list[dict[str, Any]], repeats: int, timeout: float) -> list[dict[str, Any]]:
    results = []
    for target in targets:
        latencies = []
        successes = []
        errors = []
        for _ in range(repeats):
            ok, latency, error = tcp_connect_once(target["host"], int(target["port"]), timeout)
            successes.append(ok)
            if ok and latency is not None:
                latencies.append(latency)
            elif error:
                errors.append(error)
        results.append(
            {
                "target": target,
                "latency_ms": summarize_samples(latencies),
                "reliability": summarize_boolean_results(successes),
                "errors": errors[:5],
            }
        )
    return results


def tls_handshake_once(
    host: str,
    port: int,
    timeout: float,
    server_name: str | None = None,
) -> tuple[bool, float | None, str | None]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    started = time.perf_counter_ns()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=server_name or host):
                latency = (time.perf_counter_ns() - started) / 1_000_000
                return True, latency, None
    except Exception as exc:  # noqa: BLE001
        return False, None, str(exc)


def tls_handshake_test(targets: list[dict[str, Any]], repeats: int, timeout: float) -> list[dict[str, Any]]:
    results = []
    for target in targets:
        latencies = []
        successes = []
        errors = []
        for _ in range(repeats):
            ok, latency, error = tls_handshake_once(
                target["host"],
                int(target["port"]),
                timeout,
                server_name=target.get("tls_sni"),
            )
            successes.append(ok)
            if ok and latency is not None:
                latencies.append(latency)
            elif error:
                errors.append(error)
        results.append(
            {
                "target": target,
                "latency_ms": summarize_samples(latencies),
                "reliability": summarize_boolean_results(successes),
                "errors": errors[:5],
            }
        )
    return results


def fetch_url_once(url: str, timeout: float, max_bytes: int | None = None) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "networkbench/1.0", "Cache-Control": "no-cache"},
    )
    started = time.perf_counter_ns()
    bytes_read = 0
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", None)
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                if max_bytes is not None and bytes_read + len(chunk) > max_bytes:
                    chunk = chunk[: max_bytes - bytes_read]
                bytes_read += len(chunk)
                if max_bytes is not None and bytes_read >= max_bytes:
                    break
        return {
            "ok": True,
            "status": status,
            "bytes": bytes_read,
            "seconds": (time.perf_counter_ns() - started) / 1_000_000_000,
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "bytes": bytes_read}


def small_http_tests(
    targets: list[dict[str, Any]],
    repeats: int,
    timeout: float,
) -> list[dict[str, Any]]:
    results = []
    for target in targets:
        latencies = []
        successes = []
        sizes = []
        statuses = []
        errors = []
        for _ in range(repeats):
            outcome = fetch_url_once(target["url"], timeout, max_bytes=512 * 1024)
            successes.append(outcome["ok"])
            if outcome["ok"]:
                latencies.append(outcome["seconds"] * 1_000)
                sizes.append(outcome["bytes"])
                statuses.append(outcome.get("status"))
            else:
                errors.append(outcome["error"])
        results.append(
            {
                "target": target,
                "latency_ms": summarize_samples(latencies),
                "reliability": summarize_boolean_results(successes),
                "bytes_summary": summarize_samples(sizes, unit="bytes"),
                "statuses": sorted(set(statuses)),
                "errors": errors[:5],
            }
        )
    return results


def http_burst_test(
    target: dict[str, Any],
    requests_count: int,
    concurrency: int,
    timeout: float,
) -> dict[str, Any]:
    log_progress(
        f"[self] burst test {target['name']}: {requests_count} requests at concurrency {concurrency}"
    )
    latencies = []
    successes = []
    statuses = []
    errors = []
    started = time.perf_counter_ns()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(fetch_url_once, target["url"], timeout, 512 * 1024) for _ in range(requests_count)]
        completed = 0
        progress_step = max(1, requests_count // 4)
        for future in concurrent.futures.as_completed(futures):
            outcome = future.result()
            completed += 1
            successes.append(outcome["ok"])
            if outcome["ok"]:
                latencies.append(outcome["seconds"] * 1_000)
                statuses.append(outcome.get("status"))
            else:
                errors.append(outcome["error"])
            if completed % progress_step == 0 or completed == requests_count:
                log_progress(
                    f"[self] burst progress {target['name']}: {completed}/{requests_count} complete | failures {len(errors)}"
                )
    elapsed = (time.perf_counter_ns() - started) / 1_000_000_000
    return {
        "target": target,
        "requests": requests_count,
        "concurrency": concurrency,
        "total_seconds": elapsed,
        "latency_ms": summarize_samples(latencies),
        "reliability": summarize_boolean_results(successes),
        "statuses": sorted(set(statuses)),
        "errors": errors[:5],
    }


def stream_download_once(
    target: dict[str, Any],
    timeout: float,
    progress_label: str | None = None,
) -> dict[str, Any]:
    max_bytes = target.get("read_bytes")
    request = urllib.request.Request(
        target["url"],
        headers={"User-Agent": "networkbench/1.0", "Cache-Control": "no-cache"},
    )
    bytes_read = 0
    per_second: dict[int, int] = {}
    started = time.perf_counter_ns()
    last_logged_bucket = -1
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", None)
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                if max_bytes is not None and bytes_read + len(chunk) > max_bytes:
                    chunk = chunk[: max_bytes - bytes_read]
                bytes_read += len(chunk)
                idx = int((time.perf_counter_ns() - started) / 1_000_000_000)
                per_second[idx] = per_second.get(idx, 0) + len(chunk)
                if progress_label and idx > last_logged_bucket:
                    elapsed_s = max((time.perf_counter_ns() - started) / 1_000_000_000, 0.001)
                    transfer_progress(progress_label, elapsed_s, bytes_read)
                    last_logged_bucket = idx
                if max_bytes is not None and bytes_read >= max_bytes:
                    break
        ended = time.perf_counter_ns()
        series = [per_second.get(idx, 0) for idx in range(max(per_second.keys(), default=-1) + 1)]
        return {"ok": True, "status": status, **summarize_transfer(bytes_read, (ended - started) / 1_000_000_000, series)}
    except Exception as exc:  # noqa: BLE001
        ended = time.perf_counter_ns()
        series = [per_second.get(idx, 0) for idx in range(max(per_second.keys(), default=-1) + 1)]
        return {
            "ok": False,
            "error": str(exc),
            **summarize_transfer(bytes_read, max((ended - started) / 1_000_000_000, 0.0001), series),
        }


def parallel_download_test(
    target: dict[str, Any],
    concurrency: int,
    timeout: float,
) -> dict[str, Any]:
    log_progress(
        f"[self] starting parallel download {target['name']} with {concurrency} streams"
    )
    start_event = threading.Event()
    results: list[dict[str, Any] | None] = [None] * concurrency
    errors: list[str] = []

    def worker(index: int) -> None:
        start_event.wait()
        try:
            results[index] = stream_download_once(target, timeout)
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))

    threads = [threading.Thread(target=worker, args=(idx,), daemon=True) for idx in range(concurrency)]
    for thread in threads:
        thread.start()
    wall_start = time.perf_counter_ns()
    start_event.set()
    for thread in threads:
        thread.join()
    wall_end = time.perf_counter_ns()

    total_bytes = sum(item["bytes"] for item in results if item)
    outcome = {
        "target": target,
        "concurrency": concurrency,
        "aggregate": summarize_transfer(total_bytes, (wall_end - wall_start) / 1_000_000_000),
        "per_stream": results,
        "errors": errors,
    }
    log_progress(
        f"[self] finished parallel download {target['name']}: {fmt_number(outcome['aggregate']['mbps'])} Mbps aggregate"
    )
    return outcome


def upload_once(
    target: dict[str, Any],
    timeout: float,
    progress_label: str | None = None,
) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(target["url"])
    is_https = parsed.scheme == "https"
    conn_cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
    host = parsed.hostname
    if host is None:
        return {"ok": False, "error": f"invalid upload url: {target['url']}"}
    port = parsed.port or (443 if is_https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    total_bytes = int(target.get("bytes", 20_000_000))
    method = target.get("method", "PUT").upper()
    headers = {"Content-Type": "application/octet-stream", "User-Agent": "networkbench/1.0"}
    headers.update(target.get("headers", {}))
    headers["Content-Length"] = str(total_bytes)

    per_second: dict[int, int] = {}
    payload = b"u" * (64 * 1024)
    sent_total = 0
    started = time.perf_counter_ns()
    last_logged_bucket = -1
    try:
        conn = conn_cls(host, port, timeout=timeout)
        conn.putrequest(method, path)
        for key, value in headers.items():
            conn.putheader(key, value)
        conn.endheaders()
        while sent_total < total_bytes:
            chunk = payload[: min(len(payload), total_bytes - sent_total)]
            conn.send(chunk)
            sent_total += len(chunk)
            idx = int((time.perf_counter_ns() - started) / 1_000_000_000)
            per_second[idx] = per_second.get(idx, 0) + len(chunk)
            if progress_label and idx > last_logged_bucket:
                elapsed_s = max((time.perf_counter_ns() - started) / 1_000_000_000, 0.001)
                transfer_progress(progress_label, elapsed_s, sent_total)
                last_logged_bucket = idx
        response = conn.getresponse()
        response.read(1024)
        ended = time.perf_counter_ns()
        conn.close()
        series = [per_second.get(idx, 0) for idx in range(max(per_second.keys(), default=-1) + 1)]
        return {
            "ok": 200 <= response.status < 400,
            "status": response.status,
            **summarize_transfer(sent_total, (ended - started) / 1_000_000_000, series),
        }
    except Exception as exc:  # noqa: BLE001
        ended = time.perf_counter_ns()
        series = [per_second.get(idx, 0) for idx in range(max(per_second.keys(), default=-1) + 1)]
        return {
            "ok": False,
            "error": str(exc),
            **summarize_transfer(sent_total, max((ended - started) / 1_000_000_000, 0.0001), series),
        }


def upload_tests(targets: list[dict[str, Any]], timeout: float) -> list[dict[str, Any]]:
    results = []
    for target in targets:
        outcome = upload_once(target, timeout)
        results.append({"target": target, **outcome})
    return results


def icmp_ping(host: str, count: int, interval: float, timeout: float) -> dict[str, Any]:
    if not shutil.which("ping"):
        return {"skipped": True, "reason": "ping not available"}
    command = ["ping", "-n", "-c", str(count), "-i", str(interval), "-W", str(int(max(timeout, 1))), host]
    result = run_command(command, timeout=max(timeout * count + 2, 5))
    if not result.get("ok"):
        return {"skipped": True, "reason": result}
    stdout = result["stdout"]
    packet_match = re.search(
        r"(?P<tx>\d+)\s+packets transmitted,\s+(?P<rx>\d+)\s+received(?:,.*)?(?P<loss>\d+(?:\.\d+)?)%\s+packet loss",
        stdout,
    )
    rtt_match = re.search(
        r"rtt min/avg/max/(?:mdev|stddev) = (?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)/(?P<dev>[\d.]+) ms",
        stdout,
    )
    return {
        "host": host,
        "packets": packet_match.groupdict() if packet_match else None,
        "rtt": rtt_match.groupdict() if rtt_match else None,
        "raw": stdout.splitlines()[-2:],
    }


def pmtu_probe(host: str, timeout: float) -> dict[str, Any]:
    if not shutil.which("ping"):
        return {"skipped": True, "reason": "ping not available"}
    sizes = [1200, 1400, 1472]
    results = []
    largest_ok = None
    for size in sizes:
        command = ["ping", "-n", "-M", "do", "-s", str(size), "-c", "1", "-W", str(int(max(timeout, 1))), host]
        outcome = run_command(command, timeout=max(timeout + 1, 3))
        ok = outcome.get("ok", False)
        if ok:
            largest_ok = size
        results.append({"size": size, "ok": ok, "stdout": outcome.get("stdout", "").splitlines()[-2:]})
    return {"host": host, "largest_payload_without_fragmentation": largest_ok, "results": results}


def reliability_probe(target: dict[str, Any], timeout: float) -> tuple[bool, float | None, str | None]:
    kind = target.get("kind", "tcp")
    if kind == "tcp":
        return tcp_connect_once(target["host"], int(target["port"]), timeout)
    if kind == "tls":
        return tls_handshake_once(
            target["host"],
            int(target["port"]),
            timeout,
            server_name=target.get("tls_sni"),
        )
    if kind == "http":
        outcome = fetch_url_once(target["url"], timeout, max_bytes=512 * 1024)
        if outcome["ok"]:
            return True, outcome["seconds"] * 1_000, None
        return False, None, outcome["error"]
    return False, None, f"unsupported reliability target kind: {kind}"


def soak_test(targets: list[dict[str, Any]], duration_s: int, timeout: float) -> list[dict[str, Any]]:
    if not targets:
        return []
    log_progress(f"[self] starting soak test for {duration_s}s across {len(targets)} targets")
    results = []
    deadline = time.perf_counter() + duration_s
    started = time.perf_counter()
    next_progress = started + 5.0
    while time.perf_counter() < deadline:
        for target in targets:
            ok, latency, error = reliability_probe(target, timeout)
            results.append(
                {
                    "target": target.get("name", target.get("host", target.get("url", "unknown"))),
                    "ok": ok,
                    "latency_ms": latency,
                    "error": error,
                    "timestamp": time.time(),
                }
            )
            if time.perf_counter() >= deadline:
                break
        now = time.perf_counter()
        if now >= next_progress:
            failures = sum(1 for item in results if not item["ok"])
            log_progress(
                f"[self] soak progress {int(now - started)}s/{duration_s}s | probes {len(results)} | failures {failures}"
            )
            next_progress = now + 5.0
    grouped: dict[str, dict[str, Any]] = {}
    for item in results:
        key = item["target"]
        entry = grouped.setdefault(key, {"target": key, "latencies": [], "successes": [], "errors": []})
        entry["successes"].append(item["ok"])
        if item["ok"] and item["latency_ms"] is not None:
            entry["latencies"].append(item["latency_ms"])
        elif item["error"]:
            entry["errors"].append(item["error"])
    outcome = [
        {
            "target": key,
            "latency_ms": summarize_samples(value["latencies"]),
            "reliability": summarize_boolean_results(value["successes"]),
            "errors": value["errors"][:5],
        }
        for key, value in grouped.items()
    ]
    total_failures = sum(item["reliability"]["failures"] for item in outcome)
    log_progress(f"[self] finished soak test: total failures {total_failures}")
    return outcome


def background_download_load(
    target: dict[str, Any],
    timeout: float,
    stop_event: threading.Event,
    counter: list[int],
    index: int,
) -> threading.Thread:
    def runner() -> None:
        total = 0
        load_target = dict(target)
        load_target.setdefault("read_bytes", target.get("read_bytes", 50_000_000))
        while not stop_event.is_set():
            outcome = stream_download_once(load_target, timeout)
            total += outcome.get("bytes", 0)
            if not outcome.get("ok"):
                break
        counter[index] = total

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread


def background_upload_load(
    target: dict[str, Any],
    timeout: float,
    stop_event: threading.Event,
    counter: list[int],
    index: int,
) -> threading.Thread:
    def runner() -> None:
        total = 0
        load_target = dict(target)
        load_target.setdefault("bytes", target.get("bytes", 20_000_000))
        while not stop_event.is_set():
            outcome = upload_once(load_target, timeout)
            total += outcome.get("bytes", 0)
            if not outcome.get("ok"):
                break
        counter[index] = total

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread


def under_load_test(
    latency_targets: list[dict[str, Any]],
    small_targets: list[dict[str, Any]],
    bulk_downloads: list[dict[str, Any]],
    uploads: list[dict[str, Any]],
    timeout: float,
    load_seconds: int,
) -> dict[str, Any]:
    if not bulk_downloads and not uploads:
        return {"skipped": True, "reason": "no bulk downloads or upload targets configured"}
    log_progress(f"[self] starting under-load test for {load_seconds}s")

    stop_event = threading.Event()
    threads = []
    download_counters = [0] * min(2, len(bulk_downloads))
    upload_counters = [0] * min(1, len(uploads))

    for idx, target in enumerate(bulk_downloads[:2]):
        threads.append(background_download_load(target, timeout, stop_event, download_counters, idx))
    for idx, target in enumerate(uploads[:1]):
        threads.append(background_upload_load(target, timeout, stop_event, upload_counters, idx))

    time.sleep(1.0)
    start = time.perf_counter()
    tcp_under_load = tcp_connect_test(latency_targets[:2], repeats=6, timeout=timeout)
    http_under_load = small_http_tests(small_targets[:1], repeats=4, timeout=timeout) if small_targets else []
    remaining = load_seconds - (time.perf_counter() - start)
    if remaining > 0:
        time.sleep(remaining)
    stop_event.set()
    for thread in threads:
        thread.join(timeout=2.0)
    outcome = {
        "load_seconds": load_seconds,
        "background_download_mbps": sum(download_counters) * 8 / max(load_seconds, 1) / 1_000_000,
        "background_upload_mbps": sum(upload_counters) * 8 / max(load_seconds, 1) / 1_000_000,
        "tcp_connect_under_load": tcp_under_load,
        "http_small_under_load": http_under_load,
    }
    log_progress(
        f"[self] finished under-load test: bg down {fmt_number(outcome['background_download_mbps'])} Mbps, "
        f"bg up {fmt_number(outcome['background_upload_mbps'])} Mbps"
    )
    return outcome


def flags_from_results(results: dict[str, Any]) -> list[str]:
    flags = []

    dns = results["tests"]["dns"]
    if any(item["reliability"]["failures"] for item in dns):
        flags.append("DNS lookups failed intermittently; name resolution may be an operational bottleneck.")
    for item in dns:
        p95 = item["latency_ms"]["p95"]
        if p95 and p95 > 200:
            flags.append(f"DNS latency to {item['host']} is high at the tail (>200 ms p95).")
            break

    tcp_tests = results["tests"]["tcp_connect"]
    for item in tcp_tests:
        p50 = item["latency_ms"]["p50"]
        p95 = item["latency_ms"]["p95"]
        if p50 and p95 and p95 > max(10, p50 * 3):
            flags.append(f"TCP connect latency is spiky for {item['target']['name']}.")
            break

    tls_tests = results["tests"]["tls_handshake"]
    for item in tls_tests:
        p95 = item["latency_ms"]["p95"]
        if p95 and p95 > 500:
            flags.append(f"TLS handshake latency is high for {item['target']['name']}; short-lived HTTPS requests will feel slower.")
            break

    burst = results["tests"].get("http_burst")
    if burst:
        for item in burst:
            p95 = item["latency_ms"]["p95"]
            if p95 and p95 > 1000:
                flags.append(f"Burst fetch latency is high for {item['target']['name']}; pages/APIs with many small requests may feel sluggish.")
                break

    downloads = results["tests"].get("bulk_downloads", [])
    for item in downloads:
        if not item["single"].get("ok"):
            flags.append(f"Bulk download failed for {item['target']['name']}.")
            continue
        cv = item["single"].get("stability_cv")
        if cv is not None and cv > 0.25:
            flags.append(f"Download throughput is unstable for {item['target']['name']}.")
            break

    uploads = results["tests"].get("uploads", [])
    if uploads and all(not item.get("ok") for item in uploads):
        flags.append("All configured upload tests failed; upstream benchmarking is incomplete or the upload target rejected the requests.")

    under_load = results["tests"].get("under_load", {})
    if not under_load.get("skipped"):
        idle_tcp = results["tests"]["tcp_connect"]
        loaded_tcp = under_load.get("tcp_connect_under_load", [])
        if idle_tcp and loaded_tcp:
            idle_p95 = idle_tcp[0]["latency_ms"]["p95"]
            load_p95 = loaded_tcp[0]["latency_ms"]["p95"]
            if idle_p95 and load_p95 and load_p95 > idle_p95 + 50 and load_p95 > idle_p95 * 2:
                flags.append("Latency rises sharply while transfers are active; queueing/bufferbloat is likely.")

    icmp = results["tests"].get("icmp", [])
    for item in icmp:
        loss = item.get("packets", {}).get("loss") if item.get("packets") else None
        try:
            if loss is not None and float(loss) > 0:
                flags.append(f"ICMP packet loss was observed toward {item['host']}.")
                break
        except ValueError:
            pass

    pmtu = results["tests"].get("pmtu", [])
    for item in pmtu:
        largest = item.get("largest_payload_without_fragmentation")
        if largest is not None and largest < 1472:
            flags.append(f"PMTU toward {item['host']} looks constrained (<1472 byte IPv4 payload).")
            break

    soak = results["tests"].get("soak", [])
    for item in soak:
        if item["reliability"]["failures"] > 0:
            flags.append(f"Soak test saw intermittent failures toward {item['target']}.")
            break

    return analysis_flags(flags)


def print_summary(results: dict[str, Any]) -> None:
    print("")
    print("=== VPS self benchmark summary ===")
    if results["tests"]["dns"]:
        first_dns = results["tests"]["dns"][0]
        print(
            f"DNS {first_dns['host']} p50/p95: "
            f"{fmt_number(first_dns['latency_ms']['p50'])} / {fmt_number(first_dns['latency_ms']['p95'])} ms"
        )
    if results["tests"]["tcp_connect"]:
        first_tcp = results["tests"]["tcp_connect"][0]
        print(
            f"TCP connect {first_tcp['target']['name']} p50/p95: "
            f"{fmt_number(first_tcp['latency_ms']['p50'])} / {fmt_number(first_tcp['latency_ms']['p95'])} ms"
        )
    if results["tests"]["tls_handshake"]:
        first_tls = results["tests"]["tls_handshake"][0]
        print(
            f"TLS handshake {first_tls['target']['name']} p50/p95: "
            f"{fmt_number(first_tls['latency_ms']['p50'])} / {fmt_number(first_tls['latency_ms']['p95'])} ms"
        )
    if results["tests"].get("bulk_downloads"):
        for item in results["tests"]["bulk_downloads"]:
            if item["single"]["ok"]:
                print(
                    f"Download {item['target']['name']} single/parallel: "
                    f"{fmt_number(item['single']['mbps'])} / {fmt_number(item['parallel']['aggregate']['mbps'])} Mbps"
                )
    if results["tests"].get("uploads"):
        for item in results["tests"]["uploads"]:
            if item.get("ok"):
                print(f"Upload {item['target']['name']}: {fmt_number(item['mbps'])} Mbps")
    if results["analysis_flags"]:
        print("Flags:")
        for item in results["analysis_flags"]:
            print(f"  - {item}")


def run_self_benchmark(args: argparse.Namespace) -> int:
    profile = load_profile(args.config)
    preset = PROFILE_PRESETS[args.profile]
    log_progress(
        f"[self] loaded profile '{args.profile}' with "
        f"{len(profile['dns_hosts'])} DNS hosts, "
        f"{len(profile['latency_targets'])} latency targets, "
        f"{len(profile['http_bulk_downloads'])} bulk downloads, "
        f"{len(profile['http_uploads'])} uploads"
    )

    reliability_targets = profile["reliability_targets"]
    if not reliability_targets:
        reliability_targets = [
            {"name": target["name"], "kind": "tcp", "host": target["host"], "port": target["port"]}
            for target in profile["latency_targets"][:2]
        ]
        if profile["http_small_objects"]:
            reliability_targets.append(
                {
                    "name": profile["http_small_objects"][0]["name"],
                    "kind": "http",
                    "url": profile["http_small_objects"][0]["url"],
                }
            )

    results = {
        "meta": {
            **system_metadata(),
            "mode": "vps_self_benchmark",
            "profile": args.profile,
            "config_path": args.config,
        },
        "system_snapshot": system_snapshot(),
        "config": profile,
        "tests": {},
    }
    log_progress("[self] captured system snapshot")

    log_test_start("DNS tests", f"{len(profile['dns_hosts'])} hosts x {preset['dns_repeats']} repeats")
    results["tests"]["dns"] = dns_resolution_test(
        profile["dns_hosts"], preset["dns_repeats"], args.timeout
    )
    log_test_done("DNS tests", f"{len(results['tests']['dns'])} hosts completed")

    log_test_start("TCP connect tests", f"{len(profile['latency_targets'])} targets x {preset['latency_repeats']} repeats")
    results["tests"]["tcp_connect"] = tcp_connect_test(
        profile["latency_targets"], preset["latency_repeats"], args.timeout
    )
    log_test_done("TCP connect tests", f"{len(results['tests']['tcp_connect'])} targets completed")

    log_test_start("TLS handshake tests", f"{len(profile['latency_targets'])} targets x {preset['latency_repeats']} repeats")
    results["tests"]["tls_handshake"] = tls_handshake_test(
        profile["latency_targets"], preset["latency_repeats"], args.timeout
    )
    log_test_done("TLS handshake tests", f"{len(results['tests']['tls_handshake'])} targets completed")

    log_test_start("small HTTP fetch tests", f"{len(profile['http_small_objects'])} targets")
    results["tests"]["http_small"] = small_http_tests(
        profile["http_small_objects"], preset["http_small_repeats"], args.timeout
    )
    log_test_done("small HTTP fetch tests", f"{len(results['tests']['http_small'])} targets completed")

    log_test_start("HTTP burst tests", f"{len(profile['http_small_objects'])} targets")
    results["tests"]["http_burst"] = [
        http_burst_test(target, preset["http_burst_requests"], preset["http_burst_concurrency"], args.timeout)
        for target in profile["http_small_objects"]
    ]
    log_test_done("HTTP burst tests", f"{len(results['tests']['http_burst'])} targets completed")

    bulk_download_results = []
    for target in profile["http_bulk_downloads"]:
        log_test_start("bulk download", target["name"])
        bulk_download_results.append(
            {
                "target": target,
                "single": stream_download_once(
                    target,
                    args.timeout,
                    progress_label=f"[self] download {target['name']}",
                ),
                "parallel": parallel_download_test(target, concurrency=4, timeout=args.timeout),
            }
        )
        latest = bulk_download_results[-1]
        log_test_done(
            "bulk download",
            f"{target['name']} single {fmt_number(latest['single']['mbps'])} Mbps, "
            f"parallel {fmt_number(latest['parallel']['aggregate']['mbps'])} Mbps",
        )
    results["tests"]["bulk_downloads"] = bulk_download_results

    upload_results = []
    for target in profile["http_uploads"]:
        log_test_start("upload", target["name"])
        outcome = upload_once(
            target,
            args.timeout,
            progress_label=f"[self] upload {target['name']}",
        )
        upload_results.append({"target": target, **outcome})
        log_test_done(
            "upload",
            f"{target['name']} status {upload_results[-1].get('status', '-')}, "
            f"{fmt_number(upload_results[-1].get('mbps'))} Mbps",
        )
    results["tests"]["uploads"] = upload_results

    log_test_start("under-load test", f"{args.load_seconds or preset['load_seconds']}s")
    results["tests"]["under_load"] = under_load_test(
        profile["latency_targets"],
        profile["http_small_objects"],
        profile["http_bulk_downloads"],
        profile["http_uploads"],
        timeout=args.timeout,
        load_seconds=args.load_seconds or preset["load_seconds"],
    )
    if results["tests"]["under_load"].get("skipped"):
        log_test_done("under-load test", "skipped")
    else:
        log_test_done(
            "under-load test",
            f"bg down {fmt_number(results['tests']['under_load']['background_download_mbps'])} Mbps, "
            f"bg up {fmt_number(results['tests']['under_load']['background_upload_mbps'])} Mbps",
        )

    log_test_start("ICMP tests")
    results["tests"]["icmp"] = [
        icmp_ping(target["host"], count=6, interval=0.2, timeout=args.timeout)
        for target in profile["latency_targets"][:2]
    ]
    log_test_done("ICMP tests", f"{len(results['tests']['icmp'])} targets completed")

    log_test_start("PMTU tests")
    results["tests"]["pmtu"] = [pmtu_probe(target["host"], timeout=args.timeout) for target in profile["latency_targets"][:2]]
    log_test_done("PMTU tests", f"{len(results['tests']['pmtu'])} targets completed")

    log_test_start("soak test", f"{args.soak_seconds or preset['soak_seconds']}s")
    results["tests"]["soak"] = soak_test(
        reliability_targets,
        duration_s=args.soak_seconds or preset["soak_seconds"],
        timeout=args.timeout,
    )
    log_test_done("soak test", f"{len(results['tests']['soak'])} targets summarized")
    results["analysis_flags"] = flags_from_results(results)

    print_summary(results)
    if args.output:
        write_json(args.output, results)
        print(f"[self] wrote JSON results to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a scenario-driven network benchmark directly from a VPS against configurable public targets."
    )
    parser.add_argument(
        "--config",
        help="Optional JSON profile with realistic target URLs/hosts (see profiles/self_benchmark.sample.json)",
    )
    parser.add_argument(
        "--profile",
        choices=["quick", "standard", "extended"],
        default="standard",
        help="Benchmark intensity profile",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-operation timeout in seconds")
    parser.add_argument("--soak-seconds", type=int, help="Override soak duration")
    parser.add_argument("--load-seconds", type=int, help="Override under-load duration")
    parser.add_argument("--output", help="Write full JSON results to this path")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_self_benchmark(args)


if __name__ == "__main__":
    raise SystemExit(main())
