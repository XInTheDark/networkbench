#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import os
import platform
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    if pct <= 0:
        return min(values)
    if pct >= 100:
        return max(values)
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def mean(values: Iterable[float]) -> float | None:
    values = list(values)
    if not values:
        return None
    return statistics.fmean(values)


def stdev(values: Iterable[float]) -> float | None:
    values = list(values)
    if len(values) < 2:
        return 0.0 if values else None
    return statistics.pstdev(values)


def summarize_samples(values: Iterable[float], unit: str = "ms") -> dict[str, Any]:
    values = list(values)
    if not values:
        return {
            "count": 0,
            "unit": unit,
            "min": None,
            "max": None,
            "mean": None,
            "stdev": None,
            "p50": None,
            "p95": None,
            "p99": None,
        }
    sample_mean = statistics.fmean(values)
    return {
        "count": len(values),
        "unit": unit,
        "min": min(values),
        "max": max(values),
        "mean": sample_mean,
        "stdev": statistics.pstdev(values) if len(values) > 1 else 0.0,
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
    }


def coefficient_of_variation(values: Iterable[float]) -> float | None:
    values = list(values)
    if not values:
        return None
    sample_mean = mean(values)
    sample_stdev = stdev(values)
    if sample_mean in (None, 0) or sample_stdev is None:
        return None
    return sample_stdev / sample_mean


def throughput_mbps(total_bytes: int, seconds: float) -> float | None:
    if seconds <= 0:
        return None
    return (total_bytes * 8) / seconds / 1_000_000


def per_second_bps(series_bytes: list[int]) -> list[float]:
    return [(value * 8) / 1_000_000 for value in series_bytes]


def ensure_parent(path: str | os.PathLike[str]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def write_json(path: str | os.PathLike[str], payload: dict[str, Any]) -> None:
    ensure_parent(path)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def rolling_outages(successes: Iterable[bool]) -> dict[str, Any]:
    outage_lengths = []
    current = 0
    for ok in successes:
        if ok:
            if current:
                outage_lengths.append(current)
                current = 0
        else:
            current += 1
    if current:
        outage_lengths.append(current)
    return {
        "outage_events": len(outage_lengths),
        "longest_outage_samples": max(outage_lengths) if outage_lengths else 0,
        "outage_lengths": outage_lengths,
    }


def summarize_transfer(
    total_bytes: int,
    seconds: float,
    per_second_bytes: list[int] | None = None,
) -> dict[str, Any]:
    mbps = throughput_mbps(total_bytes, seconds)
    series_mbps = per_second_bps(per_second_bytes or [])
    return {
        "bytes": total_bytes,
        "seconds": seconds,
        "mbps": mbps,
        "per_second_mbps": series_mbps,
        "stability_cv": coefficient_of_variation(series_mbps),
        "per_second_summary": summarize_samples(series_mbps, unit="Mbps")
        if series_mbps
        else None,
    }


def summarize_boolean_results(results: Iterable[bool]) -> dict[str, Any]:
    results = list(results)
    successes = sum(1 for item in results if item)
    failures = len(results) - successes
    outage_info = rolling_outages(results)
    return {
        "samples": len(results),
        "successes": successes,
        "failures": failures,
        "success_rate": successes / len(results) if results else None,
        **outage_info,
    }


def system_metadata() -> dict[str, Any]:
    return {
        "timestamp": now_iso(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version,
        "hostname": platform.node(),
    }


def clamp_non_negative(value: float | None) -> float | None:
    if value is None:
        return None
    return max(value, 0.0)


def analysis_flags(entries: Iterable[str]) -> list[str]:
    return [entry for entry in entries if entry]


def fmt_number(value: float | int | None, decimals: int = 2, fallback: str = "-") -> str:
    if value is None:
        return fallback
    return f"{value:.{decimals}f}"


def fmt_bytes(value: int | float | None, fallback: str = "-") -> str:
    if value is None:
        return fallback
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    amount = float(value)
    unit = units[0]
    for unit in units:
        if abs(amount) < 1024 or unit == units[-1]:
            break
        amount /= 1024.0
    decimals = 0 if unit == "B" else 2
    return f"{amount:.{decimals}f} {unit}"
