# networkbench

Scenario-driven network benchmarking for VPSes.

This repo has **two benchmark variants**:

1. **`scripts/vps_self_bench.py`**  
   Run on the VPS itself. It benchmarks the machine's real outbound/inbound behavior against configurable external targets.

2. **`scripts/pair_bench.py`**  
   Run a server on the VPS and a client somewhere else. It benchmarks the actual path **between that client and the server**, not just generic internet speed.

The focus is intentionally broader than “run a speed test and print Mbps”.

It measures things that matter in real use:

- connection setup latency
- tail latency, not just averages
- jitter and burstiness
- loss / intermittent failures
- stability over time
- latency under load
- single-flow vs multi-flow behavior
- small-object behavior vs bulk transfers
- UDP behavior for real-time traffic
- PMTU / fragmentation risk

The shipped defaults are now all **valid public targets**. For generic large-object upload/download checks,
the self-benchmark uses Cloudflare Speed test endpoints by default.

---

## Requirements

### Core

- **Python 3.9+** on Linux

No Python packages are auto-installed.

### Optional but useful on Linux

These are **not mandatory**, but they unlock extra diagnostics in `vps_self_bench.py`:

- `ping` — ICMP latency/loss and PMTU probing
- `ip` — route/interface snapshot
- `ss` — socket summary snapshot

---

## Why this is different from a standard speed test

Typical speed tests tell you one thing:

- “here is the best-case throughput to one specific test node”

That is useful, but incomplete.

Real traffic is often:

- many short HTTPS requests
- bursts of parallel asset/API fetches
- a single long stream
- several parallel streams
- interactive requests while a large transfer is already in flight
- UDP-based real-time traffic
- intermittent failures over time rather than one clean measurement

These scripts explicitly test those conditions.

---

## Variant 1: run from the VPS itself

### Script

```bash
python3 scripts/vps_self_bench.py --profile standard --output results/self.json
```

### With a realistic target profile

```bash
python3 scripts/vps_self_bench.py \
  --config profiles/self_benchmark.sample.json \
  --profile standard \
  --output results/self.json
```

The sample profile now contains only valid public endpoints, so it runs as-is.
You should still replace them with your own CDN/API/storage targets when you want workload-specific answers.

### What it measures

- system/network snapshot
- DNS latency + reliability
- TCP connect latency to multiple targets
- TLS handshake latency
- small HTTP fetch latency
- burst fetch behavior for many small requests
- optional bulk download throughput + stability
- optional HTTP upload throughput against your own endpoint
- latency while transfers are already active
- optional ICMP loss/jitter
- optional PMTU/fragmentation checks
- soak / intermittent-failure checks

### Important note

For the self-benchmark to reflect **your real workload**, customize the JSON profile:

- your CDN/object storage URLs
- your API endpoints
- your customer-region targets
- your upload endpoint (for upstream testing)

If you only use default targets, the script still runs, but the result is less workload-specific.

---

## Variant 2: run between a client and the VPS

### On the VPS

```bash
python3 scripts/pair_bench.py server --listen 0.0.0.0 --port 47000
```

Make sure the chosen port is allowed through the VPS firewall/security group for **both TCP and UDP**.

### On the remote client

```bash
python3 scripts/pair_bench.py client \
  --host YOUR_VPS_IP_OR_HOSTNAME \
  --profile standard \
  --output results/pair.json
```

### What it measures

- TCP connect latency
- request/response round-trip latency over persistent TCP
- single-stream download throughput
- single-stream upload throughput
- parallel-stream scaling
- UDP RTT / jitter / loss / duplicates / reordering
- UDP size sweep for real-time / MTU sensitivity
- latency under simultaneous background load
- soak stability over time

This variant is the better choice when you care about:

- user-to-server path quality
- office/home/client-to-VPS performance
- interactive behavior under load
- UDP real-time behavior
- whether the path falls apart once a bulk transfer starts

---

## Profiles

Both scripts support:

- `quick`
- `standard`
- `extended`

Use:

- `quick` for a fast smoke test
- `standard` for default practical benchmarking
- `extended` for deeper validation / troubleshooting

---

## Example workflow

### A. Benchmark the VPS as an internet client

1. Copy `profiles/self_benchmark.sample.json`
2. Replace the sample URLs/hosts with:
   - your API
   - your CDN
   - your object storage
   - your upload destination
3. Run:

```bash
python3 scripts/vps_self_bench.py --config my_targets.json --profile standard
```

### B. Benchmark a specific path from your laptop/office/home to the VPS

On the VPS:

```bash
python3 scripts/pair_bench.py server
```

On the client:

```bash
python3 scripts/pair_bench.py client --host vps.example.com --profile standard
```

---

## Interpreting the results

Look at more than raw Mbps.

### Good signs

- low connect/TLS p95
- low packet loss
- low latency inflation while transfers run
- parallel streams improve throughput when expected
- soak test has zero failures
- throughput stability is fairly flat over time

### Red flags

- high p95 relative to p50
- UDP loss even while idle
- much worse latency under load
- unstable per-second throughput
- soak test failures / short outages
- PMTU probe failing earlier than expected
- uploads much weaker than downloads

Those are usually more predictive of real application behavior than a single headline speed number.

---

## Notes on upload testing

The self-benchmark now ships with a valid generic upload/download target:

- download: `https://speed.cloudflare.com/__down?bytes=N`
- upload: `https://speed.cloudflare.com/__up`

That makes the defaults runnable out of the box.

But if you care about your actual workload, you should still benchmark against your own ingress/storage path.

Why:

- a generic public target is still not the same as your application path
- results can still differ from your CDN/object-storage/API behavior
- the best test is usually your own storage/API ingress

So for meaningful upstream testing, replace the default with your own HTTP `PUT`/`POST` target in the JSON profile.

Use a target that is safe to receive disposable benchmark payloads, such as:

- a pre-signed object-store upload URL
- a dedicated ingest endpoint
- a temporary discard/sink endpoint you control

---

## Files

- `scripts/vps_self_bench.py` — self-run benchmark
- `scripts/pair_bench.py` — server/client path benchmark
- `scripts/bench_common.py` — shared metrics helpers
- `profiles/self_benchmark.sample.json` — example realistic target profile

---

## Output

Both scripts print a concise summary to stdout.

If you pass `--output <path>`, they also write full JSON results for later analysis.
