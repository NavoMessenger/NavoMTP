# TLS Front Profile Fidelity

## Overview

This document describes how Telemt reuses captured TLS behavior in the FakeTLS server flight and how to validate the result on a real deployment.

When TLS front emulation is enabled, Telemt can capture useful server-side TLS behavior from the selected origin and reuse that behavior in the emulated success path. The goal is not to reproduce the origin byte-for-byte, but to reduce stable synthetic traits and make the emitted server flight structurally closer to the captured profile.

## Why this change exists

The project already captures useful server-side TLS behavior in the TLS front fetch path:

- `change_cipher_spec_count`
- `app_data_record_sizes`
- `ticket_record_sizes`

Before this change, the emulator used only part of that information. This left a gap between captured origin behavior and emitted FakeTLS server flight.

## What is implemented

- The emulator now replays the observed `ChangeCipherSpec` count from the fetched behavior profile.
- The emulator now replays observed ticket-like tail ApplicationData record sizes when raw or merged TLS profile data is available.
- The emulator now preserves more of the profiled encrypted-flight structure instead of collapsing it into a smaller synthetic shape.
- The emulator still falls back to the previous synthetic behavior when the cached profile does not contain raw TLS behavior information.
- Operator-configured `tls_new_session_tickets` still works as an additive fallback when the profile does not provide enough tail records.

## Practical benefit

- Reduced distinguishability between profiled origin TLS behavior and emulated TLS behavior.
- Lower chance of stable server-flight fingerprints caused by fixed CCS count or synthetic-only tail record sizes.
- Better reuse of already captured TLS profile data without changing MTProto logic, KDF routing, or transport architecture.

## Limitations

This mechanism does not aim to make Telemt byte-identical to the origin server.

It also does not change:

- MTProto business logic;
- KDF routing behavior;
- the overall transport architecture.

The practical goal is narrower:

- reuse more captured profile data;
- reduce fixed synthetic behavior in the server flight;
- preserve a valid FakeTLS success path while changing the emitted shape on the wire.

## Validation targets

- Correct count of emulated `ChangeCipherSpec` records.
- Correct replay of observed ticket-tail record sizes.
- No regression in existing ALPN and payload-placement behavior.

## How to validate the result

Recommended validation consists of two layers:

- focused unit and security tests for CCS-count replay and ticket-tail replay;
- real packet-capture comparison for a selected origin and a successful FakeTLS session.

When testing on the network, the expected result is:

- a valid FakeTLS and MTProto success path is preserved;
- the early encrypted server flight changes shape when richer profile data is available;
- the change is visible on the wire without changing MTProto logic or transport architecture.

This validation is intended to show better reuse of captured TLS profile data.
It is not intended to prove byte-level equivalence with the real origin server.

## How to test on a real deployment

The strongest practical validation is a side-by-side trace comparison between:

- a real TLS origin server used as `mask_host`;
- a Telemt FakeTLS success-path connection for the same SNI;
- optional captures from different Telemt builds or configurations.

The purpose of the comparison is to inspect the shape of the server flight:

- record order;
- count of `ChangeCipherSpec` records;
- count and grouping of early encrypted `ApplicationData` records;
- lengths of tail or continuation `ApplicationData` records.

## Recommended environment

Use a Linux host or Docker container for the cleanest reproduction.

Recommended setup:

1. One Telemt instance.
2. One real HTTPS origin as `mask_host`.
3. One Telegram client configured with an `ee` proxy link for the Telemt instance.
4. `tcpdump` or Wireshark available for capture analysis.

## Step-by-step test procedure

### 1. Prepare the origin

1. Choose a real HTTPS origin.
2. Set both `censorship.tls_domain` and `censorship.mask_host` to that hostname.
3. Confirm that a direct TLS request works:

```bash
openssl s_client -connect ORIGIN_IP:443 -servername YOUR_DOMAIN </dev/null
```

### 2. Configure Telemt

Use a configuration that enables:

- `censorship.mask = true`
- `censorship.tls_emulation = true`
- `censorship.mask_host`
- `censorship.mask_port`

Recommended for cleaner testing:

- keep `censorship.tls_new_session_tickets = 0`, so the result depends primarily on fetched profile data rather than operator-forced synthetic tail records;
- keep `censorship.tls_fetch.strict_route = true`, if cleaner provenance for captured profile data is important.

### 3. Refresh TLS profile data

1. Start Telemt.
2. Let it fetch TLS front profile data for the configured domain.
3. If `tls_front_dir` is persisted, confirm that the TLS front cache is populated.

Persisted cache artifacts are useful, but they are not required if packet captures already demonstrate the runtime result.

### 4. Check TLS-front profile health metrics

If the metrics endpoint is enabled, check the TLS-front profile health before packet-capture validation:

```bash
curl -s http://127.0.0.1:9999/metrics | grep -E 'telemt_tls_front_profile|telemt_tls_fetch_profile_cache|telemt_tls_front_full_cert'
```

The profile-health metrics expose the runtime state of configured TLS front domains:

- `telemt_tls_front_profile_domains` shows configured, emitted, and suppressed domain series.
- `telemt_tls_front_profile_info` shows profile source and feature flags per domain.
- `telemt_tls_front_profile_age_seconds` shows cached profile age.
- `telemt_tls_front_profile_app_data_records` shows cached AppData record count.
- `telemt_tls_front_profile_ticket_records` shows cached ticket-like tail record count.
- `telemt_tls_front_profile_change_cipher_spec_records` shows cached ChangeCipherSpec count.
- `telemt_tls_front_profile_app_data_bytes` shows total cached AppData bytes.

Interpretation:

- `source="merged"` or `source="raw"` means real TLS profile data is being used.
- `source="default"` or `is_default="true"` means the domain currently uses the synthetic default fallback.
- `has_cert_payload="true"` means certificate payload data is available for TLS emulation.
- Non-zero AppData/ticket/CCS counters show captured server-flight shape.

Example healthy output:

```text
telemt_tls_front_profile_domains{status="configured"} 1
telemt_tls_front_profile_domains{status="emitted"} 1
telemt_tls_front_profile_domains{status="suppressed"} 0
telemt_tls_front_profile_info{domain="itunes.apple.com",source="merged",is_default="false",has_cert_info="true",has_cert_payload="true"} 1
telemt_tls_front_profile_age_seconds{domain="itunes.apple.com"} 20
telemt_tls_front_profile_app_data_records{domain="itunes.apple.com"} 3
telemt_tls_front_profile_ticket_records{domain="itunes.apple.com"} 1
telemt_tls_front_profile_change_cipher_spec_records{domain="itunes.apple.com"} 1
telemt_tls_front_profile_app_data_bytes{domain="itunes.apple.com"} 5240
```

These metrics do not prove byte-level origin equivalence. They are an operational health signal that the configured domain is backed by real cached profile data instead of default fallback data.

### 5. Capture a direct-origin trace

From a separate client host, connect directly to the origin:

```bash
openssl s_client -connect ORIGIN_IP:443 -servername YOUR_DOMAIN </dev/null
```

Capture with:

```bash
sudo tcpdump -i any -w origin-direct.pcap host ORIGIN_IP and port 443
```

### 6. Capture a Telemt FakeTLS success-path trace

Now connect to Telemt with a real Telegram client through an `ee` proxy link that targets the Telemt instance.

`openssl s_client` is useful for direct-origin capture and fallback sanity checks, but it does not exercise the successful FakeTLS and MTProto path.

Capture with:

```bash
sudo tcpdump -i any -w telemt-emulated.pcap host TELEMT_IP and port 443
```

### 7. Decode TLS record structure

Use `tshark` to print record-level structure:

```bash
tshark -r origin-direct.pcap -Y "tls.record" -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e tls.record.content_type \
  -e tls.record.length
```

```bash
tshark -r telemt-emulated.pcap -Y "tls.record" -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e tls.record.content_type \
  -e tls.record.length
```

Focus on the server flight after ClientHello:

- `22` = Handshake
- `20` = ChangeCipherSpec
- `23` = ApplicationData

### 8. Build a comparison table

A compact table like the following is usually enough:

| Path | CCS count | AppData count in first encrypted flight | Tail AppData lengths |
| --- | --- | --- | --- |
| Origin | `N` | `M` | `[a, b, ...]` |
| Telemt build A | `...` | `...` | `...` |
| Telemt build B | `...` | `...` | `...` |

The comparison should make it easy to see that:

- the FakeTLS success path remains valid;
- the early encrypted server flight changes when richer profile data is reused;
- the result is backed by packet evidence.

## Example capture set

One practical example of this workflow uses:

- `origin-direct-nginx.pcap`
- `telemt-ee-before-nginx.pcap`
- `telemt-ee-after-nginx.pcap`

Practical notes:

- `origin` was captured as a direct TLS 1.2 connection to `nginx.org`;
- `before` and `after` were captured on the Telemt FakeTLS success path with a real Telegram client;
- the first server-side FakeTLS response remains valid in both cases;
- the early encrypted server-flight segmentation differs between `before` and `after`, which is consistent with better reuse of captured profile data;
- this kind of result shows a wire-visible effect without breaking the success path, but it does not claim full indistinguishability from the origin.

## Stronger validation

For broader confidence, repeat the same comparison on:

1. one CDN-backed origin;
2. one regular nginx origin;
3. one origin with a multi-record encrypted flight and visible ticket-like tails.

If the same directional improvement appears across all three, confidence in the result will be much higher than for a single-origin example.
