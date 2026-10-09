# IoT Research

This section is the shared workspace for firmware and embedded-device research.
It is intentionally separate from individual CVE entries because one device or
firmware build may produce several research questions over time.

## Sections

| Path | Purpose |
| --- | --- |
| [`hosts.yaml`](./hosts.yaml) | Sanitized daily inventory of lab targets |
| `devices/` | Device- or firmware-specific research notes |
| `captures/` | Sanitized packet captures and protocol observations |
| `firmware/` | Checksums and metadata, never unlicensed firmware blobs |

Create a directory under `devices/` for each device or firmware family. Start
with the [research template](../templates/RESEARCH.md), then record the exact
firmware version, hardware revision, acquisition source, and what was actually
tested.

## Daily host updates

The host inventory is for coordination, not a scanner target list. Update it
when a lab device changes state:

```yaml
- id: iot-lab-001
  vendor: Example
  model: Example Gateway
  firmware: 1.2.3
  hardware: rev-a
  network: isolated-lab
  address: 192.0.2.10
  ports:
    - 443/tcp
  status: available
  owner: researcher-handle
  updated: 2026-10-09
  notes: "Web UI available; reset before handoff"
```

Use documentation-only addresses such as `192.0.2.0/24`, `198.51.100.0/24`,
or `203.0.113.0/24` in this public repository. Keep real addresses in a
private inventory managed by the lab owner.

Allowed `status` values are `available`, `in-use`, `offline`, `needs-reset`,
and `retired`. The `owner` field should contain a handle, not a person's email
address.

## Contribution expectations

- Add a device note before adding a vulnerability claim.
- Include firmware and hardware identifiers whenever known.
- Separate observed behavior from assumptions.
- Explain how the device was reset or returned to a safe state.
- Remove credentials, tokens, serial numbers, MAC addresses, and real network
  details before opening a pull request.
- Do not upload firmware unless redistribution rights are clear; prefer a
  checksum and acquisition instructions.