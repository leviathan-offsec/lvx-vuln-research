# Contributing

Leviathan is a collaborative firmware and vulnerability research lab. Small,
well-documented contributions are welcome: firmware observations, device notes,
reproduction improvements, detection ideas, and corrections to existing work.

## Add firmware research

1. Create a device or firmware directory under [`iot/devices/`](./iot/).
2. Copy [`templates/RESEARCH.md`](./templates/RESEARCH.md) into that directory.
3. Record the target firmware, hardware revision, acquisition source, and
   evidence level.
4. Keep the lab model, PoC, and detection logic separate so each can be
   reviewed independently.
5. State what was not tested and list the next useful experiment.

## Update the host inventory

Edit [`iot/hosts.yaml`](./iot/hosts.yaml) when a shared lab target changes.
Include only sanitized coordination data:

- stable host ID
- vendor, model, firmware, and hardware revision
- documentation-only address or private lab label
- exposed lab ports
- availability status
- researcher handle and update date

Do not commit real public or private IP addresses, credentials, API keys,
session cookies, serial numbers, MAC addresses, or management URLs. Keep those
in the lab owner's private inventory.

## Review checklist

- Can another researcher understand the claim without guessing?
- Is the evidence level accurate?
- Does the reproduction run only against an isolated or authorized target?
- Are detections labelled as lab-derived or firmware-validated?
- Are sensitive host and device details removed?
- Does the device return to a known-safe state after testing?