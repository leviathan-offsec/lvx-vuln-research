# Leviathan Firmware Vulnerability Research Lab

An organized workspace for researching vulnerabilities in firmware, embedded
appliances, and security-sensitive network services. Each research entry keeps
the technical claim, reproduction environment, client, and detection logic
together.

> **Start here:** choose a lab below, read its entry README, run it on
> loopback, and compare the observed result with the documented evidence level.

> **Research-only repository.** Run the labs locally and only test systems you
> own or are explicitly authorized to assess. The PoCs are not a substitute for
> vendor remediation or a production security control.

## Lab index

| Entry | Target behavior | Start the lab | Run the client |
| --- | --- | --- | --- |
| [CVE-2026-88771](./CVE-2026-88771) | HTTP log poisoning model | `python3 lab/lab_server.py` | `python3 poc/exploit.py` |
| [CVE-2026-88772](./CVE-2026-88772) | DTLS reassembly overflow model | `python3 lab/lab_nsppe.py` | `python3 poc/poc_dtls.py` |

Run commands from inside the selected entry directory. Each lab defaults to
loopback and uses Python's standard library. The entry README explains the
expected output, limits of the model, and available options.

## Research loop

An entry is useful even when it does not contain a complete exploit. The goal is
to preserve a reproducible research trail:

1. Identify a behavior, parser, boundary, or trust decision worth studying.
2. Build the smallest local model that demonstrates that behavior.
3. Use a PoC client to drive the model and record observable results.
4. Write detection logic from those observables, clearly marked as lab-derived
   or firmware-validated.
5. Record limitations, unknowns, and the next experiment.

See the [research template](./templates/RESEARCH.md) when adding a new entry.

## Quick navigation

| I want to... | Go to |
| --- | --- |
| Run a local vulnerability lab | [Lab index](#lab-index) |
| Add firmware research | [Research template](./templates/RESEARCH.md) |
| Track shared IoT devices | [IoT research](./iot/README.md) |
| Update lab hosts | [Host inventory](./iot/hosts.yaml) |
| Contribute or review work | [Contributing guide](./CONTRIBUTING.md) |
| Understand evidence labels | [Evidence levels](#evidence-levels) |

## IoT research

The [IoT research section](./iot/README.md) is for firmware-focused work,
device notes, and a sanitized inventory of available lab targets. Use the host
template there for daily updates. Never commit public IP addresses, credentials,
serial numbers, tokens, or details that would expose an otherwise protected
device.

## Repository layout

Each entry is organized around the research question rather than around a
particular exploit:

| Directory | Purpose |
| --- | --- |
| `README.md` | Claim, scope, evidence status, and reproduction guide |
| `CHAIN.md` | Optional sequence diagram or state transition narrative |
| `lab/` | Local model of the relevant firmware behavior |
| `poc/` | Client or input generator that drives the model |
| `detection/` | Detection hypotheses and telemetry mappings |
| `notes/` | Optional packet captures, reversing notes, or experiment logs |

The lab is not the firmware. It is a controlled model that should state what it
preserves and what it intentionally simplifies.

## Evidence levels

Every entry should distinguish evidence from interpretation:

| Level | Meaning |
| --- | --- |
| `Hypothesis` | A behavior inferred from a report, binary, trace, or unusual input |
| `Lab reproduced` | The behavior is reproduced in the local harness |
| `Firmware reproduced` | The behavior is reproduced against a specific firmware build |
| `Independently reviewed` | Another researcher has repeated or challenged the result |

These levels are not severity ratings. A high-impact hypothesis can still be
unverified.

## Vulnerabilities

| Entry | Target | Research focus | Evidence |
| --- | --- | --- | --- |
| [CVE-2026-88771](./CVE-2026-88771) | Citrix NetScaler | Log poisoning and pre-auth command execution | Local lab model |
| [CVE-2026-88772](./CVE-2026-88772) | Citrix NetScaler | DTLS reassembly accounting and memory overflow | Local instrumented model |
| [CVE-2026-4810](./CVE-2026-4810) | Google ADK | Unauthenticated agent builder upload and callable injection | Local lab model |

## Principles

- **Reproducible:** commands, inputs, versions, and expected results are
	recorded.
- **Scoped:** labs are isolated models, not permission to test a live device.
- **Honest:** hypotheses, lab reproductions, and firmware reproductions are
	labelled differently.
- **Useful:** detections describe observable behavior and state their telemetry
	assumptions.
- **Collaborative:** a contribution can be a correction, trace, device note, or
	failed experiment, not only a new CVE.

## Tools

- [cve-scout](./tools/cve_scout.py) - CVE intelligence, research harness scaffolding, and CVE JSON 5.0 CNA submission generator.
- [adk-audit](./tools/adk-audit) - Root-cause analysis and auditing notes.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to add research, update the
IoT inventory, review someone else's finding, and keep sensitive lab details
private.

## Working locally

The labs bind to loopback by default and use only Python's standard library.
Each entry README contains the commands for starting its harness, running the
corresponding PoC, and interpreting the result. Detection files are analytic
starting points; adapt field names and log sources to the telemetry available
from the firmware version being investigated.
