<div align="center">

<img src="./README/banner.png" alt="Cairn Banner"/>

# Cairn
### More Than Just AI Penetration Testing — Towards General State-Space Search

<p>
  <a href="https://zc.tencent.com/hackathon" target="_blank" rel="noopener noreferrer">
    <img src="./README/tencent.png" alt="Tencent" height="55" />
  </a>
  <a href="https://zc.tencent.com/hackathon" target="_blank" rel="noopener noreferrer">
    <img src="./README/tch.png" alt="TCH" height="55" />
  </a>
  <a href="https://wiki.chainreactors.red" target="_blank" rel="noopener noreferrer">
    <img src="./README/c.png" alt="ChainReactors" height="45" />
  </a>
</p>

Cairn is a general-purpose problem-solving engine. <br/>It defines no roles, no workflows. Given an origin and a goal, it searches for a path through an unknown state space. <br/>AI Penetration Testing is one such problem — and a proven one.

<p>
  <a href="https://discord.gg/nDSy4NZVP" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/Discord-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord" />
  </a>
  <a href="https://x.com/le1xia0" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/X-000000?style=flat-square&logo=x&logoColor=white" alt="X" />
  </a>
</p>

</div>

<p align="center">
  <a href="https://www.bilibili.com/video/BV1a8R5BhEVi/" target="_blank" rel="noopener noreferrer">
    <img src="./README/cairn.png" alt="Cairn runtime screenshot" width="900" />
  </a>
</p>

## What is Cairn?

Penetration testing is fundamentally a **directed search through a near-infinite state space**:

- **Origin**: known (target IP, target system)
- **Goal**: defined (get a shell, capture the flag)
- **Path**: unknown

This structure is not unique to penetration testing. Vulnerability research, mathematical proof, CTF challenges — any problem with a clear starting point, a clear success condition, and an unknown path in between shares the same shape.

Cairn is built for this class of problems. Penetration testing is the first domain it has been validated on.

The engine is built on a **Blackboard Architecture** with an explicit fact-intent graph. Findings move through an evidence gate before they can drive completion:

| Concept | Meaning |
|---------|---------|
| **Fact** | A finding with `candidate`, `verified`, or `rejected` status |
| **Intent** | A declared direction of exploration, not yet executed |
| **Hint** | Human judgment injected at any time; absorbed by agents on the next read |

The graph grows from `origin` toward `goal`. Every new Fact is a stepping stone; every Intent is a step into the unknown.

Agent Workers run an OODA loop — Observe the full graph, Orient to the current state, Decide on next intents, Act to explore — and write evidence-backed candidate Facts. A separate Verify task independently confirms or rejects each candidate. Reason receives only verified Fact IDs, and the server refuses to complete a Goal from candidate or rejected facts. Workers have no fixed roles. Tasks are generated at runtime from the graph's current state, not from predefined job descriptions.

Agents coordinate exclusively through the shared board (Stigmergy). No direct communication. No information silos.

## Cairn in Action

https://github.com/user-attachments/assets/e557b1ac-dda4-41cb-87dd-9d56dbf05133


## How It Works

Four task types, all executed by the same Worker pool:

| Task | What it does | Output |
|------|-------------|--------|
| **Bootstrap** | At project start, attempts to solve the problem directly | Fact + possible Complete |
| **Reason** | Reads the full graph: is the goal met? What should be explored next? | Complete / new Intents / no-op |
| **Explore** | Claims one Intent and records a structured finding, evidence, and attempts | Candidate Fact |
| **Verify** | Independently reproduces or disproves a candidate | Verified / rejected Fact |

Explore records successful, failed, and inconclusive attempts. Evidence can reference commands, HTTP observations, files, authoritative sources, and artifact paths. Legacy databases are migrated automatically; existing facts remain verified for backward compatibility.

System architecture:

```
          ┌──────────────────────────────────┐
          │           Cairn Server           │
          │    Facts + Intents + Hints       │
          └─────────────────┬────────────────┘
                            │
                     Read / Write API
                            │
          ┌─────────────────┴────────────────┐
          │             Dispatcher           │
          │   Schedules tasks, manages       │
          │   containers, writes protocol    │
          └──────────┬───────────────┬───────┘
                     │               │
     ┌───────────────┴──┐     ┌──────┴──────────────┐
     │  Worker Container│     │  Worker Container   │
     │   (Project A)    │     │   (Project B)       │
     │  ┌────┐  ┌────┐  │     │  ┌────┐  ┌────┐     │
     │  │ W. │  │ W. │  │     │  │ W. │  │ W. │     │
     │  └────┘  └────┘  │     │  └────┘  └────┘     │
     └──────────────────┘     └─────────────────────┘
```

**Cairn Server** maintains graph consistency only.

**Cairn Dispatcher** reads the graph, schedules tasks, spins up and tears down worker containers, and is the sole writer to the protocol. Each project gets its own Worker Container; multiple Agent Workers run concurrently inside it. Agent Workers only receive a prompt and return structured output.

Workers can also run directly on the dispatcher host instead of in per-project containers — **local mode**, no Docker required. See [Local mode](#local-mode-no-docker) below.

Supported worker backends: **Claude Code**, **Codex**, and **Pi**.

## Results

**Tencent Cloud Hackathon · AI Penetration Testing Challenge · 2nd Edition**

610 teams · 1,345 participants · top universities and security firms across China

| Metric | Value |
|--------|-------|
| Problems solved | **54 / 54 — only team to AK** |
| Final ranking | 3rd |

> The system had never been tested before the competition. The full pipeline came online for the first time at 4 AM on race day. No training, no tuning, no domain-specific tooling. Zero MCP tools, zero RAG, zero predefined agent roles.

## Further Reading

- <a href="https://mp.weixin.qq.com/s/DlpEH7bVr0xi0VawPJs3XA" target="_blank" rel="noopener noreferrer">The Strongest AI Penetration Testing Agent: Postmortem of the Only Team to Achieve AK at the TCH Tencent Cloud Hackathon Intelligent Penetration Testing Challenge (2nd Edition)</a>
- <a href="https://mp.weixin.qq.com/s/2rEqFLvkxvYWM3gW170C2w" target="_blank" rel="noopener noreferrer">The Pathless Path: Cairn AI from Penetration Testing to General Problem Solving</a>

## Getting Started

**Prerequisites**
 
- macOS or Linux
- Python ≥ 3.12
- Docker (container execution only — not needed for local mode)


### Build the worker image

Container execution uses the worker image built from this repository. Building it
locally ensures the agent instructions and `cve-intel` query tool match the
dispatcher configuration:

```bash
docker build --platform=linux/amd64 ./container -t cairn-worker-container:latest
```

Create your local dispatcher configuration and fill in your LLM endpoints and API keys:

```bash
cp dispatch.example.yaml dispatch.yaml
```

Any YAML string may reference an environment variable as `${NAME}` or use a
default as `${NAME:-value}`. Use this for LLM credentials instead of saving
real keys in `dispatch.yaml`, for example `ANTHROPIC_AUTH_TOKEN: "${ANTHROPIC_AUTH_TOKEN}"`.
 
### Docker Compose (recommended)

Generate a private API token before starting the stack. The server requires the
same token from the dispatcher and from browser API requests:

```bash
export CAIRN_API_TOKEN="$(openssl rand -hex 32)"
```

Compose binds the UI to `127.0.0.1:8000` by default. To expose it through a
trusted reverse proxy, set `CAIRN_BIND_HOST` explicitly and terminate TLS at the
proxy. The browser asks for the API token on its first protected request and
keeps it in local storage for subsequent requests.
 
Pull the base image used to build Cairn:
 
```bash
docker pull ghcr.io/astral-sh/uv:python3.13-trixie
```
 
```bash
docker compose up --build
```
 
This starts `cairn-server` on loopback port `8000` and `cairn-dispatcher` once
the server passes its public health check. The dispatcher mounts `dispatch.yaml`
from the project root and connects to Docker via the host socket. Data is
persisted to `./datas/cairn/`. Intent and reason claims use opaque lease tokens,
so a timed-out process cannot submit results after another execution reclaims
the work. Every dispatched execution is also recorded in the project task-run
history with its final outcome.

The Compose stack also maintains a shared read-only cache of the official
[CVE List](https://github.com/CVEProject/cvelistV5). `cairn-cve-updater` performs
the initial shallow clone, builds an atomic SQLite/FTS5 index, and refreshes
changed records hourly. The source and index are stored in the named
`cairn-cve-data` volume. Project worker containers mount the current data when
`dispatch.yaml` contains the volume mapping shown in `dispatch.example.yaml`.
The updater also enriches matching records with CISA Known Exploited
Vulnerabilities metadata so workers can prioritize confirmed in-the-wild
exploitation. It reads CISA's official `kev-data` GitHub mirror and retains the
last valid local catalog when a refresh fails.
NVD CVE API 2.0 enrichment adds NVD CVSS, status, and CPE applicability data.
The first run resumes by page if interrupted; later runs request only modified
records. Set `NVD_API_KEY` before starting Compose for faster API synchronization.
Workers can query it without scanning every JSON file:

```bash
cve-intel status
cve-intel recommend --product "apache2" --version 2.4.49 --confidence 0.9
cve-intel search --vendor Apache --product "HTTP Server" --version 2.4.49
cve-intel show CVE-2024-3094
```

`recommend` normalizes common product aliases, ranks results using version
applicability, CISA KEV, CVSS, publication state, and fingerprint confidence,
and includes the reason for every score contribution. Only exact and affected
range matches are marked applicable; product-only candidates remain explicitly
unverified. Raw search results likewise distinguish exact and range matches from
unverified candidates.

Structured Facts also produce a deterministic project intelligence graph. It
merges equivalent hosts and component aliases, links components to their target,
tracks candidate/verified/rejected evidence and conflicts, and emits reusable
CVE queries. The graph is included in the YAML export and is available from:

```text
GET /projects/{project_id}/intelligence
```

Reason and Explore receive this graph with the normal project snapshot, which
lets later work reuse confirmed fingerprints and focus verification on the most
relevant candidates.
Existing project containers must be recreated once after enabling the mount.
 
### Manual
 
```bash
# Use the same value in the server and dispatcher environments.
export CAIRN_API_TOKEN="$(openssl rand -hex 32)"

# Start the server
uv run --project cairn cairn serve
 
# Run the dispatcher
uv run --project cairn cairn dispatch --config dispatch.yaml
 
# Run startup health checks only
uv run --project cairn cairn dispatch --config dispatch.yaml --startup-healthcheck-only
```

### Local mode (no Docker)

Instead of one container per project, workers can run directly on the dispatcher host, reusing the machine's already-configured `claude` / `codex` / `pi` CLIs — no Docker, and no API keys in the config.

```bash
cp dispatch.local.example.yaml dispatch.yaml

# Start the server
uv run --project cairn cairn serve

# Run the dispatcher on the same host, where the CLIs are installed and logged in
uv run --project cairn cairn dispatch --config dispatch.yaml
```

Local mode is selected by `runtime.execution: local` (see `dispatch.local.example.yaml`). On startup the dispatcher checks each configured worker CLI is installed and runnable, and reminds you they must already be logged in. Each project gets an isolated working directory under `local.workspace_root` (default: the dispatcher's current directory). Run the dispatcher directly on the host — not inside Docker — since the agents run with your user's permissions and no sandbox.

Container mode supports `memory_limit`, `cpu_limit`, `pids_limit`, `cap_drop`,
`read_only`, `security_opt`, and `tmpfs` under the `container` configuration.
The example configuration enables resource ceilings and documents stricter
options for workers that do not need sudo or runtime package installation.

### Tests

Run the fast regression suite without Docker or live model endpoints:

```bash
uv run --project cairn --group dev pytest
```

## Disclaimer

Cairn is a general-purpose problem-solving engine. Although it supports penetration testing, CTF solving, security assessment, and vulnerability research workflows, it is intended to be used only in environments where you have explicit authorization to operate.

You are solely responsible for how you use this project. Do not use Cairn against systems, networks, applications, or data without clear prior permission from the owner or operator. Unauthorized security testing, exploitation, or data access may be illegal and may cause harm.

The developers and contributors of this project do not endorse or accept responsibility for any misuse, abuse, damage, loss, or legal consequences arising from its use. By using this project, you agree to ensure that your activities comply with all applicable laws, regulations, contractual obligations, and professional or organizational policies in your jurisdiction.

## Star History

<a href="https://www.star-history.com/#oritera/Cairn&Date" target="_blank" rel="noopener noreferrer">
  <img src="https://api.star-history.com/svg?repos=oritera/Cairn&type=Date" alt="Star History Chart" />
</a>

## ⚖️ License
This project is licensed under **GNU AGPLv3** for personal and educational use.

**Commercial Use**: If you wish to use this project in a commercial or proprietary environment without the AGPL-3.0 open-source obligations, **please contact me to obtain a commercial license.**

**Contributions**: By submitting a Pull Request, you agree that your contributions may be used under both the AGPL-3.0 and the project's commercial license.
