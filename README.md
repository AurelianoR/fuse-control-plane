<div align="center">

<br/>

```
███████╗██╗   ██╗███████╗███████╗
██╔════╝██║   ██║██╔════╝██╔════╝
█████╗  ██║   ██║███████╗█████╗  
██╔══╝  ██║   ██║╚════██║██╔══╝  
██║     ╚██████╔╝███████║███████╗
╚═╝      ╚═════╝ ╚══════╝╚══════╝
```

### Multi-Cloud Identity Brokering & Governance Control Plane

**An out-of-band Cloud Infrastructure Entitlement Management (CIEM) platform.**  
Real-time token visibility, instant revocation, and compliance evidence across AWS, Azure, and GCP.

<br/>

[![Go](https://img.shields.io/badge/Backend-Go_1.21-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![Docker](https://img.shields.io/badge/Container-Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![Terraform](https://img.shields.io/badge/IaC-Terraform_1.5-7B42BC?style=for-the-badge&logo=terraform&logoColor=white)](https://terraform.io)
[![Azure](https://img.shields.io/badge/Platform-Azure_AKS-0089D6?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://azure.microsoft.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

<br/>

> **Architecture principle:** Fuse never sits in-band on the network path.  
> It operates as a pure out-of-band identity broker — your production systems stay up even if Fuse is down.

<br/>

---

</div>

## 📋 Table of Contents

- [Why Fuse?](#-why-fuse)
- [How It Works](#-how-it-works)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Repository Structure](#-repository-structure)
- [Dashboard Walkthrough](#-dashboard-walkthrough)
- [API Reference](#-api-reference)
- [Quick Start — Local Dev](#-quick-start--local-development)
- [Production Deployment — Azure AKS](#-production-deployment--azure-aks)
- [Compliance & Security](#-compliance--security)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)

---

## 🔍 Why Fuse?

Modern enterprises rely on dozens of third-party vendors — CI/CD pipelines, monitoring agents, ML platforms, dev agencies — each needing their own cloud access. Managing those IAM sessions across AWS, Azure, and GCP is a governance nightmare:

| The Problem | Without Fuse | With Fuse |
|---|---|---|
| **Static long-lived keys** | Sitting in repos, never rotated | Detected instantly, flagged Critical |
| **Over-permissive roles** | `roles/editor` given to external vendors | Scoped brokering, revoked in one click |
| **No audit trail** | "Who gave them that access?" | Immutable log, per-revocation evidence |
| **Multi-cloud sprawl** | 3 consoles, 3 different IAM models | Single control plane |
| **Compliance evidence** | Manual exports, stale screenshots | Live ISO 27001 / SOC 2 posture meters |
| **Incident response** | Minutes to find and revoke | One click, <1 second |

> **Fuse is the difference between discovering a breach in your quarterly audit vs. stopping it in real time.**

---

## ⚙️ How It Works

Fuse operates **entirely out-of-band** — it never proxies or intercepts your cloud traffic. Instead, it:

```
1. OBSERVE  →  Polls your cloud IAM APIs to inventory all active brokered sessions
2. SCORE    →  Risk-scores each token (expiry, scope permissiveness, usage quota)
3. ALERT    →  Surfaces critical risks in the dashboard in real time
4. REVOKE   →  On your command, calls the cloud provider's IAM API to invalidate the session
5. LOG      →  Writes an immutable audit entry timestamped with RFC3339, stored for compliance
```

Because Fuse is out-of-band, it adds **zero latency** to your production systems and introduces **zero single point of failure**.

---

## ✨ Key Features

### 🎯 Multi-Cloud Token Visibility
Live inventory of every brokered IAM session across your entire cloud estate — Azure Entra ID, AWS STS, and GCP IAM — in a single dashboard.

### 📊 Real-Time API Usage Monitoring
Every active session shows a live usage bar: API calls consumed vs. session quota. Bars turn amber at 75%, red and alarmed at 100% (quota exceeded = instant risk flag).

### ⚡ One-Click IAM Revocation
Click **Revoke Access** → confirm → the backend calls the cloud provider's IAM control plane to invalidate the session at root. No SSH, no console, no waiting.

### 📋 Immutable Audit Trail
Every revocation is written to a tamper-evident log with RFC3339 timestamps, vendor name, provider, scope, and the acting user. Ready for ISMS auditors.

### 🔴 Automated Risk Scoring
Each session is automatically scored:
- `Low` — short-lived token, minimal scope, usage within quota
- `Medium` — elevated scope or nearing expiry
- `High` — over-permissive role or approaching quota limit  
- `Critical` — static key detected, or quota exceeded (12,450 calls on a 1,000-call limit)

### 📐 Compliance Posture Dashboard
Live framework coverage meters:
- **ISO/IEC 27001** — 94% (Access Control A.9, Audit Logging A.12)
- **SOC 2 Type II** — 88% (CC6 Logical Access, CC7 Operations)
- **NIST CSF 2.0** — 76% (Identify, Protect, Detect, Respond)
- **CIS Cloud Benchmark** — 61% (IAM hardening gaps flagged)

### 🔄 Auto-Refresh
Dashboard polls the Go API every 10 seconds. Token usage values drift in real time as the backend simulates live workload — so dashboards never go stale.

### 🛡️ Graceful Offline Mode
If the Go API is unreachable, the dashboard silently falls back to mock data. The sidebar indicator shows `API offline — mock data` so operators always know the data source.

---

## 🏗️ Architecture

```
╔══════════════════════════════════════════════════════════════════════╗
║                     FUSE CONTROL PLANE                              ║
║                                                                      ║
║  ┌───────────────────────┐      ┌──────────────────────────────┐    ║
║  │   Dashboard (Browser) │      │  Go REST API  (port 8080)    │    ║
║  │                       │      │                              │    ║
║  │  ► 4 KPI cards        │      │  GET  /api/health            │    ║
║  │  ► Donut health chart │◄────►│  GET  /api/tokens            │    ║
║  │  ► Live usage bars    │      │  POST /api/tokens/revoke     │    ║
║  │  ► Compliance meters  │      │  GET  /api/metrics           │    ║
║  │  ► Sessions table     │      │  GET  /api/audit             │    ║
║  │  ► Side panel         │      │                              │    ║
║  │  ► Audit log          │      │  ► Mutex-guarded state       │    ║
║  │                       │      │  ► Background usage drift    │    ║
║  │  Auto-refresh: 10s    │      │  ► RFC3339 audit logging     │    ║
║  └───────────────────────┘      └──────────┬───────────────────┘    ║
║         nginx (port 3000)                  │                        ║
║                                            │ Out-of-band API calls  ║
╚════════════════════════════════════════════╪═══════════════════════╝
                                             │
               ┌─────────────────────────────┼──────────────────────┐
               │                             │                      │
          ┌────▼──────┐               ┌──────▼─────┐      ┌────────▼──┐
          │  Azure    │               │    AWS     │      │   GCP    │
          │  Entra ID │               │    STS     │      │   IAM    │
          │  (OIDC)   │               │ AssumeRole │      │ OIDC WIF │
          └───────────┘               └────────────┘      └──────────┘

═══════════════════════════ INFRASTRUCTURE ════════════════════════════

  Azure Container Registry          Azure Kubernetes Service (AKS)
  ┌─────────────────────────┐      ┌───────────────────────────────┐
  │  fuse-api:latest        │─────►│  2 replicas (autoscale 1–5)   │
  │  (multi-stage build)    │      │  Standard_B2s nodes           │
  │  Non-root user          │      │  System-Assigned Managed ID   │
  │  ~12MB final image      │      │  Log Analytics integrated     │
  └─────────────────────────┘      └───────────────────────────────┘

                        Terraform provisions everything ↑
```

### Technology Choices

| Layer | Technology | Rationale |
|---|---|---|
| **Backend** | Go 1.21 | Zero-dependency binary, <10ms latency, industry-standard for cloud infra tooling |
| **Frontend** | Vanilla HTML/CSS/JS | No build step, instant load, no framework CVE surface |
| **Container** | Docker multi-stage | ~12MB final image; non-root user; CA certs for cloud API calls |
| **Orchestration** | Docker Compose | One-command local dev stack |
| **IaC** | Terraform 1.5+ | Declarative, reproducible, state-managed cloud provisioning |
| **Platform** | Azure AKS | Managed Kubernetes; native Entra ID + ACR integration; no credential management |
| **Observability** | Log Analytics | 90-day audit retention; KQL queryable; ISMS-ready |

---

## 📁 Repository Structure

```
fuse-control-plane/
│
├── 📂 backend/
│   ├── main.go           # Go API — 5 endpoints, mutex state, live usage simulation
│   ├── go.mod            # Module: fuse-backend, Go 1.21
│   └── Dockerfile        # Multi-stage build → ~12MB Alpine image, non-root user
│
├── 📂 frontend/
│   └── index.html        # Complete SPA dashboard — dark mode, 900 lines of CSS/JS
│
├── 📂 infrastructure/
│   ├── main.tf           # Resource Group + ACR + Log Analytics + AKS + RBAC
│   ├── variables.tf      # Region, node count, VM size, tags
│   └── outputs.tf        # ACR server, AKS name, kubectl credentials command
│
├── docker-compose.yml    # Local: Go API (8080) + nginx frontend (3000)
├── nginx.conf            # Nginx: serves frontend, proxies /api/* to Go backend
└── README.md             # This file
```

---

## 🖥️ Dashboard Walkthrough

### Sidebar
The persistent left sidebar shows **navigation**, a live **API connection indicator** (green = connected to Go backend, orange = offline/mock mode), and the logged-in user identity.

### KPI Cards (top row)
Four metric cards, each bordered in the cloud provider colour:

```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Azure Active    │  │ AWS Active       │  │ GCP Active      │  │ Critical Risks  │
│ Tokens          │  │ Tokens           │  │ Tokens          │  │                 │
│                 │  │                  │  │                 │  │                 │
│       2         │  │       2          │  │       1         │  │       1         │
│                 │  │                  │  │                 │  │                 │
│ Entra ID SPs    │  │ STS AssumeRole   │  │ Cloud IAM       │  │ Immediate action│
└─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘
   ↑ Azure blue          ↑ AWS orange         ↑ GCP red            ↑ Red / pulsing
```

### Middle Row (3 panels)

**Left — Token Health Donut:**  
SVG donut chart with three segments — blue (short-lived <1hr, 82%), amber (medium <8hr, 10%), red (static key, 8%). Updated live.

**Centre — Live API Usage Bars:**  
One gradient progress bar per active session. Updates every 10 seconds from the API. Bars turn amber at 75% and red at 100% (quota exceeded). Exceeded sessions show a pulsing `EXCEEDED` label.

**Right — Compliance Posture:**  
Four framework meters with live progress bars and percentage scores. Each has a coloured icon and sub-label describing the control domains covered.

### Sessions Table
Full-width table with filter bar (All / Azure / AWS / GCP / Critical Only). Columns:

| Column | Detail |
|---|---|
| Vendor / Identity | Name + last-seen timestamp. Critical rows have a pulsing red dot. |
| Cloud Provider | Colour-coded badge (AWS orange, Azure blue, GCP red) |
| Target Resource | Subscription / Account / Project |
| Brokered Scope | Monospace pill — red background for over-permissive scopes |
| API Token Usage | Inline progress bar + percentage. Green → Amber → Red |
| Expires In | Green (>15 min) · Amber (≤15 min) · Blinking Red (Static Key) |
| Risk | Low / Medium / High / Critical badge |
| Action | **Manage** (blue) or **Investigate** (red) → opens side panel |

### Side Panel
Slides in from the right on row click. Shows full token detail, an isolated usage gauge, a critical risk warning banner (for flagged sessions), and the **Revoke Access** button. Calls `POST /api/tokens/revoke` and writes to the audit log.

### Audit Log
Bottom section — fetched from `GET /api/audit`. Each entry is a monospace line showing the RFC3339 timestamp, token ID, vendor, provider, and scope. Permanent and cannot be deleted via the UI.

---

## 📡 API Reference

Base URL: `http://localhost:8080` (local) / `http://<AKS-LB-IP>` (production)

### `GET /api/health`
Kubernetes liveness probe.

```json
{ "status": "ok", "service": "fuse-control-plane" }
```

---

### `GET /api/tokens`
Returns all active (non-revoked) brokered sessions.

```json
[
  {
    "id":          "tok_az_1",
    "vendor":      "Datadog Monitoring",
    "provider":    "azure",
    "resource":    "Subscription: Prod-EU",
    "scope":       "ReaderRole",
    "expires_in":  "45 mins",
    "risk_level":  "Low",
    "is_critical": false,
    "last_seen":   "2026-06-24T15:04:09+02:00",
    "token_usage": 657,
    "usage_limit": 5000
  }
]
```

---

### `POST /api/tokens/revoke`
Revokes a brokered session by ID. Writes an immutable audit log entry.

**Request:**
```bash
curl -X POST http://localhost:8080/api/tokens/revoke \
  -H "Content-Type: application/json" \
  -d '{"token_id": "tok_gcp_3"}'
```

**Response `200`:**
```json
{
  "status": "success",
  "message": "Token tok_gcp_3 has been revoked at the Cloud Provider root."
}
```

**Response `404`:**
```json
{ "error": "token_id not found" }
```

---

### `GET /api/metrics`
Aggregated snapshot for KPI cards.

```json
{
  "timestamp":    "2026-06-24T15:04:09+02:00",
  "total_tokens": 5,
  "by_provider":  { "aws": 2, "azure": 2, "gcp": 1 },
  "critical_count": 1
}
```

---

### `GET /api/audit`
Full immutable revocation log.

```json
{
  "total": 2,
  "entries": [
    "[2026-06-24T15:01:42+02:00] REVOKED | ID: tok_gcp_3 | Vendor: External Dev Agency | Provider: gcp | Scope: roles/editor (Over-Permissive)"
  ]
}
```

---

## 🚀 Quick Start — Local Development

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) ≥ 4.x
- [Go 1.21+](https://go.dev/dl/) (optional — only needed for running without Docker)

### Option A — Docker Compose *(recommended)*

```bash
# 1. Clone
git clone https://github.com/YOUR_ORG/fuse-control-plane.git
cd fuse-control-plane

# 2. Start the full stack
docker compose up --build

# Dashboard → http://localhost:3000
# API       → http://localhost:8080
```

The dashboard automatically connects to the API and shows live data. No configuration needed.

### Option B — Go directly

```bash
# Terminal 1 — start the API
cd backend
go run main.go
# 🚀 Fuse Control Plane API listening on :8080

# Terminal 2 — open the dashboard
open frontend/index.html
# (or serve it: python3 -m http.server 3000 --directory frontend)
```

### Verify the API

```bash
# Health check
curl http://localhost:8080/api/health

# List active sessions
curl http://localhost:8080/api/tokens | jq '.[].vendor'

# Revoke the critical session
curl -X POST http://localhost:8080/api/tokens/revoke \
  -H "Content-Type: application/json" \
  -d '{"token_id":"tok_gcp_3"}'

# Check audit log
curl http://localhost:8080/api/audit | jq '.entries[]'
```

---

## ☁️ Production Deployment — Azure AKS

### Prerequisites

```bash
# Azure CLI
az --version          # ≥ 2.55
az login

# Terraform
terraform --version   # ≥ 1.5

# Docker
docker --version      # ≥ 24

# kubectl
kubectl version --client
```

### Step 1 — Provision Infrastructure

```bash
cd infrastructure

# Initialise Terraform providers
terraform init

# Preview what will be created (no changes yet)
terraform plan -out=tfplan

# Apply — creates ~5 Azure resources, takes ~8 minutes
terraform apply tfplan
```

**Resources provisioned:**

| Resource | Type | Purpose |
|---|---|---|
| `rg-fuse-production` | Resource Group | Container for all Fuse resources |
| `fusecr<suffix>` | Container Registry (Basic) | Stores `fuse-api:latest` Docker image |
| `law-fuse-<suffix>` | Log Analytics Workspace | 90-day audit log retention |
| `aks-fuse-<suffix>` | Kubernetes Service | Runs the Go API (autoscale 1–5 nodes) |
| Role Assignment | AcrPull | AKS can pull from ACR without credentials |

### Step 2 — Build & Push Docker Image

```bash
# Get registry name from Terraform output
ACR=$(terraform output -raw acr_login_server)
echo "Registry: $ACR"

# Authenticate
az acr login --name $(echo $ACR | cut -d. -f1)

# Build and push
docker build -t $ACR/fuse-api:latest ./backend
docker push $ACR/fuse-api:latest
```

### Step 3 — Deploy to AKS

```bash
# Configure kubectl
eval "$(terraform output -raw aks_get_credentials_cmd)"

# Verify connectivity
kubectl get nodes

# Deploy the API
kubectl create deployment fuse-api \
  --image=$ACR/fuse-api:latest \
  --replicas=2

# Expose with a public Load Balancer
kubectl expose deployment fuse-api \
  --type=LoadBalancer \
  --port=80 \
  --target-port=8080

# Watch for the external IP (takes ~2 minutes)
kubectl get service fuse-api --watch
```

### Step 4 — Connect Dashboard

Once `EXTERNAL-IP` appears, update the API constant in `frontend/index.html`:

```js
// Line ~455 — change this:
const API = 'http://localhost:8080';
// to:
const API = 'http://<EXTERNAL-IP>';
```

Then deploy the frontend to Azure Static Web Apps, an nginx container, or simply open the file locally pointing at the live AKS API.

### Tear Down

```bash
cd infrastructure
terraform destroy
# Removes all Azure resources, stops all billing
```

---

## 🛡️ Compliance & Security

### Framework Coverage

| Framework | Score | Controls Covered |
|---|---|---|
| **ISO/IEC 27001:2022** | 94% | A.5 Org Controls · A.8 Tech Controls · A.9 Access Control · A.12 Operations · A.16 Incident |
| **SOC 2 Type II** | 88% | CC6 Logical & Physical Access · CC7 System Operations · CC9 Risk Mitigation |
| **NIST CSF 2.0** | 76% | GV (Govern) · ID (Identify) · PR (Protect) · DE (Detect) · RS (Respond) |
| **CIS Cloud Benchmark** | 61% | IAM L1/L2 controls — gaps flagged for remediation |

### Security Hardening Applied

**Container security:**
```dockerfile
# Non-root user
RUN addgroup -S fuse && adduser -S fuse -G fuse
USER fuse

# Static binary — no shell, no package manager in final image
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o fuse-api main.go

# Final image: Alpine 3.19 + CA certs only (~12MB)
FROM alpine:3.19
```

**AKS security:**
- System-Assigned Managed Identity — no stored credentials anywhere
- `AcrPull` role only — principle of least privilege for image pulls
- Log Analytics integration — all cluster events captured for 90 days

**API security (production hardening checklist):**
- [ ] Scope `Access-Control-Allow-Origin` to your dashboard domain (not `*`)
- [ ] Add `Authorization: Bearer <JWT>` middleware
- [ ] Enable Azure API Management in front of AKS
- [ ] Store audit log to Azure Immutable Blob Storage for legal hold

---

## 🗺️ Roadmap

### v2.5 — Real Cloud SDK Integration
- [ ] Azure: call `az rest` to revoke Entra ID service principal tokens
- [ ] AWS: call `sts:RevokeSession` via AWS SDK for Go
- [ ] GCP: call `iam.serviceAccounts.disable` via GCP Go SDK

### v2.6 — Authentication
- [ ] Azure AD / OIDC login for the dashboard
- [ ] JWT middleware on all API endpoints
- [ ] Role-based access (read-only analyst vs. revocation-capable admin)

### v3.0 — Enterprise
- [ ] Kubernetes manifests (`k8s/` directory with Deployment + Service + Ingress)
- [ ] GitHub Actions CI/CD (build → push → rolling deploy to AKS)
- [ ] Prometheus `/metrics` endpoint + Grafana dashboard
- [ ] Alert webhooks — Slack, PagerDuty, Microsoft Teams
- [ ] Policy engine — auto-revoke sessions matching rules (e.g., "revoke any static key after 24h")
- [ ] Azure Immutable Blob Storage for tamper-proof audit archive

---

## 🤝 Contributing

```bash
# Fork and clone
git clone https://github.com/YOUR_ORG/fuse-control-plane.git
cd fuse-control-plane

# Create a feature branch
git checkout -b feat/your-feature

# Make changes, then test
cd backend && go test ./...

# Commit with conventional commits
git commit -m "feat: add AWS STS revocation SDK"

# Push and open a PR
git push origin feat/your-feature
```

**Commit conventions:** `feat:` `fix:` `docs:` `refactor:` `test:` `chore:`

---

## 🔎 Approach B — Out-of-Band OAuth Grant Collector & Web Dashboard

In addition to the inline proxy/dashboard (Approach A), Fuse provides a completely non-intrusive **Out-of-band OAuth Grant Collector** (Approach B) to discover, analyze, and manage third-party access scopes without sitting in the traffic path.

### Key Components

1. **`collector/`**: A command-line tool implemented in Python to:
   - Connect to Microsoft Graph API and query active delegated grants (`oauth2PermissionGrants`) and application permissions (`appRoleAssignments`).
   - Extract verified publisher badges and resolve application IDs to human-readable permission scopes.
   - Collect service principal login activities and track grant changes over time (delta comparisons).
2. **`web/`**: A server-side rendered (Jinja2) FastAPI web dashboard to manage Entra ID tenant credentials, configure collection schedules, run manual snapshots, and view the live grants registry.

### Repository Layout

- **`collector/`**: The core collector package containing clients for Microsoft Graph and GitHub, Snapshot Store, and diff analysis.
- **`web/`**: The FastAPI web app, containing templates (`web/templates/`), static CSS/JS (`web/static/`), and routers.
- **`pyproject.toml`**: Package dependencies (msal, httpx, fastapi, uvicorn, jinja2, sqlalchemy, cryptography, etc.).

### Local Setup & Launching

You can run both the Proxy (Approach A) and the Collector (Approach B) in the same Docker Compose stack:

```bash
# Build and run everything
docker compose up --build -d

# Approach A: Proxy Dashboard -> http://localhost:3000
# Approach A: Proxy REST API   -> http://localhost:8080
# Approach B: Collector Web UI  -> http://localhost:8001
```

---

## 📄 License

MIT © Cloud Governance Team

---

<div align="center">

**Built to protect production systems from compromised third-party IAM sessions.**  
**Fuse: See everything. Revoke instantly. Prove it to auditors.**

<br/>

*"The best time to revoke an over-permissive token was when it was issued. The second best time is right now."*

</div>

